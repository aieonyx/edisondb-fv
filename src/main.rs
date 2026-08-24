use clap::{Parser, Subcommand};
use edisondb::{executor::EqlExecutor, eql::parse};
use rpassword::read_password;
use rustyline::{DefaultEditor, error::ReadlineError};
use std::io::{self, Write};

const HISTORY: &str = ".eql_history";

// -- CLI definition ----------------------------------------------------------
#[derive(Parser)]
#[command(
    name = "edctl",
    about = "EdisonDB control CLI — Sovereign. Encrypted. Yours.",
    version = "0.1.0-alpha",
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new EdisonDB database
    Init {
        /// Database file path (e.g. myapp.redb)
        name: String,
    },
    /// Open an interactive EQL shell
    Shell {
        /// Database file path
        name: String,
    },
    /// Show database status and statistics
    Status {
        /// Database file path
        name: String,
    },
    /// Verify audit chain integrity
    Verify {
        /// Database file path
        name: String,
    },
}

// -- Entry point -------------------------------------------------------------
fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Init   { name } => cmd_init(&name),
        Command::Shell  { name } => cmd_shell(&name),
        Command::Status { name } => cmd_status(&name),
        Command::Verify { name } => cmd_verify(&name),
    }
}

// -- edctl init --------------------------------------------------------------
fn cmd_init(path: &str) {
    if std::path::Path::new(path).exists() {
        eprintln!("Error: database already exists at {path}");
        std::process::exit(1);
    }
    println!("Initializing EdisonDB at {path}");
    let owner_id = prompt_line("Owner ID  : ");
    if owner_id.is_empty() {
        eprintln!("Error: owner ID cannot be empty.");
        std::process::exit(1);
    }
    let password = prompt_password("Password  : ");
    if password.is_empty() {
        eprintln!("Error: password cannot be empty.");
        std::process::exit(1);
    }
    let confirm = prompt_password("Confirm   : ");
    if password != confirm {
        eprintln!("Error: passwords do not match.");
        std::process::exit(1);
    }
    match EqlExecutor::open(path, &owner_id, &password) {
        Ok(ex)  => {
            // Force-save so the .redb file exists on disk immediately
            if let Err(e) = ex.save() {
                eprintln!("Error: failed to write database: {e}");
                std::process::exit(1);
            }
            println!("\nDatabase created: {path}");
            println!("Owner ID        : {owner_id}");
            println!("\nRun 'edctl shell {path}' to start.");
        }
        Err(e) => {
            eprintln!("Error: failed to create database: {e}");
            std::process::exit(1);
        }
    }
}

// -- edctl shell -------------------------------------------------------------
fn cmd_shell(path: &str) {
    print_banner();
    if !std::path::Path::new(path).exists() {
        eprintln!("Error: database not found at {path}");
        eprintln!("Hint : run 'edctl init {path}' first.");
        std::process::exit(1);
    }
    let owner_id = prompt_line("Owner ID : ");
    if owner_id.is_empty() {
        eprintln!("Error: owner ID cannot be empty.");
        std::process::exit(1);
    }
    let password = prompt_password("Password : ");
    if password.is_empty() {
        eprintln!("Error: password cannot be empty.");
        std::process::exit(1);
    }
    let mut ex = match EqlExecutor::open(path, &owner_id, &password) {
        Ok(e)  => e,
        Err(e) => { eprintln!("Error: {e}"); std::process::exit(1); }
    };
    println!("\nDatabase : {path}");
    println!("Owner    : {owner_id}");
    println!("Type EQL statements or 'help'. Ctrl-C / Ctrl-D to exit.\n");
    let mut rl = DefaultEditor::new().expect("readline init failed");
    let _ = rl.load_history(HISTORY);
    'repl: loop {
        match rl.readline("eql> ") {
            Ok(line) => {
                for raw in line.split('\n') {
                    let stmt = raw.trim().to_string();
                    if stmt.is_empty() { continue; }
                    let _ = rl.add_history_entry(&stmt);
                    if stmt.eq_ignore_ascii_case("help") {
                        print_help();
                        continue;
                    }
                    if stmt.eq_ignore_ascii_case("exit")
                        || stmt.eq_ignore_ascii_case("quit") {
                        break 'repl;
                    }
                    match parse(&stmt) {
                        Err(e)   => eprintln!("Parse error: {e}"),
                        Ok(stmt) => match ex.execute(stmt) {
                            Ok(result) => println!("{result}"),
                            Err(e)     => eprintln!("Error: {e}"),
                        },
                    }
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
            Err(e) => { eprintln!("Readline error: {e}"); break; }
        }
    }
    let _ = rl.save_history(HISTORY);
    println!("\nSession closed. Goodbye.");
}

// -- edctl status ------------------------------------------------------------
fn cmd_status(path: &str) {
    if !std::path::Path::new(path).exists() {
        eprintln!("Error: database not found at {path}");
        std::process::exit(1);
    }
    let owner_id = prompt_line("Owner ID : ");
    let password = prompt_password("Password : ");
    let ex = match EqlExecutor::open(path, &owner_id, &password) {
        Ok(e)  => e,
        Err(e) => { eprintln!("Error: {e}"); std::process::exit(1); }
    };
    let stats = match ex.stats() {
        Ok(stats) => stats,
        Err(e) => {
            eprintln!("Error: {e}");
            return;
        }
    };
    println!("\n╔══════════════════════════════════════╗");
    println!("║         EdisonDB — Status            ║");
    println!("╚══════════════════════════════════════╝");
    println!("  Database    : {path}");
    println!("  Owner       : {owner_id}");
    println!("  Records     : {}", stats.record_count);
    println!("  Audit log   : {} entries", stats.audit_count);
    println!("  Critical    : {}", stats.critical_count);
    println!("  Personal    : {}", stats.personal_count);
    println!("  Noise       : {}", stats.noise_count);
    println!("  Chain valid : {}", if stats.chain_valid { "YES" } else { "NO — TAMPERED" });
    println!();
}

// -- edctl verify ------------------------------------------------------------
fn cmd_verify(path: &str) {
    if !std::path::Path::new(path).exists() {
        eprintln!("Error: database not found at {path}");
        std::process::exit(1);
    }
    let owner_id = prompt_line("Owner ID : ");
    let password = prompt_password("Password : ");
    let ex = match EqlExecutor::open(path, &owner_id, &password) {
        Ok(e)  => e,
        Err(e) => { eprintln!("Error: {e}"); std::process::exit(1); }
    };
    print!("Verifying audit chain for {path} ... ");
    io::stdout().flush().ok();
    match ex.verify_chain() {
        Ok(())  => println!("OK — chain intact."),
        Err(e)  => {
            println!("FAILED");
            eprintln!("Chain violation: {e}");
            std::process::exit(2);
        }
    }
}

// -- Helpers -----------------------------------------------------------------
fn prompt_line(prompt: &str) -> String {
    print!("{prompt}");
    io::stdout().flush().ok();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).ok();
    buf.trim().to_string()
}

fn prompt_password(prompt: &str) -> String {
    print!("{prompt}");
    io::stdout().flush().ok();
    read_password().unwrap_or_default()
}

fn print_banner() {
    println!("╔══════════════════════════════════════╗");
    println!("║        EdisonDB  —  EQL Shell        ║");
    println!("║   Sovereign. Encrypted. Yours.       ║");
    println!("╚══════════════════════════════════════╝");
    println!();
}

fn print_help() {
    println!("  WRITE <id> TIER <CRITICAL|PERSONAL|NOISE> <payload>");
    println!("  READ  <id>");
    println!("  LIST  [TIER <CRITICAL|PERSONAL|NOISE>]");
    println!("  DELETE <id>");
    println!("  AUDIT  [<id>]");
    println!("  help | exit | quit");
}
