use criterion::{criterion_group, criterion_main, Criterion};
use edisondb::{Store, Record, DataTier, encrypt_payload, decrypt_payload, derive_key};

fn bench_write(c: &mut Criterion) {
    c.bench_function("write_record", |b| {
        b.iter(|| {
            let mut store = Store::new();
            let r = Record::new("rec:bench", DataTier::Personal,
                "owner", vec![1,2,3], [0u8; 32]).unwrap();
            store.write(r).unwrap();
        })
    });
}

fn bench_read_granted(c: &mut Criterion) {
    let mut store = Store::new();
    let r = Record::new("rec:bench", DataTier::Personal,
        "owner", vec![1,2,3], [0u8; 32]).unwrap();
    store.write(r).unwrap();

    c.bench_function("read_granted", |b| {
        b.iter(|| {
            let _ = store.read("rec:bench", "owner");
        })
    });
}

fn bench_read_denied(c: &mut Criterion) {
    let mut store = Store::new();
    let r = Record::new("rec:bench", DataTier::Critical,
        "owner", vec![1,2,3], [0u8; 32]).unwrap();
    store.write(r).unwrap();

    c.bench_function("read_denied", |b| {
        b.iter(|| {
            let _ = store.read("rec:bench", "attacker");
        })
    });
}

fn bench_encrypt(c: &mut Criterion) {
    let key = [0u8; 32];
    let data = b"sovereign data for benchmarking";

    c.bench_function("encrypt_payload", |b| {
        b.iter(|| {
            encrypt_payload(
                data,
                &key,
                "rec:bench",
                &DataTier::Personal,
            ).unwrap();
        })
    });
}

fn bench_decrypt(c: &mut Criterion) {
    let key = [0u8; 32];
    let data = b"sovereign data for benchmarking";
    let encrypted = encrypt_payload(
                data,
                &key,
                "rec:bench",
                &DataTier::Personal,
            ).unwrap();

    c.bench_function("decrypt_payload", |b| {
        b.iter(|| {
            decrypt_payload(
                &encrypted,
                &key,
                "rec:bench",
                &DataTier::Personal,
            ).unwrap();
        })
    });
}

fn bench_derive_key(c: &mut Criterion) {
    let salt = [1u8; 32];

    c.bench_function("derive_key_argon2", |b| {
        b.iter(|| {
            derive_key("owner_password", &salt).unwrap();
        })
    });
}

fn bench_save_load(c: &mut Criterion) {
    let path = "/tmp/bench_edison.redb";

    c.bench_function("save_and_load_100_records", |b| {
        b.iter(|| {
            let _ = std::fs::remove_file(path);
            let mut store = Store::new();
            for i in 0..100 {
                let id = format!("rec:{i}");
                let r = Record::new(&id, DataTier::Personal,
                    "owner", vec![1,2,3], [0u8; 32]).unwrap();
                store.write(r).unwrap();
            }
            store.save(path).unwrap();
            let _ = Store::load(path).unwrap();
        })
    });
}

criterion_group!(benches,
    bench_write,
    bench_read_granted,
    bench_read_denied,
    bench_encrypt,
    bench_decrypt,
    bench_derive_key,
    bench_save_load,
);
criterion_main!(benches);