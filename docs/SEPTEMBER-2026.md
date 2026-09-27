# EdisonDB — September 2026 Update

## FV-5: Encryption & Secret Boundaries

September marks completion of the FV-5 verification phase.

The verified FV-5 history was merged into `main` through PR #13 while
preserving the complete signed 18-commit phase history.

- **FV-5 closure:** `70028047306cc37e759510c6154c67920cc5cddf`
- **Main integration:** `66a287e2776a878ff174564ea6c25cea8df5c722`
- **Claims:** `CLAIM-FV5-001` through `CLAIM-FV5-007`

## What changed

### Encrypted persistence

Persisted record payloads now use a versioned encrypted envelope, with
validation at the persistence reconstruction boundary.

### Authenticated metadata authority

FV-5 hardens the authority boundaries for metadata associated with
encrypted records, including record identity and tier information used
by authenticated encryption.

### Mobile monotonicity and provenance

The mobile boundary now includes verified monotonic write-counter
transition behavior and fail-closed provenance validation within the
documented JNI/Rust scope.

Rejected provenance does not advance the persisted counter.

### Authenticated audit checkpoints

Persisted audit checkpoints are authenticated, strengthening detection
of unsupported local audit-state modification within the documented
local trust model.

### Persisted `created_at` authentication

Checkpoint v2 binds a deterministic commitment for current persisted
record IDs and nonzero `created_at` values.

This authenticates the documented persisted `created_at` boundary; it
does not claim wall-clock correctness or timestamp freshness.

## Verification evidence

FV-5 includes commit-bound evidence for:

- persisted reconstruction authority;
- encrypted payload persistence;
- AAD metadata authority;
- mobile write-counter monotonicity;
- authenticated audit checkpoint sealing;
- mobile fail-closed provenance validation;
- persisted `created_at` authenticated-checkpoint behavior.

The phase closure is recorded in:

`verification/evidence/FV-5-PHASE-CLOSURE.md`

Raw verification artifacts are retained under:

`verification/evidence/raw/fv5/`

## Scope boundaries

FV-5 is a bounded verification phase, not a claim that EdisonDB as a
whole is formally verified.

The phase does **not** claim formal cryptographic proofs of AES-GCM,
BLAKE3, Argon2, or MAC unforgeability. It also does not claim external
anti-rollback protection, wall-clock freshness, persisted metadata
confidentiality, or detection of total local-state destruction and
replacement without an external trust anchor.

Kani results apply to the specifically documented structural and
arithmetic properties of their respective claims.

## What comes next

FV-6 focuses on **concurrency, atomicity, crash behavior, and recovery**.

Crash-consistency remediation associated with `LIMIT-005` remains
assigned to FV-6. External trust-boundary work tracked by `LIMIT-002`
and `LIMIT-003` remains assigned to FV-7.

---

Copyright © 2026 Edison Lepiten / AIEONYX

Licensed under the Apache License 2.0.
