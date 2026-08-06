# FV-3 Storage Invariants Evidence

Copyright (c) 2026 Edison Lepiten / AIEONYX

## Scope

FV-3 strengthens EdisonDB storage boundaries for Redb and Fjall.

The verified and tested invariants are:

1. Every stored record has a non-empty owner.
2. Every stored record has a non-empty record ID.
3. Record IDs are immutable and globally unique across storage tiers.
4. A persisted storage key must match the record ID.
5. A Fjall keyspace must match the record tier.
6. Invalid public in-memory state cannot be persisted.
7. Invalid persisted state is rejected during database loading.
8. Failed validation does not mutate records or append audit entries.

## Redb Enforcement

`Store::write` validates record identity before mutation.

`Store::save` validates:

- record owner
- record ID
- map key and record ID consistency

`Store::load` validates:

- deserialized record identity
- persisted table key and record ID consistency

Invalid persisted records fail closed.

## Fjall Enforcement

`FjallBackend::write` validates record identity before audit or mutation.

Record ID existence is checked across:

- Critical
- Personal
- Noise

`FjallBackend::open` validates all persisted records before returning a usable backend.

The open boundary rejects:

- invalid owner
- invalid record ID
- key and record ID mismatch
- tier and keyspace mismatch
- duplicate IDs across keyspaces
- malformed persisted records

## Formal Verification

Kani result:

- Harnesses: 6
- Checks: 194
- Failures: 0
- Unreachable checks: 4
- Result: successful

FV-3 harnesses cover:

- record identity validation
- storage ID immutability
- persisted-record metadata validity

## Behavioral Tests

FV-3 storage test suite:

- Tests: 12
- Passed: 12
- Failed: 0

Coverage includes Redb and Fjall write, save, load, open, immutability, and persisted-corruption boundaries.

## Regression Qualification

Complete all-target gate:

- Tests passed: 209
- Tests failed: 0
- gRPC tests passed: 8
- Benchmarks successful: 7

Documentation gate:

- Doctests passed: 1
- Doctests failed: 0

Strict Clippy passed for the FV-3-affected targets with no new FV-3 warnings.

Two unrelated inherited warnings remain outside the FV-3 change scope.

## Security Result

FV-3 changes EdisonDB storage behavior from trusting record construction and persisted metadata to validating every protected storage boundary.

Malformed, inconsistent, ownerless, empty-ID, tier-mismatched, and duplicate-ID records now fail closed before becoming active database state.
