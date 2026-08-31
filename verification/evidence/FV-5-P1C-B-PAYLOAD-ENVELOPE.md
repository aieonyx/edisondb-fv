# FV-5 P1c-B Encrypted Payload Envelope Evidence

Copyright (c) 2026 Edison Lepiten / AIEONYX

## Status

`COMMIT-BOUND TARGETED VERIFICATION PASS`

`FULL KANI SUITE: BASELINE-CONSTRAINED / VERIFIER RESOURCE EXHAUSTION / NOT GREEN`

This document records the FV-5 P1c-B migration of record persistence to
the versioned `EncryptedPayload` boundary and the commit-bound evidence
generated for that source.

The verified source commit is:

`eace7cc86c354481c100ccf88b8f5d4bda33d898`

Its parent is the P1c-A source commit:

`dba00ea58cd160a69c9a4fc6bb041e361fa40e47`

Its Git tree is:

`6ec6861fbfef69ab7a424bab616dc7cd1755ce5c`

The evidence-closure commit that will contain this document and the raw
evidence is documentation/evidence only. It does not replace the source
commit identified above as the subject of verification.

## Scope

FV-5 P1c-A introduced the versioned encrypted payload envelope.

FV-5 P1c-B migrates the production persistence and reconstruction paths
to that typed boundary.

At the verified source commit:

- `Record.payload` is represented by `EncryptedPayload`;
- `PersistedRecord.payload` is represented by `EncryptedPayload`;
- persisted payload reconstruction structurally validates the envelope
  before record reconstruction proceeds;
- encryption emits the current versioned envelope;
- decryption accepts the typed encrypted payload boundary;
- the existing record ID and tier authenticated-data binding remains in
  place;
- executor, migration, persistence, integration tests, and benchmarks use
  the typed encrypted payload representation;
- unmarked legacy payload bytes are not silently adopted;
- unknown payload-envelope versions fail closed;
- truncated current-version envelopes fail closed;
- valid current-version persisted envelopes reconstruct through the
  guarded persistence seam;
- no automatic legacy payload migration is introduced.

This phase concerns payload representation, construction authority, and
persistence boundaries. It does not establish confidentiality for clear
record metadata.

## Versioned Payload Boundary

The persisted encrypted payload format uses:

- magic marker: `EDB1`;
- current envelope version: `1`;
- nonce length: `12` bytes;
- ciphertext bytes containing the AES-GCM authentication tag.

Structural envelope validation distinguishes:

- unmarked legacy payload representation;
- unsupported envelope version;
- malformed or truncated current envelope.

Structural validity is not equivalent to cryptographic authenticity.

A structurally valid encrypted envelope can only establish that the bytes
conform to the expected representation. Authenticity remains dependent on
successful authenticated decryption with the correct key, nonce, and
associated-data boundary.

## Persistence-Level Fail-Closed Evidence

The committed Fjall persistence regressions include:

- `p1c_persisted_unmarked_legacy_payload_fails_closed`;
- `p1c_persisted_unknown_version_fails_closed`;
- `p1c_persisted_truncated_current_envelope_fails_closed`;
- `p1c_valid_versioned_persisted_payload_reconstructs`.

The malformed-envelope cases are inserted through the raw persisted
record boundary rather than through ordinary public construction.

At the storage boundary, malformed persisted encrypted payload
deserialization is surfaced as `EdisonError::LoadFailed`.

Once payload structure is valid, the previously established P1b metadata
validation precedence remains active.

## Dynamic Verification

Commit-bound dynamic result:

- Cargo test targets counted: `15`;
- passed: `271`;
- failed: `0`;
- ignored: `0`.

The complete committed library and integration suite passed.

The observed suite includes the persistence-envelope regressions listed
above as well as the existing storage, audit, checkpoint, migration,
verification, compliance, gRPC, SDK, and compile-fail boundaries.

## Clippy Verification

Baseline-aware Clippy comparison:

- baseline source: `dba00ea58cd160a69c9a4fc6bb041e361fa40e47`;
- baseline diagnostics: `23`;
- current P1c-B diagnostics: `23`;
- new diagnostics: `0`;
- baseline exit code: `0`;
- current exit code: `0`.

Classification:

`PASS — NO NEW CLIPPY DIAGNOSTICS RELATIVE TO P1c-A`

Existing baseline diagnostics were not expanded into unrelated cleanup
during this security-boundary slice.

## Targeted Kani Verification

Commit-bound targeted Kani arithmetic:

`1514 checks / 0 failed / 21 unreachable`

Environment:

- Rust: `rustc 1.97.0 (2d8144b78 2026-07-07)`;
- Cargo: `cargo 1.97.0 (c980f4866 2026-06-30)`;
- Kani: `cargo-kani 0.67.0`.

Harness results:

| Harness | Checks | Failed | Unreachable | Unsupported notice |
| --- | ---: | ---: | ---: | --- |
| `kani_tier_gate_critical` | 455 | 0 | 7 | yes |
| `kani_persisted_record_metadata` | 607 | 0 | 7 | yes |
| `kani_persisted_created_at_validation` | 452 | 0 | 7 | yes |

All three targeted harnesses completed with:

`VERIFICATION:- SUCCESSFUL`

Kani reported unsupported `caller_location` and foreign-function
constructs. Those notices remain preserved in the raw logs.

The successful targeted runs are not interpreted as verification of
behavior represented by unsupported constructs themselves.

## Full Kani Suite Classification

The complete Kani suite is **not classified as green** for this slice.

A full P1c-B run contained `18` harnesses. The audit-related portion
encountered verifier process/resource failures.

A representative audit harness,
`kani_audit_chain_valid_sealed_chain`, exhausted CBMC memory.

The same representative failure was reproduced on the committed P1c-A
baseline.

A broader P1c-A full-suite attempt was also performed. Before deliberate
interruption due impractical local resource consumption, it recorded:

- harnesses reached: `5`;
- successful verification summaries: `3`;
- verifier-failed summaries: `1`;
- explicit CBMC out-of-memory diagnostics: `1`;
- assertion `Status: FAILURE` results: `0`;
- final harness reached:
  `verification::kani_harnesses::kani_audit_chain_interior_drop_rejected`.

The P1c-A partial full-suite log is archived in this evidence package.

The named audit verification/digest/hash boundary diff between P1c-A and
P1c-B is empty.

Accordingly, this evidence classifies the full-suite result as:

`BASELINE-CONSTRAINED VERIFIER RESOURCE EXHAUSTION`

It is not represented as:

- a successful full-suite proof;
- an assertion counterexample;
- a P1c-B-introduced audit regression.

No audit harness is weakened or rewritten merely to obtain a green
verifier result.

## Cryptographic Claim Boundary

This evidence does **not** claim formal verification of AES-GCM.

The cryptographic primitive implementation remains a trusted dependency
unless separately verified.

The targeted Kani results establish properties of the named EdisonDB
production boundaries under their modeled execution paths. They do not
constitute a proof of AES-GCM confidentiality, authenticity, nonce
security, implementation correctness, or resistance to cryptanalysis.

The existing ID and tier associated-data binding remains subject to its
dedicated FV-5 P2 hardening and evidence scope.

## Compatibility and Migration Boundary

P1c intentionally rejects unmarked legacy payload representation at the
new persistence boundary.

There is no silent wrapping, adoption, or automatic migration of legacy
payload bytes into the versioned encrypted envelope.

Any future legacy migration must be explicit and separately controlled.

This is a deliberate fail-closed compatibility decision.

## Lockfile and Source Identity

Verified `Cargo.lock` SHA-256:

`9b33517f58b16900e774e26132fbbb7a48179f121d2795365c9608d45bc19c8b`

Source-tree manifest SHA-256:

`57ec38708204264c453bca8d4c5b4657a04521d2409d350960746524635a1460`

Raw evidence `summary.json` SHA-256:

`a093c10d5255bcd80dccaadb5641eb6bc840a7d90c710e3419b70b6bdb453a6d`

Raw evidence checksum manifest SHA-256:

`386460e6a31110ab17209d742d89fb24c6d6af728f353f4b5f1d9bca144f525b`

## Raw Evidence

Archived commit-bound evidence:

`verification/evidence/raw/fv5/p1c-b-eace7cc86c35-r1/`

Checksum manifest:

`verification/evidence/raw/fv5/p1c-b-eace7cc86c35-r1/SHA256SUMS.txt`

The package contains:

- commit-bound Cargo check output;
- complete dynamic-test output;
- baseline-aware Clippy logs and comparison summary;
- three commit-bound targeted Kani logs;
- source and environment identity;
- P1c-A partial full-Kani resource-limit evidence;
- machine-readable resource classification;
- the empty named audit/Kani boundary diff;
- machine-readable P1c-B evidence summary;
- SHA-256 manifest.

## Remaining Limitations

### Persisted metadata confidentiality

Payload encryption does not conceal record existence, owner, tier,
timestamp, or other clear persisted metadata.

This remains `LIMIT-009`.

### Public salt mutation boundary

P1a removed direct public mutation authority over record salt state.

`LIMIT-010` remains source-remediated with final FV-5 phase closure still
pending.

### Persisted timestamp authenticity

Structural timestamp validation does not cryptographically authenticate
`created_at`.

This remains `LIMIT-012`.

### Local clock anomaly

The distinction between local construction permitting a zero timestamp
under a clock anomaly and persisted reconstruction rejecting zero remains
unchanged.

This remains `LIMIT-013`.

### Full Kani verifier resource ceiling

The full audit-related Kani suite is not green under the current local
resource/harness configuration.

The baseline reproduction and resource-exhaustion evidence are retained
rather than converted into a false proof claim or false property failure.

## Evidence Classification

- typed encrypted payload migration: `PASS`;
- versioned persisted envelope emission: `PASS`;
- persisted structural envelope validation: `PASS`;
- unmarked legacy payload rejection: `PASS`;
- unknown-version rejection: `PASS`;
- truncated-envelope rejection: `PASS`;
- valid versioned persisted reconstruction: `PASS`;
- dynamic commit-bound suite: `271 PASS / 0 FAIL`;
- baseline-aware Clippy: `PASS / 0 NEW DIAGNOSTICS`;
- three targeted Kani harnesses:
  `1514 CHECKS / 0 FAILED / 21 UNREACHABLE`;
- unsupported Kani constructs: `DISCLOSED`;
- complete Kani suite:
  `NOT GREEN / BASELINE-CONSTRAINED RESOURCE EXHAUSTION`;
- observed assertion counterexample in baseline full-suite attempt: `NO`;
- AES-GCM formal verification: `NOT CLAIMED`;
- automatic legacy adoption or migration: `NOT PRESENT`;
- `LIMIT-009`: `OPEN`;
- `LIMIT-010`: `SOURCE REMEDIATED / FV-5 PHASE CLOSURE PENDING`;
- `LIMIT-012`: `OPEN`;
- `LIMIT-013`: `OPEN`.

No claim is made here that AES-GCM, clear persisted metadata, the complete
audit implementation, crash consistency, third-party cryptographic
dependencies, or the complete EdisonDB system has been formally verified.
