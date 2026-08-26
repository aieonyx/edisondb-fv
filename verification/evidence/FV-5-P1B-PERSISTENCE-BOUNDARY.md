# FV-5 P1b Persistence Boundary Evidence

Copyright (c) 2026 Edison Lepiten / AIEONYX

## Status

`COMMIT-BOUND VERIFICATION PASS`

This document records the FV-5 P1b persistence-boundary remediation
and its commit-bound verification evidence.

The verified source commit is:

`354e1289dda9ff3bc15f41afc0242d7a8c5731a3`

Its parent is:

`81782052fb4ad1c73aeb51df0a72973318f4fa7c`

Its Git tree is:

`f55ef22d87f07fb7e5821b9d68ffa32c4ac17b6f`

The evidence-closure commit that contains this document and the archived
raw logs is documentation/evidence only. It does not replace the source
commit identified above as the subject of verification.

## Scope

FV-5 P1b narrows record construction and persisted reconstruction
authority without changing the persisted JSON record format.

The remediation establishes the following boundaries:

- public `Record` remains serializable but is no longer externally
  deserializable through Serde;
- persisted decoding uses the crate-private `PersistedRecord` DTO;
- all five direct persisted-record deserialization sites reconstruct
  through the validated persistence seam;
- record identity validation has one production definition;
- valid verification paths use the production-shared explicit-timestamp
  constructor rather than verification-only record construction;
- persisted `created_at == 0` fails closed with
  `EdisonError::InvalidCreatedAt`;
- ordinary in-process construction retains the documented distinction
  that a zero timestamp may represent a local clock anomaly;
- Fjall owner listing fails closed on malformed or structurally invalid
  persisted records instead of silently skipping them;
- migration reconstruction routes through the same validated seam.

## Public Deserialization Boundary

The external compile-fail case is:

`tests/ui/p1b_record_deserialize.rs`

The committed compiler golden is:

`tests/ui/p1b_record_deserialize.stderr`

The test proves that external code cannot perform:

`serde_json::from_str::<Record>(...)`

because `Record` does not implement `Deserialize`.

This is a compile-time construction-authority property. It is not a claim
that arbitrary serialized input is cryptographically authenticated.

## Compatibility Evidence

A compatibility fixture was generated from committed P1a source
`81782052fb4ad1c73aeb51df0a72973318f4fa7c`.

The P1b runtime test confirms that the pre-P1b JSON representation
round-trips byte-compatibly through the new persistence DTO and validated
reconstruction seam.

P1b intentionally does not introduce the versioned encrypted payload
envelope. That work belongs to the subsequent FV-5 payload-boundary phase.

## Dynamic Verification

Commit-bound R5 dynamic result:

- Cargo test targets counted: `15`;
- passed: `263`;
- failed: `0`;
- ignored: `0`.

The observed P1b closure tests include:

- pre-P1b persisted JSON byte compatibility;
- persisted zero-timestamp rejection;
- local zero-timestamp construction asymmetry;
- malformed Fjall persisted JSON rejection;
- exact `NoOwner` propagation during listing;
- exact `EmptyRecordId` propagation during listing;
- exact `InvalidCreatedAt` propagation during listing;
- external `Record` deserialization compile-fail enforcement.

## Kani Verification

**Commit-bound Kani arithmetic:** `852 checks / 0 failed / 10 unreachable` across 7 required harnesses.

Environment:

- Rust: `rustc 1.97.0 (2d8144b78 2026-07-07)`;
- Cargo: `cargo 1.97.0 (c980f4866 2026-06-30)`;
- Kani: `cargo-kani 0.67.0`.

Commit-bound R5 arithmetic:

- harnesses: `7`;
- checks: `852`;
- failed: `0`;
- unreachable: `10`.

Harness results:

| Harness | Checks | Failed | Unreachable | Unsupported notice |
| --- | ---: | ---: | ---: | --- |
| `kani_owner_nonempty_invariant` | 76 | 0 | 0 | no |
| `kani_policy_tier_ceiling` | 23 | 0 | 0 | no |
| `kani_record_identity_validation` | 77 | 0 | 0 | no |
| `kani_storage_id_immutability` | 8 | 0 | 0 | no |
| `kani_audit_chain_tail_drop_checkpoint_rejected` | 90 | 0 | 0 | no |
| `kani_persisted_record_metadata` | 363 | 0 | 5 | yes |
| `kani_persisted_created_at_validation` | 215 | 0 | 5 | yes |

The two persisted-record harness logs contain Kani
unsupported-construct notices. Both runs nevertheless completed with
zero failed checks and `VERIFICATION:- SUCCESSFUL`.

Those notices are retained in the raw logs and are not silently removed.
This evidence does not claim verification of behavior represented by
unsupported constructs themselves.

## Source Authority Census

At the verified source commit:

- direct `Record` Serde reconstruction sites: `0`;
- typed `PersistedRecord` direct Serde sites: `5`;
- verification direct `Record { ... }` construction: `0`;
- authoritative `Record` construction literal: confined to the
  production-shared constructor in `src/lib.rs`.

## Lockfile and Source Identity

Verified `Cargo.lock` SHA-256:

`9b33517f58b16900e774e26132fbbb7a48179f121d2795365c9608d45bc19c8b`

Source-tree manifest SHA-256:

`2455a3827fb12b419406aab2aa1eaafe9dabac7d2bd3ce2e4dec5c962d758fd4`

R5 evidence summary SHA-256:

`83ee3067ede4f2da171f2806a8d11b3c6644f5f078554cba2c0821d0c37c683d`

## Raw Evidence

Archived commit-bound evidence:

`verification/evidence/raw/fv5/p1b-354e1289dda9-r5/`

Checksum manifest:

`verification/evidence/raw/fv5/p1b-354e1289dda9-r5/SHA256SUMS.txt`

The raw R5 files were copied byte-for-byte from the commit-bound
verification workspace. No raw log was normalized or rewritten.

## LIMIT-011 Closure

`LIMIT-011` is closed for the P1b scope.

The former gap was that persisted records could be deserialized directly
into public `Record`, bypassing reconstruction validation and allowing
construction and persisted reconstruction invariants to diverge.

Closure evidence includes:

- removal of public `Record: Deserialize`;
- crate-private persisted DTO reconstruction;
- all five persisted decoding sites migrated;
- migration reconstruction routed through the validated seam;
- fail-closed exact-error listing tests;
- pre-P1b byte-compatibility evidence;
- external compile-fail construction-authority evidence;
- dedicated persisted timestamp Kani evidence;
- full dynamic and Kani commit-bound R5 verification.

This closure does not authenticate all persisted metadata and does not
close the separate timestamp-integrity limitation recorded as
`LIMIT-012`.

## Remaining Limitations

### Metadata confidentiality

Payload encryption does not by itself conceal record existence, owner,
tier, or other clear metadata. This remains `LIMIT-009`.

### Salt mutation boundary

The public record salt-mutation boundary discovered during FV-5 was
removed in P1a by making salt private. That remediation is recorded as
`LIMIT-010`; final FV-5 phase-level closure remains separate from this
P1b evidence package.

### Persisted timestamp integrity

`created_at` is persisted metadata and is not yet cryptographically bound
into the audit/checkpoint authenticity boundary. This remains
`LIMIT-012`, assigned to later authenticated metadata/checkpoint work.

### Local clock anomaly

`Record::new()` obtains its timestamp from the local clock. The current
clock helper may yield zero when the platform clock is before the Unix
epoch or duration acquisition falls back to the default.

P1b intentionally does not weaken persisted reconstruction to accept that
value after reopening. A locally constructed zero timestamp may therefore
exist in-process while persisted reconstruction rejects zero.

This remains `LIMIT-013`.

## Evidence Classification

- source authority remediation: `PASS`;
- persisted reconstruction validation: `PASS`;
- external deserialization compile-fail boundary: `PASS`;
- pre-P1b JSON compatibility: `PASS`;
- dynamic P1b closure suite: `PASS`;
- seven required Kani harnesses: `PASS`;
- unsupported Kani constructs: `DISCLOSED`;
- `LIMIT-011`: `CLOSED FOR P1B SCOPE`;
- `LIMIT-009`: `OPEN`;
- `LIMIT-010`: `SOURCE REMEDIATED / FV-5 PHASE CLOSURE PENDING`;
- `LIMIT-012`: `OPEN`;
- `LIMIT-013`: `OPEN`.

No claim is made here that AES-GCM, payload confidentiality, authenticated
metadata, crash consistency, or the complete EdisonDB system has been
formally verified.
