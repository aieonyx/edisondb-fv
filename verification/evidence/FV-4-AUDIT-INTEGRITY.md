# FV-4 Audit Integrity Evidence

**Project:** EdisonDB-FV
**Phase:** FV-4 — Audit Integrity
**Date:** 2026-08-06
**Branch:** `fv/audit-integrity`
**Copyright:** Edison Lepiten / AIEONYX
**License:** Apache License 2.0

## Verified security claims

1. Every audit entry contains a deterministic self-sealing `entry_hash`.
2. Each entry commits to its predecessor through `prev_hash`.
3. The first audit entry must reference the zero hash.
4. Tampering with any sealed entry invalidates the audit chain.
5. Tampering with the final audit entry is detected.
6. Malformed persisted audit entries are rejected.
7. Missing or non-sequential audit entries are rejected.
8. Audit keys use canonical fixed-width 20-digit sequence numbers.
9. Redb persistence removes stale audit rows before rewriting the chain.
10. Redb and Fjall validate the complete persisted audit chain when opened.
11. Redb refuses to save an invalid in-memory audit chain.
12. ARPi headers commit to the sealed audit-chain tail rather than the previous-link hash.

## Formal verification

Toolchain:

- Kani Rust Verifier 0.67.0
- CBMC 6.8.0

Original recorded result:

- 7 proof harnesses verified
- 194 verification checks
- 0 failed checks
- 4 unreachable checks
- Verification successful

FV-4b evidence-integrity re-audit established that the `194 checks /
4 unreachable` values belonged only to the final
`kani_owner_nonempty_invariant` harness. They were not an aggregate count for
all seven harnesses.

Independent historical reproduction at commit
`5885efbdf1f4b186c68962ccb78c5dc793d78678` with Kani 0.67.0 and CBMC 6.8.0
verified all 7 harnesses with 0 failures.

Per-harness summaries:

- `kani_owner_nonempty_invariant`: 194 checks, 4 unreachable
- `kani_tier_gate_critical`: 237 checks, 5 unreachable
- `kani_policy_tier_ceiling`: 7 checks, 0 unreachable
- `kani_record_identity_validation`: 198 checks, 4 unreachable
- `kani_storage_id_immutability`: 8 checks, 0 unreachable
- `kani_audit_link_integrity`: 1 check, 0 unreachable
- `kani_persisted_record_metadata`: 1 check, 0 unreachable

Arithmetic sum: 646 checks, 0 failures, 13 unreachable. This arithmetic sum
is not a Kani-emitted aggregate count.

Combined raw evidence:

`verification/evidence/raw/fv4-historical-all-harnesses.log`

SHA-256:

`b17f6dfa5c195b3eb778c4c25993d132c4f2d20e87b450657a508e75e751bc52`

The historical `kani_audit_link_integrity` harness reproduced successfully,
but later review established that it proves only its Boolean decision helper
and does not constitute a production audit-chain proof.

The historical FV-4 proof recorded that an audit-link decision is valid
exactly when:

- the previous hash matches the expected chain tail; and
- the current entry seal is valid.

The production audit invariant applies this rule across the complete chain.

## Runtime verification

FV-4 audit-integrity tests:

- 11 passed
- 0 failed

Covered failure conditions:

- malformed Redb audit entry
- broken Redb audit chain
- tampered Redb audit chain
- stale Redb audit rows
- noncanonical Redb audit key
- malformed Fjall audit entry
- broken Fjall audit chain
- tampered final Fjall entry
- noncanonical Fjall audit key
- Fjall audit sequence gap

Full regression result:

- 220 tests passed
- 0 tests failed
- 7 benchmark targets completed successfully

## Static-analysis result

The scoped FV-4 Clippy gate examined 8 changed Rust files:

- no FV-4 warnings
- no FV-4 errors

The repository-wide `cargo clippy --all-targets -- -D warnings` command remains blocked by 10 inherited findings in unrelated migration, policy, and sovereign-embedding code. Those findings were not introduced or modified by FV-4.

## Scope boundaries

FV-4 establishes audit-chain structure, persistence validation, canonical sequencing, self-sealing entries, and fail-closed loading.

The following remain outside this phase:

- cryptographic proof of the SHA-256 implementation
- multi-operation crash atomicity
- concurrent writer ordering
- process interruption recovery
- public API error-propagation redesign

Those concerns belong to later verification and qualification phases.

## Conclusion

FV-4 demonstrates that EdisonDB-FV detects malformed, reordered, missing, incorrectly keyed, link-tampered, and content-tampered audit records across both Redb and Fjall persistence paths.

The audit-chain tail exported through ARPi now represents the sealed final entry.

## ERRATA — FV-4b

FV-4 claim 5 stated that "tampering with the final audit entry is detected."
That wording was imprecise.

The FV-4 implementation detects modification of a final audit entry because
its stored `entry_hash` no longer matches the hash recomputed from the entry
content and `prev_hash`.

However, the pre-FV-4b `verify_audit_chain()` implementation does not detect
removal of the final audit entry. A truncated chain prefix can remain
internally valid because the verifier has no independently persisted expected
entry count or expected terminal chain hash.

FV-4b records this as a witnessed historical limitation. The local
remediation now persists an audit checkpoint containing the expected entry
count and expected terminal chain hash across the Redb and Fjall persistence
paths.

FV-4b additionally closes public local re-anchoring paths discovered during
review: `Store` storage collections are no longer publicly mutable, and Redb
`Store::save()` requires the already-persisted audit history to be an exact
prefix of the candidate history before rewriting persisted state.

The checkpoint tail-drop rejection harness and current dynamic storage/lineage
tests pass. Final FV-4b release closure still requires commit-bound evidence and
the remaining phase-level remediation obligations.

This correction does not change the original FV-4 verification results. It
narrows the interpretation of the claim to what the implementation actually
established.

### Security scope

The FV-4 hash chain is tamper-evident but not independently authenticated.
An attacker capable of rewriting both the audit chain and its checkpoint is
outside the protection provided by the FV-4b checkpoint alone. Authentication
of the checkpoint is deferred to the encryption and secret-boundary phase.

### ERRATUM #2 — ARPi audit-tail integration

FV-4 claim 12 stated that ARPi headers commit to the sealed audit-chain tail.
That statement requires a narrower interpretation.

The ARPi API surface includes an audit-aware header construction path that
accepts the sealed audit-chain tail, and the FV-4 test suite exercises that
path.

However, FV-4b architectural review found that this audit-aware construction
path is not currently wired into a production serving path. The verified
property therefore applies to the API-level construction path and must not be
interpreted as evidence that deployed responses currently carry an external
audit-chain anchor.

FV-4b also records that the mobile deployment uses a separate ARPi-format
implementation whose provenance data is not the same as the audit-tail field
used by the server-side ARPi format.

Accordingly, ARPi is not treated as a current external audit anchor in the
FV-4b threat model. Production integration and interface unification remain
separate remediation work.

#### Registered limitations

The following limitations were identified during FV-4b architectural review
and are assigned to later verification phases:

- `LIMIT-002`: the audit-tail-aware ARPi header construction path is verified
  at API level but is not wired into a production response path.
- `LIMIT-003`: the mobile database path does not currently route through the
  same verified storage and policy chokepoint as the core Store path.
- `LIMIT-004`: mobile provenance/content verification requires fail-closed
  on-device enforcement on the deployed target.
- `LIMIT-005`: mobile record persistence and write-counter persistence are
  not yet demonstrated to be one atomic crash-consistent transition.

These entries are findings, not completed remediations. Their final mappings
to claims, tests, harnesses, and assigned phases will be maintained in the
FV-4b claim registry.
