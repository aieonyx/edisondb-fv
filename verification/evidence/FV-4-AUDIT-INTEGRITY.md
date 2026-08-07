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

Final result:

- 7 proof harnesses verified
- 194 verification checks
- 0 failed checks
- 4 unreachable checks
- Verification successful

The FV-4 proof establishes that an audit-link decision is valid exactly when:

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
