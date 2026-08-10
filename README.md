# EdisonDB — Formal Verification Track

> **This repository is the formal verification record for EdisonDB.**
> For the database itself — what it is, how to use it, architecture, roadmap — see the primary repo:
> **[github.com/aieonyx/edisondb](https://github.com/aieonyx/edisondb)**

---

## What This Repo Is

`edisondb-fv` is the machine-checked assurance track running in parallel with
EdisonDB's main development. It contains:

- Kani proof harnesses targeting the real production Rust code (no re-implementation)
- Verification evidence documents for each completed phase
- A claims registry (`verification/CLAIMS.md`) mapping every verified property to its harness and evidence
- An open limitations registry tracking every known gap and its assigned remediation phase
- Threat model and reproducible verification commands

No EdisonDB features are developed here. Every proof targets code that lives in the primary repo.

---

## Verification Progress

| Phase | Layer | Status |
| --- | --- | --- |
| FV-1 | Proof foundation — Kani integration, baseline harnesses, ownership + tier invariants | ✅ Complete |
| FV-2 | Sovereignty & access-control kernel — Critical-tier ceiling, policy engine, gRPC concurrent writes | ✅ Complete |
| FV-3 | Storage invariants — record identity, tier, and ownership across persistence | ✅ Complete |
| FV-4 | Audit-chain integrity — append-only linkage, tamper-evidence, hash-chain walk | ✅ Complete (with errata) |
| FV-4b | Remediation sprint — tautological harness replacement, real audit-chain proofs, claims/limits registry, evidence integrity | 🟡 In progress |
| FV-5 | Encryption & secret boundaries — EncryptedPayload newtype, AAD binding, ARPi counter, zeroization | ⬜ Next |
| FV-6 | Concurrency, atomicity, crash & recovery model | ⬜ Planned |
| FV-7 | External trust boundaries — gRPC / REST / SDK / FFI single-chokepoint | ⬜ Planned |
| FV-8 | End-to-end composition, traceability matrix, signed evidence release | ⬜ Planned |

### Key findings to date

- **LIMIT-001** — Audit tail-truncation (dropping only the last entry passes `verify_audit_chain()`).
  Remediation: persisted `AuditCheckpoint` approved, landing in FV-4b. Keyed BLAKE3 seal deferred to FV-5.
- **LIMIT-002** — `ArpiHeader::from_audit` is verified at API level but has no production callers.
  ARPi is not yet a live external audit anchor.
- **LIMIT-003** — `MobileDb` (Android path) bypasses the verified sovereignty kernel entirely —
  no `Store`, no tier ceiling, no audit chain. FV-7 single-chokepoint refactor is the remediation.
- **LIMIT-004** — On `target_os = android`, content-hash verification is cfg-gated off.
  Remediation: on-device BLAKE3 verification, FV-5.
- **LIMIT-005** — Record insert and `persist_counter()` are non-atomic; crash window allows
  duplicate `write_counter` values. FV-6 remediation.
- **LIMIT-006** — Published check counts (194) identical across FV-2/3/4 despite growing harness
  sets; under re-audit. Historical counts marked `HISTORICAL / NOT REPRODUCED` until reproduced.

---

## What Has Been Proven (so far)

All claims are bounded — verified over explicitly stated finite domains. See
`verification/CLAIMS.md` for the full registry with harness names, check counts, and evidence links.

**Sovereignty kernel (FV-2)**
- `Critical`-tier data is owner-only; no admin role, delegation rule, or explicit allow rule can expand the tier ceiling — proven over `PolicyEngine::evaluate()` and `tier_ceiling_allows()`.
- Wrong-owner reads return `PERMISSION_DENIED`; both granted and denied reads are durably recorded in audit history.

**Storage invariants (FV-3)**
- Record identity, tier, and ownership survive serialization and persist correctly through both Redb and Fjall backends.
- Failed operations leave prior valid state intact.

**Audit-chain integrity (FV-4 + FV-4b)**
- Content tamper, `prev_hash` tamper, `entry_hash` tamper, entry reorder, and interior-entry removal are all detected by `Store::verify_audit_chain()` — proven via the two-layer proof structure (chain-walk logic with injective model hash; production SHA-256 integration covered by proptest and known-answer test).
- Tail-truncation is an open limitation (LIMIT-001) with approved remediation in FV-4b.

---

## Honest Scope

- Proofs are **bounded** — verified over stated finite domains, not all possible inputs.
- Cryptographic primitive correctness (AES-GCM, SHA-256, Argon2) is a **trusted-dependency assumption** consistent with standard practice.
- EdisonDB does **not yet** claim to be "formally verified" as a whole. That wording is reserved for FV-8 completion and will describe only the specific core that has been proven.
- Every open limitation is tracked above and in `verification/CLAIMS.md`. Nothing is papered over.

---

## Repository Layout
verification/
CLAIMS.md — claims and limitations registry
evidence/
FV-1-FOUNDATION.md
FV-2-SOVEREIGNTY-KERNEL.md
FV-3-STORAGE-INVARIANTS.md
FV-4-AUDIT-INTEGRITY.md
FV-4B-REMEDIATION.md (in progress)
THREAT-MODEL.md (FV-5, pending)
src/
verification.rs — Kani harnesses (cfg(kani)-gated)
... — production EdisonDB source (mirrored from primary repo)
---

## License

Apache License 2.0 — © 2026 Edison Lepiten / AIEONYX

*"Light for your data."*
