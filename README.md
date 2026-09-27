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
| FV-4b | Remediation sprint — tautological harness replacement, real audit-chain proofs, claims/limits registry, evidence integrity | ✅ Complete |
| FV-5 | Encryption & secret boundaries — encrypted payload persistence, AAD metadata authority, mobile counter/provenance, authenticated checkpoints | ✅ Complete |
| FV-6 | Concurrency, atomicity, crash & recovery model | ⬜ Next |
| FV-7 | External trust boundaries — gRPC / REST / SDK / FFI single-chokepoint | ⬜ Planned |
| FV-8 | End-to-end composition, traceability matrix, signed evidence release | ⬜ Planned |

### September 2026 — FV-5 complete

FV-5 **Encryption & Secret Boundaries** is complete and merged through
[PR #13](https://github.com/aieonyx/edisondb-fv/pull/13).

The phase adds bounded verification and hardening around EdisonDB's
encrypted persistence and authenticated metadata boundaries:

- versioned encrypted-payload persistence;
- validated persisted-record reconstruction;
- hardened AAD authority for record identity and tier metadata;
- mobile write-counter monotonicity and fail-closed provenance validation;
- authenticated audit-checkpoint sealing;
- authenticated handling of persisted nonzero `created_at` metadata;
- commit-bound verification evidence for the completed FV-5 claims.

FV-5 closes **CLAIM-FV5-001 through CLAIM-FV5-007** within their documented
scope. Full cryptographic primitive verification is **not** claimed:
AES-GCM, BLAKE3, Argon2, MAC unforgeability, external anti-rollback,
wall-clock correctness, and complete local-state replacement detection
remain outside these bounded claims.

See [`verification/evidence/FV-5-PHASE-CLOSURE.md`](verification/evidence/FV-5-PHASE-CLOSURE.md)
for the phase accounting and [`docs/SEPTEMBER-2026.md`](docs/SEPTEMBER-2026.md)
for the public September summary.

## Key findings to date

- **LIMIT-001** — Local audit-tail truncation remediation is complete in FV-4b.
  Authenticated checkpoint sealing for authenticated mode is complete in FV-5 P3.5.
  Total local-state destruction/replacement remains separately tracked by `LIMIT-008`.
- **LIMIT-002** — ARPi production integration remains assigned to FV-7.
- **LIMIT-003** — Mobile verified-kernel integration remains assigned to FV-7.
- **LIMIT-004** — Closed for the bounded mobile fail-closed provenance-validation scope by
  `CLAIM-FV5-006`.
- **LIMIT-005** — FV-5 witness complete; crash-consistent remediation remains assigned to FV-6.
- **LIMIT-006** — Historical Kani check-count reporting was re-audited and corrected;
  status is `RESOLVED / CORRECTED`.
- **LIMIT-007** — Current Fjall related-write implementation gap remediated; crash/power-loss
  qualification remains assigned to FV-6.
- **LIMIT-008** — Remains `OPEN / TRUST-BOUNDARY`.
- **LIMIT-009** — Persisted metadata confidentiality remains an explicit nonclaim.
- **LIMIT-010** — Closed for the bounded public record-salt mutation scope.
- **LIMIT-011** — Closed for the P1b persisted-reconstruction scope.
- **LIMIT-012** — Closed for the authenticated checkpoint-v2 persisted-`created_at` scope.
- **LIMIT-013** — Local zero-timestamp clock anomaly remains open and separate.

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
- Local audit-tail truncation remediation was completed in FV-4b; authenticated checkpoint sealing was completed in FV-5 P3.5. Complete local-state destruction/replacement remains the separate `LIMIT-008` trust boundary.

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
FV-4B-REMEDIATION.md
FV-5-PHASE-CLOSURE.md
FV-5-LIMIT-004-MOBILE-PROVENANCE.md
FV-5-LIMIT-012-CREATED-AT-AUTHENTICITY.md
src/
verification.rs — Kani harnesses (cfg(kani)-gated)
... — production EdisonDB source (mirrored from primary repo)
---

## License

Apache License 2.0 — © 2026 Edison Lepiten / AIEONYX

*"Light for your data."*
