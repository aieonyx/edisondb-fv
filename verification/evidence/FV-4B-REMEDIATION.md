# FV-4b Remediation Evidence

Copyright (c) 2026 Edison Lepiten / AIEONYX

## Status

FV-4b is in progress.

This document records remediation evidence produced after the FV-4
architectural audit. Individual evidence items may pass while the overall
phase remains open.

## CLAIM-FV4B-001 — Bounded Audit Tamper Detection

### Production boundary

The randomized validation exercises `AuditEntry::new()`.

That production constructor computes `entry_hash` through the production
canonical audit serialization and production SHA-256 path. The property tests
do not reconstruct the canonical serialization or implement a separate SHA-256
calculation.

### Real SHA-256 randomized validation

Result:

`PASS`

Locked command scope:

- integration test target: `fv4_audit_integrity_tests`;
- property-test filter: `audit_sha256_`;
- dependency graph enforced with `--locked`;
- 4,096 timestamp single-bit mutation cases;
- 4,096 `prev_hash` single-bit mutation cases;
- 4,096 distinct-record identity cases;
- 12,288 randomized trials total.

Observed result:

- 3 tests passed;
- 0 tests failed;
- 12 unrelated tests filtered out;
- property-test execution: 1.39 seconds;
- total command elapsed time: 3.14 seconds;
- maximum resident set size: 604,276 KB;
- exit status: 0;
- no warnings or errors reported.

Final raw evidence:

`verification/evidence/raw/fv4b/real-sha-proptest-12288.log`

SHA-256:

`02225669aca14e95097f1015fb81dca8aa4ae5d7157b78aab92175e3a4ebe316`

Earlier intermediate 8,192-trial evidence is retained at:

`verification/evidence/raw/fv4b/real-sha-proptest-locked.log`

SHA-256:

`7f423f5939498245d9b99f53be76714a8d16ef655f8964cffb94c7eae4b63a27`

The `Cargo.lock` SHA-256 before and after the locked validation was identical:

`a0fdc98da50a71804566cee4e760c482b5f927a99ef85a3d6762aa3e45631740`

The exact randomized input sequence is not claimed to be deterministic.
`--locked` establishes dependency-graph stability, not fixed property-test
randomness.

### Kani bounded-model-checking result

Result:

`INCONCLUSIVE — VERIFIER RESOURCE CEILING`

The forward single-bit tamper harness reached symbolic execution and
propositional reduction but CBMC was terminated by the kernel OOM killer.

Kernel record:

- process: `cbmc`;
- anonymous RSS at termination: 26,034,328 KB;
- total virtual memory: 42,116,100 KB.

Raw evidence:

`verification/evidence/raw/fv4b/forward-tamper-oom.log`

SHA-256:

`1d69881daa4e9a4a2cd9266c395301cc1b0796457088c76383f080f9432708c8`

Kernel evidence:

`verification/evidence/raw/fv4b/forward-tamper-oom-kernel.log`

SHA-256:

`95dc36c1d0bafd444e847a86848bf9544c76fd387aa0788eea829697a0190532`

This termination is a verifier resource failure. It is not a counterexample
to the target property and is not counted as a successful proof.

### Cross-entry identity-separation Kani result

Result:

`INCONCLUSIVE — VERIFIER RESOURCE CEILING`

The cross-entry harness was reduced from whole-digest equality to the
structural identity byte carried by the bounded verification digest.

Despite that reduction, CBMC exceeded the protected memory scope during
propositional solving.

Observed kernel record:

- process: `cbmc`;
- termination constraint: `CONSTRAINT_MEMCG`;
- anonymous RSS at termination: 18,792,092 KB;
- total virtual memory: 23,388,504 KB;
- systemd result: `oom-kill`;
- scope CPU consumption: 2 minutes 59.276 seconds.

Raw verification log:

`verification/evidence/raw/fv4b/cross-entry-oom.log`

SHA-256:

`680dc6c699d9a7915ebb5fa79e87bf569826736732646df69ec3a3631e5f0c2a`

Kernel evidence:

`verification/evidence/raw/fv4b/cross-entry-oom-kernel.log`

SHA-256:

`1aab52b40c1867154ecec045f1de11c08971ebad18d6da08985a04abdcbdefeb`

Systemd scope evidence:

`verification/evidence/raw/fv4b/cross-entry-oom-systemd.log`

SHA-256:

`27703fe316769dc0ab907b73a2a1a529d64ee2a99877eeb5fa2bd78104048a8d`

This is a verifier resource failure and is not a counterexample. It is not
counted as a successful formal proof.

Production-path cross-entry separation is covered by the final randomized
real-SHA property-test run recorded above. The corresponding Kani obligation
remains formally inconclusive because of the verifier resource ceiling.

### Earlier fixed-array injectivity attempt

The earlier fixed-array equality formulation also exceeded the available CBMC
memory budget.

Raw evidence:

`verification/evidence/raw/fv4b/fixed-array-injective-oom.log`

SHA-256:

`2dcfd5822ee75b7e181ab5e04427ddfff5210e9756bc696b28bcbdb85637c3e5`

Kernel evidence:

`verification/evidence/raw/fv4b/fixed-array-injective-oom-kernel.log`

SHA-256:

`2ece30c56b6ec7ea8a269a11e4bfa4c0b7593eec887dfcd1f9ae38c8d4751f0e`

## Dependency Provenance Note

The FV baseline contained a source-less `fjall 3.1.6` lock entry.

Git history established that:

- the dependency was originally registry-sourced;
- commit `136fc12` introduced a temporary local `[patch.crates-io]` override;
- baseline commit `f6fe95a` removed that override because upstream Fjall 3.1.6
  contained the required Android behavior;
- the source-less lock identity remained after the manifest patch was removed.

The current lockfile therefore normalizes Fjall 3.1.6 back to its registry
source rather than treating the stale path-package identity as an intentional
local dependency.

Storage versions remain:

- `fjall 3.1.6`;
- `lsm-tree 3.1.6`.

Property testing adds:

- `proptest 1.11.0`.

## Critical Policy Ceiling Remediation

### Direct production-engine attempt

The first FV-4b policy remediation attempt exercised the Critical-tier property
through the concrete `PolicyEngine::evaluate` implementation.

Result:

`INCONCLUSIVE — VERIFIER/LIBRARY OBSTRUCTION`

The concrete engine contains a `HashMap`. During bounded model checking, the
verification path entered standard-library `getrandom` and SipHash machinery
associated with randomized hash-state construction.

The run reached the configured five-minute timeout with exit status `124`.
No successful-verification marker was produced.

This result is not a counterexample to the Critical-tier property and is not
counted as a formal pass.

Raw evidence:

`verification/evidence/raw/fv4b/policy-real-engine-getrandom-timeout.log`

SHA-256:

`70a3e8a45d3fe2c7940b871df7f245a45e4159409a59aeba2c61a7dcfe775d88`

### Production decision-core extraction

The smallest production decision core required for the owner/Critical boundary
was extracted as:

- `PolicyPrecheck`;
- `policy_precheck`.

The extraction is part of the production policy path rather than a
verification-only model.

`PolicyEngine::evaluate` delegates to this precheck before processing:

- explicit deny rules;
- delegation roles;
- explicit allow rules;
- default deny.

The precheck therefore establishes the Critical ceiling before collection-backed
policy state can influence the request.

### Kani production-precheck result

Result:

`FORMAL PASS`

Harness:

`kani_policy_tier_ceiling`

Toolchain:

- Kani 0.67.0;
- CBMC 6.8.0.

Result summary:

- `0 of 23 failed`;
- `VERIFICATION:- SUCCESSFUL`;
- `1 successfully verified harnesses, 0 failures, 1 total`;
- verification time reported by Kani: `0.092333086s`;
- command wall time: `5.34s`;
- maximum resident set size: `366348 KB`;
- exit status: `0`.

The four policy decision assertions succeeded for:

- owner / Critical -> `PermitOwner`;
- non-owner / Critical -> `DenyCritical`;
- owner / non-Critical -> `PermitOwner`;
- non-owner / non-Critical -> `Continue`.

No `getrandom`, SipHash, or `RandomState` path appeared in the successful
production-precheck proof.

Raw evidence:

`verification/evidence/raw/fv4b/policy-precheck-production-pass.log`

SHA-256:

`e18863d0530cce2f38b0dc3a965e1c0ace815830188b7370655256d56573e89b`

### Policy proof scope

The formal result applies to the production `policy_precheck` decision core
used by `PolicyEngine::evaluate`.

It does not establish formal verification of the complete HashMap-backed
delegation/rule-processing implementation.

The direct full-engine attempt is retained as evidence of the verifier/library
boundary rather than being represented as either a proof success or a policy
failure.

## Audit checkpoint and lineage remediation

FV-4b implements the approved remediation for the local audit-tail truncation
finding.

Both Redb and Fjall persist and validate an audit checkpoint containing the
expected audit-entry count and terminal entry hash.

The storage paths reject missing, malformed, count-mismatched, head-mismatched,
and unanchored-record checkpoint states according to the declared fail-closed
open rules.

Redb `Store::save()` also validates the existing persisted audit history inside
the same Redb write transaction and requires that history to be an exact prefix
of the candidate history before rewriting records, audit rows, and checkpoint.

This rejects:

- final audit-row removal with an intact checkpoint;
- unrelated history replacement;
- stale-snapshot overwrite after another writer extends the history;
- divergent writers branching from the same persisted history.

It permits:

- same-lineage resave;
- legitimate extension of the persisted history.

### Formal checkpoint evidence

Harness:

`kani_audit_chain_tail_drop_checkpoint_rejected`

Result:

`PASS — 0 of 90 checks failed`

Toolchain:

- Kani Rust Verifier 0.67.0
- CBMC 6.8.0

Raw evidence:

`verification/evidence/raw/fv4b-kani-tail-drop-checkpoint-rejected.log`

SHA-256:

`ec944943addc3e7eedb7a8bf49c9704736df75efc0aaaba7d1eab82faa6387e1`

### Dynamic lineage evidence

Current archived evidence:

- `fv4b-current-tree-all-targets.log`
  - SHA-256 `93235066b36cfab57506b6787712a4bb6fd636f0b20522a9a067691b3a6e425b`
- `fv4b-redb-lineage-gate.log`
  - SHA-256 `0b128af2b527f83ce460d0ce911b6dc46e8ef6b81eaacf27cb7054a0ff1bd505`
- `fv4b-stale-writer-lineage.log`
  - SHA-256 `4078b6de649dec6ec425f5852b00f4eb785a2f2ee85280bbe865c433a1cebb42`
- `fv4b-fv3-checkpoint-fixture-repair.log`
  - SHA-256 `c8564bfbdd937f51721a5ac414d5ae23321d73167c729c64a4a8d41916712500`

The current-tree regression completed with zero failed test targets.

### LIMIT-001 status

`LOCAL REMEDIATION COMPLETE / COMMIT-BOUND EVIDENCE COMPLETE`

The remaining security boundary is different from local tail truncation:
the checkpoint is not yet authenticated against an attacker who can coherently
rewrite both the complete audit history and the checkpoint.

Authenticated checkpoint sealing remains assigned to FV-5.

The archived logs in this section were produced from the current remediation
working tree. Final FV-4b evidence is now bound to reviewed source commit `5c63ac45289e876eb563f1752eb796a19b553534` through successful GitHub Actions run `32210859833`.

## Assumptions

1. The production SHA-256 implementation is treated as a trusted
   cryptographic primitive.
2. SHA-256 collision resistance is assumed and is not formally proved by
   EdisonDB-FV.
3. Randomized property testing supplies dynamic evidence only.
4. The verification-only digest model is not evidence that production SHA-256
   itself has been formally verified.
5. The archived raw logs are identified by their recorded SHA-256 digests.

## Commit-Bound Verification Closure

Reviewed production source:

`5c63ac45289e876eb563f1752eb796a19b553534`

GitHub Actions verification:

- workflow: `EdisonDB Kani Verification`;
- run ID: `32210859833`;
- event: `workflow_dispatch`;
- conclusion: `success`;
- Kani: `0.67.0`;
- CBMC: `6.8.0`;
- Rust: `1.97.0`;
- mandatory harnesses: `6 / 6` successful;
- arithmetic Kani total: `938 checks / 0 failed / 13 unreachable`.

The six mandatory harnesses cover the production-path owner validation,
Critical-tier precheck, record identity validation, storage ID immutability,
checkpoint-backed tail-drop rejection, and persisted-record metadata
validation.

The CI artifact includes the six raw harness logs, pinned toolchain evidence,
and workflow provenance binding run `32210859833` to the reviewed source
commit. The final evidence package also retains the corresponding local
commit-bound Kani run, the `cargo test --locked --lib --tests
-- --test-threads=1` gate, and the benchmark smoke gate.

The local test result is an arithmetic per-target sum of `254 passed /
0 failed / 0 ignored`. The benchmark smoke gate completed all seven expected
benchmark cases successfully.

Evidence:

`verification/evidence/raw/fv4b/final-5c63ac45289e/`

Manifest:

`verification/evidence/raw/fv4b/final-5c63ac45289e/SHA256SUMS.txt`

This closure does not broaden the formal claims. The production SHA-256
bounded-model experiments previously classified as `INCONCLUSIVE` remain so.
The complete HashMap-backed `PolicyEngine` is not claimed as formally
verified. Authenticated checkpoint sealing remains deferred to FV-5, and
complete Edison-owned local-state erasure remains `LIMIT-008`.

## Explicit Limitations

1. `CLAIM-FV4B-001` is not a formal proof of SHA-256 injectivity or collision
   resistance.
2. The forward Kani tamper-detection obligation remains formally inconclusive
   because the verifier exceeded the available memory ceiling.
3. No successful FV-4b Kani check total is published from the inconclusive
   runs.
4. `LIMIT-001` local audit-tail truncation and API re-anchoring remediation is
   implemented and has passed its current formal/dynamic gates. Final
   commit-bound evidence is now recorded under `verification/evidence/raw/fv4b/final-5c63ac45289e/`.
   Authenticated checkpoint sealing remains outside this local remediation and
   is assigned to FV-5.
5. Remaining FV-4b remediation obligations are not closed by these property
   tests.
6. Historical FV-2, FV-3, and FV-4 Kani count re-audit is complete.
   `LIMIT-006` records the corrected interpretation, exact source commits,
   toolchain, normalized dependency-state caveat, arithmetic per-harness
   totals, and archived raw evidence.
7. The policy formal result covers the production `policy_precheck` decision core; the complete HashMap-backed `PolicyEngine` is not claimed as formally verified.
8. `LIMIT-007` records the former Fjall related-write persistence gap as
   `REMEDIATED / CURRENT`. FV-4b batches the related audit/data/checkpoint
   mutations, but crash, power-loss, filesystem, and durability qualification
   remain assigned to FV-6.
9. `LIMIT-008` remains `OPEN / TRUST-BOUNDARY`: complete destruction or
   replacement of all Edison-owned local persisted state can be
   indistinguishable locally from fresh genesis when no independent continuity
   anchor survives.

## Evidence Classification

For CLAIM-FV4B-001:

- production SHA-256 randomized validation: `PASS — 12,288 trials`;
- timestamp single-bit mutation coverage: `PASS`;
- `prev_hash` single-bit mutation coverage: `PASS`;
- distinct-record identity separation coverage: `PASS`;
- production SHA-256 known-answer boundary: retained separately in FV-4 tests;
- Kani forward tamper proof: `INCONCLUSIVE`;
- Kani cross-entry separation proof: `INCONCLUSIVE`;
- cryptographic collision-resistance proof: `OUT OF SCOPE / ASSUMED`;
- direct HashMap-backed policy-engine proof: `INCONCLUSIVE — VERIFIER/LIBRARY OBSTRUCTION`;
- production Critical policy precheck: `FORMAL PASS — 0 of 23 checks failed`;
- overall FV-4b phase: `OPEN`.
