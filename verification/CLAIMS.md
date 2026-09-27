# EdisonDB-FV Claim Registry

Copyright (c) 2026 Edison Lepiten / AIEONYX

## Purpose

This registry maps EdisonDB-FV assurance claims to their implementation
boundaries, verification harnesses, behavioral tests, evidence records,
assumptions, limitations, and historical status.

The registry does not upgrade historical evidence. A claim is recorded only
at the strength supported by its source phase and later corrections.

Historical verification counts are retained as originally recorded in phase
evidence. Where independent re-audit identifies a reporting error, the
original record remains historical and the corrected interpretation is
recorded explicitly under `LIMIT-006`.

## Status Vocabulary

- `HISTORICAL` — established or reported by the named completed phase.
- `CURRENT` — supported by the current verification state.
- `RE-AUDIT` — historical evidence exists but is being independently checked.
- `REMEDIATION` — a known gap is being corrected in a later phase.
- `INCONCLUSIVE` — a verification attempt reached a documented tool or
  resource ceiling and did not establish or refute the property.
- `LIMITED` — the claim is valid only within an explicitly stated boundary.

## FV-1 — Bootstrap Invariants

### CLAIM-FV1-001 — Record owner non-empty

**Historical property**

A record satisfies the owner invariant only when its owner identifier is
non-empty.

**Historical source**

- Commit: `a2dda1a`
- Production/specification helper:
  `invariant_record_owner_nonempty`
- Historical Kani harness:
  `kani_owner_nonempty_invariant`

**Evidence status**

`HISTORICAL / RE-AUDIT`

FV-1 had no contemporaneous file under `verification/evidence/` at the merge
commit. The source commit is therefore the historical source of truth.

The current FV-4b audit identified the owner-nonempty harness as requiring
replacement with a production-path proof before it can be treated as current
formal evidence.

No historical Kani check count is asserted here until independently
reproduced from the historical commit and compatible toolchain.

### CLAIM-FV1-002 — Critical tier owner gate

**Historical property**

Critical-tier records are readable only by their owner at the tier-gate
boundary.

**Historical source**

- Commit: `a2dda1a`
- Invariant helper: `invariant_tier_gate`
- Historical Kani harness: `kani_tier_gate_critical`

**Evidence status**

`HISTORICAL / RE-AUDIT`

The historical invariant implementation also grouped Personal with Critical,
but the contemporaneous Kani harness identified during source reconstruction
specifically exercised the Critical tier. This registry does not expand that
historical formal claim beyond the harness identified at the commit.

No historical Kani check count is asserted here until independently
reproduced.

## FV-2 — Sovereignty Kernel

### CLAIM-FV2-001 — Critical access ceiling

**Property**

For data classified as Critical, access is permitted only when the requester
is the authenticated owner.

Administrator roles, delegated roles, and explicit allow rules cannot expand
the Critical-tier ceiling.

Equivalent decision:

    Critical access permitted <=> requester is owner

**Implementation boundary**

- `src/policy.rs`
- `tier_ceiling_allows(is_owner, tier)`
- The ceiling executes before delegated roles and explicit allow rules.

**Formal harness**

- `kani_policy_tier_ceiling`

**Behavioral evidence**

FV-2 evidence records:

- administrator delegation cannot access Critical data;
- explicit allow rule cannot access Critical data;
- wrong-owner Critical gRPC reads return `PERMISSION_DENIED`;
- unauthenticated requests are rejected.

**Evidence**

- `verification/evidence/FV-2-SOVEREIGNTY-KERNEL.md`

**Status**

`HISTORICAL / CORRECTED`

The FV-2 evidence document originally reported 3 harnesses and 194 checks.
Independent historical re-audit under `LIMIT-006` reproduced all 3 harnesses
and established that `194 checks / 4 unreachable` was the summary of the final
owner-nonempty harness, not an aggregate count for all 3 harnesses.

The reproduced per-harness summaries have an arithmetic sum of 438 checks,
0 failures, and 9 unreachable checks. Kani did not emit an aggregate check
count for the combined run.

The security property itself is not discarded by the historical reporting
error; numeric evidence is recorded separately from claim strength.

## FV-3 — Storage Invariants

### CLAIM-FV3-001 — Stored record identity validity

**Property**

Protected storage boundaries reject records with an empty owner or empty
record identifier before accepting them as active state.

**Implementation boundaries**

- `Store::write`
- `Store::save`
- `Store::load`
- `FjallBackend::write`
- `FjallBackend::open`

**Formal evidence**

Historical FV-3 harness coverage includes record identity validation.

Relevant current harness names include:

- `kani_owner_nonempty_invariant`
- `kani_record_identity_validation`

The owner-nonempty proof is under FV-4b production-path remediation and is not
treated as current formal evidence until that remediation completes.

**Behavioral tests**

- `store_rejects_empty_owner_without_mutation`
- `store_rejects_empty_record_id_without_mutation`
- `store_refuses_to_save_invalid_public_state`
- `store_load_rejects_invalid_record`
- `fjall_rejects_empty_owner_without_mutation`
- `fjall_rejects_empty_record_id_without_mutation`
- `fjall_open_rejects_invalid_persisted_record`

**Evidence**

- `verification/evidence/FV-3-STORAGE-INVARIANTS.md`

**Status**

`HISTORICAL / RE-AUDIT`

### CLAIM-FV3-002 — Global record-ID immutability

**Property**

Record identifiers are immutable and globally unique across Critical,
Personal, and Noise storage tiers.

**Formal harness**

- `kani_storage_id_immutability`

**Behavioral evidence**

- `fjall_enforces_global_id_immutability_across_tiers`
- `fjall_open_rejects_cross_tier_duplicate_ids`

**Evidence**

- `verification/evidence/FV-3-STORAGE-INVARIANTS.md`

**Status**

`HISTORICAL / RE-AUDIT`

### CLAIM-FV3-003 — Persisted metadata fails closed

**Property**

Persisted storage metadata must remain internally consistent before a Redb or
Fjall database becomes usable.

The behavioral boundary rejects:

- persisted key and record-ID mismatch;
- Fjall tier and keyspace mismatch;
- duplicate IDs across Fjall keyspaces;
- malformed persisted records.

**Behavioral tests**

- `store_load_rejects_key_id_mismatch`
- `fjall_open_rejects_key_id_mismatch`
- `fjall_open_rejects_tier_keyspace_mismatch`
- `fjall_open_rejects_cross_tier_duplicate_ids`

**Historical formal evidence**

FV-3 reported persisted-record metadata validity as part of its Kani
coverage.

The current harness `kani_persisted_record_metadata` is under FV-4b
remediation because architectural review requires the proof to traverse the
actual persisted/open validation path rather than a tautological predicate.

**Evidence**

- `verification/evidence/FV-3-STORAGE-INVARIANTS.md`

**Status**

`HISTORICAL / REMEDIATION`

The FV-3 evidence document originally reported 6 harnesses and 194 checks.
Independent historical re-audit under `LIMIT-006` reproduced all 6 harnesses
and established that `194 checks / 4 unreachable` was the summary of the final
owner-nonempty harness, not an aggregate count for all 6 harnesses.

The reproduced per-harness summaries have an arithmetic sum of 645 checks,
0 failures, and 13 unreachable checks. Kani did not emit an aggregate check
count for the combined run.

## FV-4 — Audit Integrity

### CLAIM-FV4-001 — Audit entries are self-sealed and linked

**Property**

Each audit entry contains a deterministic `entry_hash`, commits to its
predecessor through `prev_hash`, and the first entry references the zero
hash.

Modification of sealed content, `prev_hash`, or `entry_hash` invalidates the
corresponding chain verification condition.

**Production boundary**

- `AuditEntry::audit_hash_input`
- `AuditEntry::calculate_hash`
- `AuditEntry::verify_hash`
- `Store::verify_audit_chain`

**Behavioral evidence**

- `redb_load_rejects_broken_audit_chain`
- `redb_save_rejects_tampered_audit_chain`
- `fjall_open_rejects_broken_audit_chain`
- `fjall_open_rejects_tampered_final_audit_entry`
- `audit_hash_known_answer_v1`

**Evidence**

- `verification/evidence/FV-4-AUDIT-INTEGRITY.md`

**Status**

`HISTORICAL / REMEDIATION`

The original FV-4 formal audit-link harness was later found insufficiently
connected to the production chain path. FV-4b replaces that proof evidence
with production-path harnesses and an explicitly documented cryptographic
assumption boundary.

### CLAIM-FV4-002 — Persisted audit structure fails closed

**Property**

Persisted Redb and Fjall audit state rejects malformed entries, broken
chains, noncanonical keys, and sequence gaps before becoming usable.

Redb additionally removes stale audit rows when rewriting the chain and
refuses to save an invalid in-memory audit chain.

**Behavioral tests**

- `redb_load_rejects_malformed_audit_entry`
- `redb_load_rejects_broken_audit_chain`
- `redb_save_rejects_tampered_audit_chain`
- `redb_save_removes_stale_audit_rows`
- `redb_save_uses_canonical_audit_keys`
- `redb_load_rejects_noncanonical_audit_key`
- `fjall_open_rejects_malformed_audit_entry`
- `fjall_open_rejects_broken_audit_chain`
- `fjall_open_rejects_noncanonical_audit_key`
- `fjall_open_rejects_audit_sequence_gap`

**Evidence**

- `verification/evidence/FV-4-AUDIT-INTEGRITY.md`

**Status**

`HISTORICAL / CURRENT BEHAVIORAL`

### CLAIM-FV4-003 — Final-entry modification detection

**Corrected property**

Modification of a final sealed audit entry is detected because its stored
`entry_hash` no longer matches the digest recomputed from its content and
`prev_hash`.

Removal of the final entry is a different property and was not detected by
the pre-FV-4b verifier.

**Evidence**

- `verification/evidence/FV-4-AUDIT-INTEGRITY.md`
- ERRATUM #1

**Status**

`HISTORICAL / CORRECTED`

The original FV-4 claim remains historically narrowed to final-entry
modification detection.

FV-4b now remediates final-entry removal for the local persisted-storage
model through an expected-count/expected-head checkpoint plus Redb lineage
continuity enforcement.

See `LIMIT-001`.

### CLAIM-FV4-004 — ARPi audit-tail-aware construction

**Corrected property**

The server-side ARPi API contains an audit-aware header-construction path
that accepts the sealed audit-chain tail, and that API-level path is covered
by tests.

This claim does not establish that deployed production responses currently
carry an external audit-chain anchor.

**Evidence**

- `verification/evidence/FV-4-AUDIT-INTEGRITY.md`
- ERRATUM #2

**Status**

`LIMITED / REMEDIATION`

See `LIMIT-002` and related deployment limitations.

## FV-4b — Current Remediation Work

### CLAIM-FV4B-001 — Bounded audit tamper detection

**Target property**

Within the declared FV-4b bounded audit domain, a supported single-bit
mutation of timestamp or `prev_hash` changes the verification digest.

Cross-entry separation is carried structurally by pairwise-distinct concrete
record identities.

**Serialization boundary**

Every proof preimage must originate exclusively from production
`AuditEntry::audit_hash_input()`.

No harness-side reconstruction of the canonical serialization is permitted.

**Cryptographic boundary**

The production SHA-256 implementation is not re-proved by Kani.

Current methodology separates:

1. production SHA-256 known-answer testing;
2. a verification-only bounded digest model for chain-logic proofs;
3. explicit trusted assumptions for cryptographic primitive correctness and
   collision resistance;
4. randomized real-SHA testing where bounded model checking is not tractable.

**Current assurance status**

`DYNAMIC PASS / FORMAL INCONCLUSIVE`

The production SHA-256 path passed randomized tamper validation using
`AuditEntry::new()` without reproducing canonical serialization or hashing in
the test harness.

The locked validation executed:

- 4,096 randomized timestamp single-bit mutations;
- 4,096 randomized `prev_hash` single-bit mutations;
- 4,096 randomized distinct-record identity cases;
- 12,288 randomized production-SHA trials total;
- 3 property tests passed, 0 failed.

This is dynamic cryptographic-path evidence. It is not a formal proof of
SHA-256 collision resistance or injectivity.

**Current Kani status**

`INCONCLUSIVE — VERIFIER RESOURCE CEILING`

The following tractability attempts are retained as evidence and are not
counted as successful proofs:

- real production SHA-256 under Kani: resource/time ceiling;
- looped syndrome model: resource/time ceiling;
- linear syndrome with variable-length byte equality: kernel OOM;
- linear syndrome with fixed `[u8; 84]` equality: kernel OOM;
- forward single-bit tamper model: kernel OOM during propositional reduction;
- structural cross-entry identity-separation model: memory-cgroup OOM.

The forward tamper and cross-entry Kani obligations therefore remain formally
inconclusive. Production SHA-256 behavior for the bounded timestamp,
`prev_hash`, and distinct-record identity properties is covered by dynamic
property testing under the standing cryptographic assumptions.

The successful commit-bound six-harness FV-4b Kani gate reports an arithmetic total of `938 checks / 0 failed / 13 unreachable` against reviewed source commit `5c63ac45289e876eb563f1752eb796a19b553534`.

### CLAIM-FV4B-002 — Production Critical policy precheck

**Property**

The production policy precheck enforces the owner/Critical boundary before
delegation and explicit policy-rule processing.

Its complete decision relation is:

- owner on any tier -> `PermitOwner`;
- non-owner on Critical -> `DenyCritical`;
- non-owner on Personal or Noise -> `Continue`.

For Critical data, therefore:

    requester is owner     -> PermitOwner
    requester is non-owner -> DenyCritical

Downstream role, action, delegation-expiry, explicit-allow, and explicit-deny
configuration cannot change this precheck result because those inputs are not
accepted by the precheck and are evaluated only after it returns `Continue`.

**Production boundary**

- `src/policy.rs`
- `PolicyPrecheck`
- `policy_precheck`
- `PolicyEngine::evaluate`

`PolicyEngine::evaluate` invokes `policy_precheck(subject == owner_id, tier)`
before explicit deny rules, delegation roles, explicit allow rules, and default
deny processing.

**Direct-engine verification attempt**

A Kani harness first attempted the Critical property through the concrete
`PolicyEngine::evaluate` path.

That attempt is classified:

`INCONCLUSIVE — VERIFIER/LIBRARY OBSTRUCTION`

The concrete `HashMap` path reached `getrandom` and SipHash/`RandomState`
implementation machinery and reached the five-minute verification timeout.
This is not a policy counterexample and is not counted as a successful proof.

Raw evidence:

`verification/evidence/raw/fv4b/policy-real-engine-getrandom-timeout.log`

SHA-256:

`70a3e8a45d3fe2c7940b871df7f245a45e4159409a59aeba2c61a7dcfe775d88`

**Formal harness**

- `kani_policy_tier_ceiling`

The current harness targets the production `policy_precheck` decision core.

**Formal result**

`FORMAL PASS`

Kani 0.67.0 with CBMC 6.8.0 reported:

- `0 of 23 failed`;
- `VERIFICATION:- SUCCESSFUL`;
- `1 successfully verified harnesses, 0 failures, 1 total`;
- exit status `0`;
- no `getrandom`, SipHash, or `RandomState` path in the successful proof.

Raw evidence:

`verification/evidence/raw/fv4b/policy-precheck-production-pass.log`

SHA-256:

`e18863d0530cce2f38b0dc3a965e1c0ace815830188b7370655256d56573e89b`

**Status**

`CURRENT / FORMAL PASS`

**Scope**

This formal result proves the production `policy_precheck` decision relation
used by `PolicyEngine::evaluate`.

It does not claim that the complete HashMap-backed delegation and rule engine
has been formally verified. Existing behavioral policy tests remain composition
evidence for the surrounding `PolicyEngine::evaluate` behavior.

### CLAIM-FV4B-003 — Persisted audit checkpoint and lineage continuity

**Property**

For the local persisted-storage model, an existing audit history cannot be
silently shortened, replaced by an unrelated history, or overwritten by a
stale/divergent `Store::save()` candidate through the verified Redb save
boundary.

Redb and Fjall persist an audit checkpoint containing the expected audit-entry
count and expected terminal entry hash.

Redb additionally requires the already-persisted audit sequence to be an exact
prefix of the candidate in-memory sequence before rewriting persisted state.

**Formal evidence**

`kani_audit_chain_tail_drop_checkpoint_rejected` exercises the production
`validate_audit_checkpoint()` path and establishes that a one-entry count
reduction is rejected while the expected checkpoint count remains unchanged.

Raw evidence:

`verification/evidence/raw/fv4b-kani-tail-drop-checkpoint-rejected.log`

SHA-256:

`ec944943addc3e7eedb7a8bf49c9704736df75efc0aaaba7d1eab82faa6387e1`

**Dynamic evidence**

- FV-4b checkpoint integration suite: 22 tests passed;
- Redb unrelated-history replacement rejected;
- same-lineage resave and extension accepted;
- stale snapshot overwrite rejected;
- divergent stale writer rejected;
- current-tree all-target regression passed with zero failed tests.

Archived logs:

- `verification/evidence/raw/fv4b-current-tree-all-targets.log`
- `verification/evidence/raw/fv4b-redb-lineage-gate.log`
- `verification/evidence/raw/fv4b-stale-writer-lineage.log`

SHA-256:

- `93235066b36cfab57506b6787712a4bb6fd636f0b20522a9a067691b3a6e425b`
- `0b128af2b527f83ce460d0ce911b6dc46e8ef6b81eaacf27cb7054a0ff1bd505`
- `4078b6de649dec6ec425f5852b00f4eb785a2f2ee85280bbe865c433a1cebb42`

**Assurance status**

`FORMAL PASS — CHECKPOINT COUNT-MISMATCH PROPERTY`

`DYNAMIC PASS — PERSISTENCE AND LINEAGE COMPOSITION`

**Scope**

This claim applies to the local Redb/Fjall persistence and normal API model.

It does not establish protection against an attacker capable of coherently
rewriting the entire audit history and checkpoint. Authentication of the
checkpoint remains deferred to FV-5.

The original intermediate local logs are retained as development evidence. Final commit-bound local and CI evidence is now archived under `verification/evidence/raw/fv4b/final-5c63ac45289e/` and is bound to reviewed source commit `5c63ac45289e876eb563f1752eb796a19b553534`.

## FV-5 — Encryption and Secret Boundaries

### CLAIM-FV5-001 — Persisted reconstruction authority

**Status:** `COMMIT-BOUND VERIFICATION PASS`

FV-5 P1b removes public Serde reconstruction authority from `Record` and
routes persisted record decoding through a crate-private validated
reconstruction boundary.

Verified source commit:

`354e1289dda9ff3bc15f41afc0242d7a8c5731a3`

Commit-bound R5 evidence records:

- `263 passed / 0 failed / 0 ignored` dynamic tests;
- `7` Kani harnesses;
- `852` Kani checks;
- `0` failed Kani checks;
- `10` unreachable Kani checks;
- passing external `Record` deserialization compile-fail enforcement.

The two persisted-record Kani runs contain retained unsupported-construct
notices. Their raw logs remain archived and the notices are explicitly
disclosed; they are not interpreted as proof of unsupported behavior.

Evidence:

`verification/evidence/FV-5-P1B-PERSISTENCE-BOUNDARY.md`

Raw evidence:

`verification/evidence/raw/fv5/p1b-354e1289dda9-r5/`

`LIMIT-011` is closed for the P1b reconstruction scope. `LIMIT-009`,
`LIMIT-012`, and `LIMIT-013` remain open. `LIMIT-010` has source-level
remediation from P1a but remains part of the wider FV-5 phase accounting.


### CLAIM-FV5-002 — Versioned encrypted payload persistence boundary

**Status:** `COMMIT-BOUND TARGETED VERIFICATION PASS`

**Full Kani status:** `BASELINE-CONSTRAINED / RESOURCE EXHAUSTION / NOT GREEN`

FV-5 P1c-B completes the production persistence migration to the
versioned `EncryptedPayload` boundary introduced in P1c-A.

Verified source commit:

`eace7cc86c354481c100ccf88b8f5d4bda33d898`

Commit-bound evidence records:

- `271 passed / 0 failed / 0 ignored` dynamic tests across `15` targets;
- baseline-aware Clippy with `23` baseline diagnostics, `23` current
  diagnostics, and `0` new diagnostics;
- `3` targeted Kani harnesses;
- `1514` targeted Kani checks;
- `0` failed targeted Kani checks;
- `21` unreachable targeted Kani checks;
- persisted fail-closed rejection of unmarked legacy payloads;
- persisted fail-closed rejection of unknown payload versions;
- persisted fail-closed rejection of truncated current envelopes;
- successful reconstruction of a structurally valid current-version
  persisted envelope.

The complete Kani suite is not represented as green. Audit-related
harnesses encounter a reproduced P1c-A baseline CBMC resource ceiling.
The archived baseline attempt contains an explicit out-of-memory
diagnostic and no observed assertion `Status: FAILURE`.

The named audit verification/digest/hash boundary diff between P1c-A and
P1c-B is empty.

Kani unsupported-construct notices are retained and disclosed.

This claim does not formally verify AES-GCM. Structural encrypted-envelope
validity is not equivalent to cryptographic authenticity.

Unmarked legacy payloads are not silently adopted or automatically
migrated.

Evidence:

`verification/evidence/FV-5-P1C-B-PAYLOAD-ENVELOPE.md`

Raw evidence:

`verification/evidence/raw/fv5/p1c-b-eace7cc86c35-r1/`

`LIMIT-009`, `LIMIT-012`, and `LIMIT-013` remain open. `LIMIT-010`
remains source-remediated with wider FV-5 phase closure pending.

### CLAIM-FV5-003 — AAD metadata authority boundary

**Status:** `COMMIT-BOUND TARGETED VERIFICATION PASS`

**Full Kani status:** `NOT RERUN / PREVIOUSLY CHARACTERIZED RESOURCE CEILING REMAINS`

FV-5 P2 hardens authority over the existing record ID and tier AES-GCM
associated-data boundary.

Verified source commit:

`6793c15c77b07c8f8cdbb51934bf4be1eee5e883`

Commit-bound evidence records:

- `273 passed / 0 failed / 0 ignored` dynamic tests across `16` test-result
  summaries;
- passing compile-fail enforcement preventing external mutation of
  `Record.id` and `Record.tier`;
- baseline-aware Clippy with `23` baseline diagnostics, `23` current
  diagnostics, and `0` new diagnostics;
- `1` targeted Kani harness;
- `500` targeted Kani checks;
- `0` failed targeted Kani checks;
- `7` unreachable targeted Kani checks;
- successful preservation of selected record ID and tier through the modeled
  production construction seam;
- dynamic authenticated-decryption failure when either ID or tier context is
  substituted.

The public `Record::new` constructor now owns encryption of plaintext using
the same ID and tier stored in the record. External callers cannot supply
ciphertext independently from those metadata values through that public
construction seam.

Kani unsupported-construct notices are retained and disclosed.

This claim does not formally verify AES-GCM. The targeted Kani proof covers
metadata preservation through the named construction seam; the cryptographic
AAD mismatch behavior is supported by dynamic regression tests.

The complete Kani suite was not rerun for P2. The previously documented
audit-related verifier resource ceiling remains classified as a tool/resource
constraint rather than a property failure.

Evidence:

`verification/evidence/FV-5-P2-AAD-METADATA-AUTHORITY.md`

Raw evidence:

`verification/evidence/raw/fv5/p2-6793c15c77b0-r1/`

`LIMIT-009`, `LIMIT-012`, and `LIMIT-013` remain open. `LIMIT-010` remains
source-remediated with wider FV-5 phase closure pending.

### CLAIM-FV5-004 — Mobile write-counter monotonicity boundary

**Status:** `COMMIT-BOUND TARGETED VERIFICATION PASS`

**Full Kani status:** `NOT RERUN / PREVIOUSLY CHARACTERIZED RESOURCE CEILING REMAINS`

FV-5 P3 hardens mobile write-counter state validation and the arithmetic
monotonic transition boundary.

Verified source commit:

`d041b9ffe45e20849d6afbbdcd01b3a4954f9c89`

Commit-bound evidence records:

- `273 passed / 0 failed / 0 ignored` default dynamic tests;
- `84 passed / 0 failed / 0 ignored` mobile-library dynamic tests;
- fail-closed rejection of malformed persisted counter state;
- propagated Fjall counter-read errors rather than silent reset to zero;
- counter recovery across reopen followed by continued monotonic advance;
- rejection of `u64::MAX` exhaustion without wraparound or record write;
- baseline-aware default Clippy with `10` baseline diagnostics, `10` current
  diagnostics, and `0` new diagnostics;
- baseline-aware mobile Clippy with `21` baseline diagnostics, `21` current
  diagnostics, and `0` new diagnostics;
- `1` targeted Kani harness;
- `38` targeted Kani checks;
- `0` failed targeted Kani checks;
- successful proof that the production counter transition advances by exactly
  one for every non-exhausted `u64` value and rejects the exhausted value.

The targeted formal result is limited to the arithmetic transition. It does
not prove persistence atomicity, crash consistency, replay protection,
anti-rollback behavior, deployed mobile provenance enforcement, or Fjall
internals.

`LIMIT-005` remains open. P3 records the required FV-5 source-level witness:
mobile record persistence and write-counter persistence remain separate
operations. Crash-consistent atomic remediation remains assigned to FV-6.

`LIMIT-004` also remains open and assigned to FV-5; P3 does not claim deployed
mobile provenance/content enforcement.

Evidence:

`verification/evidence/FV-5-P3-MOBILE-COUNTER-MONOTONICITY.md`

Raw evidence:

`verification/evidence/raw/fv5/p3-d041b9ffe45e-r1/`


### CLAIM-FV5-005 — Authenticated audit checkpoint sealing boundary

**Status:** `COMMIT-BOUND TARGETED VERIFICATION PASS`

**Full Kani status:** `NOT RERUN / PREVIOUSLY CHARACTERIZED RESOURCE CEILING REMAINS`

FV-5 P3.5 adds a keyed authenticated audit-checkpoint mode over the local
expected audit-entry count and expected terminal audit hash.

Verified source commit:

`f5e14886304dc57895d7f988e56883a9b394e189`

Commit-bound evidence records:

- `297 passed / 0 failed / 0 ignored`
  aggregate default dynamic tests;
- `105 passed / 0 failed / 0 ignored`
  mobile-library tests;
- `23` focused P3.5 dynamic passes;
- authenticated Redb and Fjall open/save persistence;
- authenticated Fjall write, granted-read, denied-read, and delete checkpoint
  persistence;
- strict rejection of authenticated checkpoints by the legacy parser;
- strict rejection of nonempty legacy checkpoints by authenticated open;
- fail-closed wrong-store-secret behavior;
- multi-owner operation with distinct owner passwords and one shared
  database-global store secret;
- preserved non-owner Critical access denial;
- required `EDISONDB_STORE_SECRET` server startup authority;
- baseline-aware default Clippy with
  `23` baseline diagnostics,
  `23` current diagnostics, and
  `0` new diagnostics;
- baseline-aware mobile Clippy with
  `29` baseline diagnostics,
  `29` current diagnostics, and
  `0` new diagnostics;
- `1` targeted Kani harness;
- `381` targeted Kani checks;
- `0` failed targeted Kani checks;
- `7` unreachable targeted Kani checks.

The targeted Kani harness proves only the canonical checkpoint MAC-input byte
layout:

`domain || big-endian expected_count || expected_head`

It does not prove BLAKE3, Argon2, MAC unforgeability, cryptographic strength,
constant-time execution, OS secret handling, or anti-rollback behavior.

The authenticated checkpoint authority is distinct from the per-owner record
password. Possession of `store_secret` does not bypass Critical/Personal
record authorization or provide the owner password required for payload
decryption.

Authenticated mode does not silently migrate or adopt a nonempty legacy
checkpoint.

Legacy construction APIs remain available for compatibility and are outside
this authenticated-checkpoint claim. The P3.5 production server path requires
the authenticated store-secret authority and does not silently fall back to
legacy mode.

The checkpoint authenticates local audit continuity against a holder of the
store secret but does not provide a monotonic external freshness anchor.
Replay of an older complete, internally valid authenticated state is not
claimed to be detected.

Total destruction or replacement of all Edison-owned local state remains the
separate `LIMIT-008` trust boundary.

Evidence:

`verification/evidence/FV-5-P3.5-AUTHENTICATED-AUDIT-CHECKPOINT.md`

Raw evidence:

`verification/evidence/raw/fv5/p35-f5e14886304d-r1/`

At the P3.5 verified source boundary, `LIMIT-004`, `LIMIT-005`, and
`LIMIT-012` remained open within their documented boundaries. `LIMIT-004` is
subsequently closed by `CLAIM-FV5-006`; `LIMIT-005` and `LIMIT-012` remain
open.


### CLAIM-FV5-006 — Mobile fail-closed provenance validation boundary

**Status:** `COMMIT-BOUND TARGETED VERIFICATION PASS`

**Physical Android runtime:** `PASS — PRODUCTION JNI/RUST PATH EXERCISED`

**Full Kani status:** `NOT RERUN / PREVIOUSLY CHARACTERIZED RESOURCE CEILING REMAINS`

FV-5 LIMIT-004 hardens and verifies the bounded mobile write-provenance
validation boundary.

Verified final source commit:

`bc60c1da158466c90ce2c0dd96e60e3e7c7f71b3`

Initial production-remediation commit:

`2f3c8fca6860e9f97e79e799a9e8050de38012e0`

Commit-bound evidence records:

- `296 passed / 0 failed / 0 ignored` aggregate default dynamic tests across
  `17` test-result summaries;
- `106 passed / 0 failed / 0 ignored` mobile-library tests;
- `5 passed / 0 failed / 0 ignored` focused LIMIT-004 integration tests;
- `1 passed / 0 failed / 0 ignored` rejected-provenance state-invariance
  regression;
- successful default and mobile Cargo checks;
- baseline-aware default Clippy with `23` baseline diagnostics, `23` current
  diagnostics, and `0` new diagnostics;
- baseline-aware server-plus-mobile test-surface Clippy with `60` baseline
  diagnostics, `60` current diagnostics, and `0` new diagnostics;
- `1` targeted Kani harness;
- `158` targeted Kani checks;
- `0` failed targeted Kani checks;
- `4` unreachable targeted Kani checks;
- parser structural fail-closed enforcement for exact 78-byte length, `ARPi`
  magic, tier range, and zero reserved bytes;
- dynamic rejection of mismatched BLAKE3 content provenance before the
  monotonic counter transition;
- regression evidence that rejected mismatched provenance does not advance or
  persist the mobile counter in the exercised path;
- Android API-26 cross-builds for `arm64-v8a` and `x86_64`;
- exported production `nativeBlake3` and `nativeInsert` JNI symbols on both
  Android artifacts;
- physical Android 11 / API-30 / `arm64-v8a` execution of the production
  JNI/Rust path;
- physical-runtime rejection of mismatched content, invalid tier, nonzero
  reserved bytes, and both 77-byte and 79-byte JNI headers;
- successful valid write after the physical-runtime rejection cases.

The targeted Kani result proves only the deterministic structural parser
acceptance relation. It does not formally verify BLAKE3 or any other
cryptographic primitive.

The physical Android result exercises a temporary Java harness against the
production EdisonDB JNI exports. It does not establish full production Kotlin
application execution or formally verify JNI, JVM, Android, Java, or Kotlin.

The direct C FFI remains an exactly-78-byte caller pointer contract; arbitrary
C-caller length validation is not claimed.

This claim does not establish crash consistency, replay resistance,
anti-rollback, timestamp freshness, node-id authenticity, verified-kernel
integration, or complete production ARPi integration.

Evidence:

`verification/evidence/FV-5-LIMIT-004-MOBILE-PROVENANCE.md`

Raw passing evidence:

`verification/evidence/raw/fv5/limit004-bc60c1da1584-r2/`

Preserved failed-methodology evidence:

`verification/evidence/raw/fv5/limit004-2f3c8fca6860-r1/`

`LIMIT-004` is closed for this bounded provenance-validation scope.
`LIMIT-002`, `LIMIT-003`, and `LIMIT-005` remain open within their separately
documented boundaries.


### CLAIM-FV5-007 — Persisted `created_at` authenticated-checkpoint boundary

**Status:** `COMMIT-BOUND TARGETED VERIFICATION PASS`

FV-5 LIMIT-012 authenticates the persisted association between record identity
and nonzero `created_at` metadata in authenticated checkpoint version 2.

Verified source commit:

`e1cb11dcbcfb0913ce4f61c8c00be019527fb1fa`

Commit-bound evidence records:

- default and mobile Cargo checks: `PASS`;
- aggregate default dynamic tests:
  `301 passed / 0 failed / 0 ignored`;
- aggregate mobile dynamic tests:
  `311 passed / 0 failed / 0 ignored`;
- focused core LIMIT-012 regressions: `2 passed / 0 failed`;
- focused Redb/Fjall tamper regressions: `2 passed / 0 failed`;
- baseline/current Clippy diagnostics: `36 / 36`;
- new Clippy diagnostics: `0`;
- targeted Kani: `395` checks, `0` failed,
  `7` unreachable, `1` verified harness.

Authenticated checkpoint v2 binds a deterministic commitment over current
record `id -> created_at` state into the checkpoint MAC input. Record state is
canonicalized independently of backend iteration order.

Authenticated Redb and Fjall reopen fail closed when a persisted nonzero
`created_at` value is modified without corresponding authenticated checkpoint
authority.

Authenticated checkpoint-v1 shape is rejected rather than silently migrated
or upgraded into version 2.

The targeted Kani harness proves only structural checkpoint MAC-input layout.
It does not formally prove BLAKE3 or other cryptographic primitives.

This claim does not establish wall-clock correctness, timestamp freshness,
external anti-rollback, metadata confidentiality, or detection of replay of
an older complete internally valid authenticated state.

Evidence:

`verification/evidence/FV-5-LIMIT-012-CREATED-AT-AUTHENTICITY.md`

Raw evidence:

`verification/evidence/raw/fv5/limit012-e1cb11dcbcfb-r1/`

`LIMIT-012` is closed for this bounded authenticated persisted-`created_at`
authenticity scope. `LIMIT-008`, `LIMIT-009`, `LIMIT-013`, and other separately
registered boundaries remain governed by their own claims and limitations.


### FV-5 phase closure — Encryption and Secret Boundaries

**Status:** `COMMIT-BOUND PHASE ACCOUNTING COMPLETE`

Final reviewed FV-5 head before the phase-closure record:

`aff67ac84012e32f1bbfd4d4976e176d1d0241e2`

FV-5 records seven bounded claims, `CLAIM-FV5-001` through
`CLAIM-FV5-007`.

Final phase accounting confirms:

- `LIMIT-010` source remediation remains effective in the final FV-5 tree and
  is closed for the bounded public record-salt mutation authority;
- `LIMIT-005` has completed its required FV-5 witness, with crash-consistent
  remediation assigned to FV-6;
- `LIMIT-002` and `LIMIT-003` remain assigned to FV-7;
- `LIMIT-008` remains an explicit trust boundary;
- `LIMIT-009` remains an explicit metadata-confidentiality nonclaim;
- `LIMIT-013` remains a separate local-clock anomaly boundary.

FV-5 phase closure does not claim complete formal verification, crash
consistency, external anti-rollback, timestamp freshness, general metadata
confidentiality, verified-kernel integration, or complete ARPi production
integration.

Evidence:

`verification/evidence/FV-5-PHASE-CLOSURE.md`

Raw evidence:

`verification/evidence/raw/fv5/phase-closure-aff67ac84012-r1/`


## Registered Limitations

#### FV-4b commit-bound closure

**Status:** `SOURCE-BOUND VERIFICATION COMPLETE`

The reviewed FV-4b production source is bound to commit
`5c63ac45289e876eb563f1752eb796a19b553534`.

Independent GitHub Actions workflow run `32210859833` executed
`EdisonDB Kani Verification` through `workflow_dispatch` against that exact
source commit and completed successfully.

Pinned verification toolchain:

- Kani `0.67.0`;
- CBMC `6.8.0`;
- Rust `1.97.0`.

The six mandatory commit-bound harnesses completed successfully:

1. `kani_owner_nonempty_invariant`;
2. `kani_policy_tier_ceiling`;
3. `kani_record_identity_validation`;
4. `kani_storage_id_immutability`;
5. `kani_audit_chain_tail_drop_checkpoint_rejected`;
6. `kani_persisted_record_metadata`.

The arithmetic sum of their individual Kani reports is:

- `938` checks;
- `0` failed;
- `13` unreachable.

This is an arithmetic sum of the six selected harness reports, not a claim that
every FV-4b experiment or every EdisonDB property is formally verified.
In particular, the production-SHA bounded proof attempts recorded as
`INCONCLUSIVE` remain inconclusive, and the formal policy result remains scoped
to the production `policy_precheck` decision core rather than the complete
HashMap-backed `PolicyEngine`.

Commit-bound CI and local evidence is archived under:

`verification/evidence/raw/fv4b/final-5c63ac45289e/`

The evidence manifest is:

`verification/evidence/raw/fv4b/final-5c63ac45289e/SHA256SUMS.txt`

`LIMIT-001` local tail-truncation remediation is therefore commit-bound for
FV-4b. Authenticated checkpoint sealing remains assigned to FV-5, and
`LIMIT-008` remains an explicit trust boundary.

### LIMIT-001 — Audit-tail truncation

The pre-FV-4b audit-chain verifier accepted a valid prefix after removal of
the final audit entry because the chain alone carried no independently
persisted expected entry count or expected terminal hash.

**FV-4b local remediation**

The local persisted-storage model enforces:

- an audit checkpoint containing expected entry count and terminal hash;
- checkpoint validation on Redb and Fjall open paths;
- atomic audit/checkpoint persistence for Fjall mutations;
- checkpoint persistence in the Redb write transaction;
- rejection of final-row deletion when the checkpoint remains intact;
- private `Store` record and audit collections;
- Redb persisted-history prefix enforcement before `Store::save()` rewrites;
- rejection of unrelated history replacement;
- rejection of stale-snapshot overwrite;
- rejection of divergent stale-writer history.

The checkpoint tail-drop count mismatch is covered by a successful production
checkpoint-validation Kani harness. Storage and lineage composition are also
covered dynamically.

**FV-5 P3.5 authenticated sealing**

Source commit `f5e14886304dc57895d7f988e56883a9b394e189` adds an authenticated checkpoint mode whose
expected count and expected terminal hash are sealed under a key derived from
a distinct database-global `store_secret`.

Authenticated open fails closed on:

- wrong store secret;
- MAC tampering;
- count or head tampering;
- salt tampering;
- unsupported checkpoint version;
- nonempty legacy checkpoint state.

Legacy parsing also rejects the authenticated representation rather than
silently accepting it as the older checkpoint type.

The store checkpoint authority is separate from owner record passwords and
does not bypass record authorization.

**Local remediation status:** `REMEDIATED / CURRENT`

For authenticated mode, an attacker who modifies local audit history cannot
simply recompute a matching checkpoint without the external store authority.

This status does not claim:

- global anti-rollback protection;
- freshness against replay of an older complete valid authenticated state;
- protection after compromise of `store_secret`;
- protection against total destruction or replacement of all Edison-owned
  local state;
- formal verification of BLAKE3 or Argon2.

Legacy compatibility APIs remain outside the P3.5 authenticated-sealing
claim.

Total Edison-owned local-state destruction/replacement remains recorded
separately under `LIMIT-008`.

**Assigned phases:** local truncation and re-anchoring remediation completed
in FV-4b; authenticated checkpoint sealing completed for authenticated mode
in FV-5 P3.5.

### LIMIT-002 — ARPi production integration

The audit-tail-aware server ARPi construction path is verified at API level
but is not currently wired into a production response path.

**Assigned phase:** FV-7.

### LIMIT-003 — Mobile verified-kernel bypass

The mobile database path does not currently route through the same verified
storage and policy chokepoint as the core Store path.

**Assigned phase:** FV-7.

### LIMIT-004 — Mobile fail-closed provenance validation

**Status:** `CLOSED — FV-5 / CLAIM-FV5-006`

The bounded mobile provenance-validation property is closed by commit-bound
FV-5 evidence at:

`bc60c1da158466c90ce2c0dd96e60e3e7c7f71b3`

The verified boundary includes:

- exact 78-byte mobile ARPi structural validation;
- fail-closed `ARPi` magic, tier, and reserved-byte validation;
- BLAKE3 content recomputation with mismatch rejection;
- rejection before local monotonic-counter advancement;
- regression evidence that rejected mismatched provenance does not advance or
  persist the counter in the exercised path;
- exact-length enforcement at the Android JNI insertion boundary;
- Android API-26 `arm64-v8a` and `x86_64` cross-build evidence;
- physical Android execution of the production JNI/Rust provenance path.

Closure is limited to `CLAIM-FV5-006`.

It does not claim formal verification of BLAKE3, JNI/JVM/Android/Kotlin/Java,
full Kotlin application deployment, arbitrary direct-C caller length
validation, crash consistency, anti-rollback, timestamp freshness, node-id
authenticity, `LIMIT-002`, `LIMIT-003`, or `LIMIT-005`.

**Assigned phase:** FV-5.

**Closed by:** `CLAIM-FV5-006`.

### LIMIT-005 — Mobile counter crash consistency

Mobile record persistence and write-counter persistence are not yet
demonstrated to be one atomic crash-consistent transition.

**Assigned phases:** FV-5 witness, FV-6 remediation.

### LIMIT-006 — Historical Kani check-count integrity

**Status:** `RESOLVED / CORRECTED`

FV-2, FV-3, and FV-4 evidence documents originally reported `194`
verification checks despite changing harness sets.

Independent historical re-audit reproduced the exact source commits with
Kani 0.67.0 and CBMC 6.8.0:

- FV-2 source commit:
  `feea60da7e70982945cf16e178d55f91c6f5e9f0`
- FV-3 source commit:
  `412977e7abb6e6647ce9c819ef89c21a825ebc74`
- FV-4 source commit:
  `5885efbdf1f4b186c68962ccb78c5dc793d78678`

The combined runs verified every harness with zero failures but did not emit
one aggregate verification-check count. In each phase, the historical
`194 checks / 4 unreachable` value was the summary of the final
`kani_owner_nonempty_invariant` harness immediately preceding Kani's separate
overall harness-completion summary.

Reproduced per-harness arithmetic totals are therefore:

- FV-2: 3 harnesses; 438 checks; 0 failures; 9 unreachable.
- FV-3: 6 harnesses; 645 checks; 0 failures; 13 unreachable.
- FV-4: 7 harnesses; 646 checks; 0 failures; 13 unreachable.

These totals are arithmetic sums of the individual Kani harness summaries.
They are not represented as Kani-emitted aggregate check counts.

Combined raw evidence:

- `verification/evidence/raw/fv2-historical-all-harnesses.log`
  SHA-256:
  `a1029daac86d6131e0a259c0ff9cc883fd7cab9bad3a754b00ada2f7574c8366`
- `verification/evidence/raw/fv3-historical-all-harnesses.log`
  SHA-256:
  `787fe78d31bd53afea95edb49ca537bbf300ed3c63188635a58b6a2cea1e104f`
- `verification/evidence/raw/fv4-historical-all-harnesses.log`
  SHA-256:
  `b17f6dfa5c195b3eb778c4c25993d132c4f2d20e87b450657a508e75e751bc52`

The historical source trees were reproduced exactly. Their original
`Cargo.lock` SHA-256 was:

`2285d3a2b12fbf6eb4eaed728b70917c70a912d592696487d9df01243c379cea`

Cargo 1.97.0 could not replay that lock state without normalization. The
controlled dependency normalization used for all three re-audits produced:

`d7e7fc1734f63b7b7e990ccb98181856b2f7679b5849c47336a76d19defc9924`

The normalization resolved Fjall from 3.1.6 to 3.1.8 and lsm-tree from 3.1.6
to 3.1.9 within the historical semver constraints. Accordingly, these results
are exact-source historical reproductions with a documented normalized
dependency state, not byte-identical replay of the original lock state.

The original numeric wording remains part of the historical record but must
not be represented as an aggregate Kani check count.

**Resolved in:** FV-4b evidence-integrity remediation.

### LIMIT-007 — Fjall related-mutation atomicity

**Status:** `REMEDIATED / CURRENT`

Before FV-4b, related Fjall audit and data mutations were not represented as
one storage batch, leaving an implementation-level persistence-divergence
window between related writes.

FV-4b now groups the related local mutations through the Fjall batch API:

- record writes batch the audit entry, record mutation, and audit checkpoint;
- record deletes batch the audit entry, record removal, and audit checkpoint;
- read-audit persistence batches the audit entry and audit checkpoint;
- in-memory audit length and tail state advance only after successful batch
  commit.

This closes the identified separate-write implementation gap for the current
Fjall paths.

This status does not claim that power-loss durability, filesystem behavior,
device flush semantics, or every crash boundary has been formally proved.
Crash and recovery qualification remains assigned to FV-6.

**Remediated in:** FV-4b.

**Residual qualification:** FV-6 crash/power-loss and recovery testing.

### LIMIT-008 — Total Edison-owned local-state erasure

**Status:** `OPEN / TRUST-BOUNDARY`

A local instance cannot distinguish a genuinely fresh database from complete
destruction or replacement of all Edison-owned persisted state when the audit
history, checkpoint, records, and every other local Edison-owned continuity
anchor are removed together before open.

The FV-4b checkpoint and lineage controls detect partial truncation, stale
history, divergent history, and related local continuity failures while the
required persisted anchor remains available. They do not create an independent
trust anchor outside the state whose destruction is being considered.

Closing this limitation would require continuity evidence anchored outside the
simultaneously erasable Edison-owned local state. FV-4b makes no such claim.

**Status in FV-4b:** retained as an explicit residual trust boundary.

### LIMIT-009 — Persisted metadata confidentiality

Record payload protection does not conceal the existence of a record or
clear persisted metadata such as owner and tier.

**Status:** `OPEN`.

Payload confidentiality and metadata confidentiality are distinct
properties. FV-5 must not claim that encrypting payload bytes conceals
record metadata.

### LIMIT-010 — Public salt mutation boundary

The FV-5 audit identified direct public mutation authority over record
salt state.

P1a source commit
`81782052fb4ad1c73aeb51df0a72973318f4fa7c` makes the salt field private and exposes only read-only access.

Final FV-5 authority verification against
`aff67ac84012e32f1bbfd4d4976e176d1d0241e2` confirms that `Record.salt` remains private, the public accessor is
read-only, no public salt mutator or mutable salt reference is exposed, and no
direct production `.salt = ...` assignment exists.

**Status:** `CLOSED FOR FV-5 PUBLIC SALT MUTATION SCOPE`.

Evidence:

`verification/evidence/FV-5-PHASE-CLOSURE.md`

This closure is limited to the public record-salt mutation authority identified
by the FV-5 audit. It does not establish broader metadata confidentiality or
cryptographic primitive verification.

### LIMIT-011 — Persisted reconstruction validation bypass

Before P1b, persisted records could deserialize directly into public
`Record`, allowing persisted reconstruction to bypass the validated
construction boundary.

P1b source commit
`354e1289dda9ff3bc15f41afc0242d7a8c5731a3` removes `Record: Deserialize`, introduces the
crate-private persisted DTO, routes all five persisted decoding sites and
migration reconstruction through validation, and makes Fjall listing
fail closed on malformed or invalid persisted data.

Commit-bound R5 evidence records `263` passing dynamic tests and `852`
Kani checks with zero failures.

**Status:** `CLOSED FOR P1B SCOPE`.

Evidence:

`verification/evidence/FV-5-P1B-PERSISTENCE-BOUNDARY.md`

### LIMIT-012 — Persisted created_at authenticity

The original FV-5 finding was that persisted `created_at` could be modified
to another nonzero value without invalidating the authenticated checkpoint.
P1b's nonzero reconstruction rule provided structural validation but not
timestamp authenticity.

Authenticated checkpoint version 2 now binds a deterministic commitment over
the current record `id -> created_at` state into the checkpoint MAC boundary.

Verified source commit:

`e1cb11dcbcfb0913ce4f61c8c00be019527fb1fa`

Authenticated Redb and Fjall fail closed when the exercised persisted nonzero
`created_at` value is modified without corresponding authenticated checkpoint
authority.

**Status:** `CLOSED FOR FV-5 AUTHENTICATED CHECKPOINT-V2 SCOPE`.

Evidence:

`verification/evidence/FV-5-LIMIT-012-CREATED-AT-AUTHENTICITY.md`

This closure does not claim timestamp freshness, wall-clock correctness,
external anti-rollback, BLAKE3 formal verification, or general metadata
confidentiality. `LIMIT-013` remains separate.

### LIMIT-013 — Local zero-timestamp clock anomaly

`Record::new()` obtains `created_at` from the local system clock. The
current clock helper can fall back to zero on a pre-Unix-epoch or clock
duration anomaly.

P1b intentionally preserves a stricter reconstruction rule: persisted
`created_at == 0` is rejected. Therefore an in-process record created
during such a clock anomaly may be persistable but fail reconstruction
after reopen.

The reconstruction rule must not be weakened merely to hide this
distinction.

**Status:** `OPEN`.

## Standing Assumptions

Unless a narrower claim states otherwise:

- cryptographic primitive implementations are trusted dependencies unless
  separately verified;
- collision resistance is a cryptographic assumption, not established by
  bounded model checking;
- software and hardware cryptographic backend equivalence is trusted unless
  separately demonstrated;
- authenticated ownership inputs are assumed to accurately represent the
  authenticated requester at policy entry;
- claims apply only to the named production boundary and do not imply
  verification of every source file or third-party dependency.

## Registry Maintenance Rules

1. Every new assurance claim receives a stable `CLAIM-*` identifier.
2. Every known unresolved assurance gap receives a stable `LIMIT-*`
   identifier.
3. Claims map to actual production boundaries, harnesses, tests, and evidence.
4. A proof about scaffolding alone cannot silently substitute for a production
   property.
5. Historical evidence remains historical; later work may narrow or correct
   its interpretation but does not rewrite the original result.
6. Current verification counts are reported from actual completed harness
   runs only.
7. Inconclusive verifier runs are retained and labeled as inconclusive.
8. Tool or resource ceilings are not reported as property failures.
9. Assumptions and explicit limitations are part of the assurance claim.
10. Public assurance wording must not exceed what this registry supports.
