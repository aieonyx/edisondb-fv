# FV-5 LIMIT-012 — Persisted `created_at` Authenticity

## Status

`COMMIT-BOUND TARGETED VERIFICATION PASS`

Verified source commit:

`e1cb11dcbcfb0913ce4f61c8c00be019527fb1fa`

Source parent:

`3f7d80740c9ec08ade42ae497a3d2c7d4d43d734`

Raw evidence:

`verification/evidence/raw/fv5/limit012-e1cb11dcbcfb-r1/`

## Boundary

LIMIT-012 identified that a persisted nonzero `Record.created_at` value could
be modified in local storage without invalidating the authenticated audit
checkpoint.

Structural persisted-record validation already rejected
`created_at == 0`, but that did not authenticate an otherwise valid nonzero
timestamp.

This remediation extends the authenticated checkpoint format to version 2 and
binds the current persisted record `id -> created_at` state into the
database-global authenticated checkpoint.

## Authenticated state commitment

The version-2 checkpoint includes a deterministic
`record_created_at_commitment`.

The commitment input is domain-separated and canonicalized by sorting records
by record-id bytes. Its encoded state is:

`domain || record_count || repeated(length(id) || id || created_at_be)`

The resulting 32-byte BLAKE3 digest is incorporated into the authenticated
checkpoint MAC input alongside the audit entry count and audit head.

The checkpoint MAC input is therefore structurally:

`checkpoint_domain || expected_count_be || expected_head || record_created_at_commitment`

This associates each committed timestamp with its record identity while
remaining independent of backend iteration order.

## Redb boundary

Authenticated Redb save verifies the existing checkpoint against the
persisted record-state commitment before replacing persisted state.

The replacement authenticated checkpoint is generated from the new in-memory
record state.

Authenticated load recomputes the persisted `id -> created_at` commitment and
fails closed if it differs from the value authenticated by the checkpoint.

A dynamic regression modifies a persisted nonzero timestamp from `100` to
`101` without updating the checkpoint. Authenticated load rejects the modified
state.

## Fjall boundary

Authenticated Fjall open validates persisted records, computes the canonical
record-state commitment, and checks it against the authenticated checkpoint.

Write and delete calculate the prospective record-state commitment and retain
the existing single-batch property for audit mutation, record mutation, and
checkpoint mutation.

Audit-only read transitions preserve the current record-state commitment.

The backend also retains the authenticated record commitment in memory and
checks current persisted record state before authenticated operations.

A dynamic regression modifies a persisted nonzero timestamp from `100` to
`101` without updating the checkpoint. Authenticated open rejects the modified
state.

## Version boundary

Authenticated checkpoint version 2 is intentionally strict.

An authenticated version-1 checkpoint shape does not silently migrate or
upgrade during authenticated open. The version-1 shape fails closed.

Legacy unauthenticated APIs remain a separately documented compatibility
boundary and are not upgraded into this claim.

## Dynamic verification

Commit-bound verification records:

- default Cargo check: `PASS`;
- mobile Cargo check: `PASS`;
- aggregate default test results:
  `301 passed / 0 failed / 0 ignored`
  across `19` test-result summaries;
- aggregate mobile test results:
  `311 passed / 0 failed / 0 ignored`
  across `19` test-result summaries;
- focused LIMIT-012 core regressions:
  `2 passed / 0 failed`;
- focused LIMIT-012 backend tamper regressions:
  `2 passed / 0 failed`;
- baseline Clippy diagnostics: `36`;
- current Clippy diagnostics: `36`;
- new Clippy diagnostics: `0`.

The focused core regressions establish:

1. record iteration order does not change the canonical commitment;
2. changing `created_at` changes the commitment;
3. record-id length boundaries are encoded unambiguously;
4. authenticated checkpoint-v1 shape is rejected by the v2 boundary.

The focused backend regressions establish fail-closed nonzero
`created_at` tamper detection for both Redb and Fjall authenticated reopen.

## Targeted formal verification

Targeted Kani harness:

`verification::kani_harnesses::kani_p35_checkpoint_mac_input_canonical_layout`

Result:

- `395` checks;
- `0` failed;
- `7` unreachable;
- `1` successfully verified harness.

The harness proves the structural checkpoint-v2 MAC-input byte layout includes
the record-created-at commitment at the defined canonical position.

It does **not** prove BLAKE3 cryptographic security, collision resistance,
preimage resistance, keyed-hash security, Argon2 security, MAC
unforgeability, constant-time execution, secret storage, filesystem
integrity, or operating-system integrity.

## Explicit nonclaims

This remediation does not establish an external freshness anchor.

Replay of an older complete, internally valid authenticated database state is
not claimed to be detected.

This remediation does not prove wall-clock correctness or timestamp freshness.
`LIMIT-013` remains the separate local zero-timestamp clock-anomaly boundary.

The commitment authenticates the persisted `created_at` association in the
authenticated local checkpoint boundary. It does not establish general
metadata confidentiality; that remains separate from this authenticity claim.

Total destruction or wholesale replacement of all Edison-owned local state
remains the `LIMIT-008` trust boundary.

## Conclusion

For the authenticated checkpoint-v2 boundary exercised by this evidence,
persisted nonzero `created_at` modification without corresponding authenticated
checkpoint authority fails closed.

`LIMIT-012` is closed for this bounded authenticated persisted-`created_at`
authenticity scope.
