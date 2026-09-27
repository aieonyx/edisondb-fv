# FV-5 Phase Closure — Encryption and Secret Boundaries

## Status

`COMMIT-BOUND PHASE ACCOUNTING COMPLETE`

Final reviewed FV-5 head before this phase-closure record:

`aff67ac84012e32f1bbfd4d4976e176d1d0241e2`

Raw phase-closure evidence:

`verification/evidence/raw/fv5/phase-closure-aff67ac84012-r1/`

## Scope completed in FV-5

FV-5 established bounded verification evidence for the following production
security boundaries:

1. validated persisted-record reconstruction authority;
2. versioned encrypted-payload persistence;
3. record ID and tier authority for AES-GCM associated data;
4. mobile write-counter monotonic transition behavior;
5. authenticated audit-checkpoint sealing;
6. fail-closed mobile provenance validation;
7. persisted nonzero `created_at` authenticity through authenticated
   checkpoint version 2.

These are recorded as `CLAIM-FV5-001` through `CLAIM-FV5-007`.

## LIMIT-010 final accounting

`LIMIT-010 — Public salt mutation boundary` was remediated in signed P1a source
commit:

`81782052fb4ad1c73aeb51df0a72973318f4fa7c`

That change made `Record.salt` private and retained read-only access through
`Record::salt()`.

Final FV-5 authority verification against `aff67ac84012e32f1bbfd4d4976e176d1d0241e2` confirms:

- `Record.salt` remains private;
- the public `salt()` accessor returns an immutable reference;
- no public salt setter or mutator is present;
- no public mutable salt reference is exposed;
- no direct `.salt = ...` production assignment is present.

Accordingly, LIMIT-010 is closed for the bounded public record-salt mutation
authority identified by the FV-5 audit.

## Deferred and residual boundaries

Phase closure does not mean every broader EdisonDB security property is
resolved.

The following boundaries remain explicit:

- `LIMIT-002` — ARPi production integration: deferred to FV-7;
- `LIMIT-003` — mobile verified-kernel bypass: deferred to FV-7;
- `LIMIT-005` — mobile counter crash consistency:
  FV-5 source-level witness complete, remediation deferred to FV-6;
- `LIMIT-008` — total Edison-owned local-state erasure:
  retained as an explicit trust boundary;
- `LIMIT-009` — persisted metadata confidentiality:
  retained as an explicit nonclaim;
- `LIMIT-013` — local zero-timestamp clock anomaly:
  retained as a separate open boundary.

These residuals do not invalidate the narrower FV-5 claims. They constrain the
scope of what FV-5 establishes.

## Formal-verification boundary

FV-5 does not claim complete formal verification of EdisonDB.

The phase contains a mixture of:

- commit-bound dynamic regression evidence;
- baseline-aware Clippy comparison;
- compile-fail API-boundary enforcement;
- targeted Kani harnesses;
- physical Android runtime evidence for the bounded mobile provenance path.

Cryptographic primitives remain trusted dependencies unless separately stated.
BLAKE3, AES-GCM, Argon2, operating-system behavior, filesystem durability,
anti-rollback, crash consistency, JNI/JVM/Android/Kotlin correctness, and
external freshness are not promoted into formal claims by this phase closure.

## Repository binding

At phase-closure evidence collection:

- local FV-5 head: `aff67ac84012e32f1bbfd4d4976e176d1d0241e2`;
- remote tracking head: `aff67ac84012e32f1bbfd4d4976e176d1d0241e2`;
- protected pre-FV2 Redb backup remained untracked;
- the FV-5 recovery/reference stash remained preserved.

## Conclusion

FV-5 is phase-accounting complete for its documented encryption and secret
boundaries.

All FV-5 obligations assigned to this phase are either:

- closed within their explicitly bounded claim;
- satisfied as a required FV-5 witness with remediation assigned to a later
  phase; or
- retained explicitly as a trust boundary or nonclaim.

This closure does not erase or weaken any deferred limitation.
