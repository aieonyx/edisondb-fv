# FV-5 P3 Mobile Counter Monotonicity Evidence

Copyright (c) 2026 Edison Lepiten / AIEONYX

## Status

`COMMIT-BOUND TARGETED VERIFICATION PASS`

`FULL KANI SUITE: NOT RERUN / PREVIOUSLY CHARACTERIZED RESOURCE CEILING REMAINS`

This document records FV-5 P3 hardening of the mobile ARPi write-counter
state-validation and arithmetic monotonicity boundary.

The verified source commit is:

`d041b9ffe45e20849d6afbbdcd01b3a4954f9c89`

Its parent is the FV-5 P2 evidence-closure commit:

`916167bd5704f3638624fbbfbabb0dbe31a40ad8`

Its Git tree is:

`b93fd815e0906429eb72dd08ea6fd8b18994ead8`

The evidence-closure commit that will contain this document and the raw
evidence is documentation/evidence only. It does not replace the source
commit identified above as the subject of verification.

## Scope

At the verified source commit:

- the persisted mobile write-counter key is centralized as
  `WRITE_COUNTER_KEY`;
- a missing counter initializes the local counter to zero;
- a persisted counter with any length other than eight bytes fails closed
  with `DbError::InvalidCounterState`;
- Fjall counter-read failures propagate as `DbError::Fjall` rather than
  silently resetting the counter to zero;
- the production counter transition uses `checked_add(1)`;
- `u64::MAX` is treated as exhaustion and returns
  `DbError::CounterExhausted`;
- counter exhaustion does not wrap to zero and the attempted record is not
  written;
- the locally generated counter remains authoritative over the caller's
  ARPi `write_counter` field;
- a successfully persisted counter is recovered across reopen and the next
  successful transition advances from that recovered value.

P3 does not claim global anti-rollback protection for a valid but older
persisted counter supplied by an attacker.

## Dynamic Verification

Commit-bound default regression result:

- passed: `273`;
- failed: `0`;
- ignored: `0`.

Commit-bound mobile-library regression result:

- passed: `84`;
- failed: `0`;
- ignored: `0`.

The mobile suite includes four P3-specific regressions:

- `p3_counter_increments_and_resumes_after_reopen`;
- `p3_malformed_persisted_counter_fails_closed`;
- `p3_counter_exhaustion_rejects_write_without_wraparound`;
- `p3_counter_transition_never_wraps`.

The default all-target Cargo check and the mobile-library Cargo check both
completed successfully.

## Clippy Verification

Baseline-aware commit-bound Clippy comparison uses the P2 evidence-closure
commit `916167bd5704f3638624fbbfbabb0dbe31a40ad8` as baseline.

Default configuration:

- baseline diagnostics: `10`;
- current diagnostics: `10`;
- new diagnostics: `0`;
- current errors: `0`.

Mobile-library configuration:

- baseline diagnostics: `21`;
- current diagnostics: `21`;
- new diagnostics: `0`;
- current errors: `0`.

Classification:

`PASS — NO NEW CLIPPY/COMPILER DIAGNOSTICS RELATIVE TO P2 CLOSURE`

Existing diagnostics were not expanded into unrelated cleanup during this
security-boundary slice.

## Targeted Kani Verification

Commit-bound targeted harness:

`kani_p3_mobile_counter_monotonic_transition`

Result:

- checks: `38`;
- failed checks: `0`;
- successfully verified harnesses: `1 / 1`;
- final verifier result: `VERIFICATION:- SUCCESSFUL`.

The harness quantifies over the complete `u64` input domain of the production
`next_write_counter` seam.

It establishes:

- for every `current < u64::MAX`, the returned counter equals
  `current + 1`;
- the successful result is strictly greater than `current`;
- for `current == u64::MAX`, the transition returns `None`;
- the transition therefore does not wrap through zero.

## Formal Claim Boundary

The targeted Kani result establishes an arithmetic transition property only.

This evidence does **not** claim formal verification of:

- record/counter persistence atomicity;
- crash consistency;
- rollback resistance against replacement with an older valid counter;
- replay protection;
- deployed Android provenance/content enforcement;
- Fjall implementation internals;
- the complete EdisonDB Kani suite.

The successful targeted proof must not be interpreted as any of those broader
properties.

## LIMIT-005 Source-Level Witness

`LIMIT-005 — Mobile counter crash consistency` remains open.

At the verified source commit, `MobileDb::insert` still performs:

1. record persistence through `partition.insert(...)`;
2. counter persistence afterward through `persist_counter()`.

Those remain separate persistence operations.

A failure or crash between those operations can therefore leave record state
and durable counter state without a demonstrated single atomic
crash-consistent transition.

P3 intentionally does not replace those operations with a Fjall atomic batch.

This is the FV-5 source-level witness for `LIMIT-005`. It records the
remaining boundary rather than claiming remediation.

Actual crash-consistency remediation remains assigned to FV-6.

## Other Mobile Limitation

`LIMIT-004 — Mobile fail-closed provenance validation` remains open and
assigned to FV-5.

P3 is limited to write-counter state validity and arithmetic monotonicity and
does not claim deployed mobile provenance/content enforcement.

## Full Kani Suite Classification

The complete EdisonDB Kani suite was not rerun for P3.

Earlier FV-5 evidence already characterized the audit-related verifier
resource ceiling. P3 does not reinterpret that historical resource result as
green and does not weaken unrelated audit harnesses to obtain a passing
complete-suite result.

Accordingly, P3 is classified as targeted commit-bound verification, not
complete-suite formal verification.

## Lockfile and Source Identity

Verified `Cargo.lock` SHA-256:

`9b33517f58b16900e774e26132fbbb7a48179f121d2795365c9608d45bc19c8b`

Source-tree manifest SHA-256:

`1c7671d2a38d9219282c99f70262d206b7f783ea9675a8ea1a92c42220cffe25`

Raw evidence `summary.json` SHA-256:

`d34b0772b30974e5b7b2b651e606e80cafc61c769d9b63885eb424931c45f469`

Raw evidence checksum manifest SHA-256:

`dfaa612fb09a29729df33e1b6030af0cf467043d668878016aa82a810a2de5a3`

## Raw Evidence

Archived commit-bound evidence:

`verification/evidence/raw/fv5/p3-d041b9ffe45e-r1/`

Checksum manifest:

`verification/evidence/raw/fv5/p3-d041b9ffe45e-r1/SHA256SUMS`

The checksum manifest verifies all `20` raw artifacts covered by the
manifest. The manifest itself is the additional package index file.
