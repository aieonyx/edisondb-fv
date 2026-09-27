# FV-5 P3.5 Authenticated Audit Checkpoint Evidence

Copyright (c) 2026 Edison Lepiten / AIEONYX

## Status

`COMMIT-BOUND TARGETED VERIFICATION PASS`

`FULL KANI SUITE: NOT RERUN / PREVIOUSLY CHARACTERIZED RESOURCE CEILING REMAINS`

This document records FV-5 P3.5 hardening of the local audit-checkpoint
authentication boundary.

The verified source commit is:

`f5e14886304dc57895d7f988e56883a9b394e189`

Its parent is the FV-5 P3 evidence-closure commit:

`824182b556b63d18c70f343122a1a200edf6a411`

Its Git tree is:

`06f5ca327255f0f3b94d3b137cc2db35c88d5213`

The evidence-closure commit that will contain this document and the raw
evidence is documentation/evidence only. It does not replace the source
commit identified above as the subject of verification.

## Scope

At the verified source commit, authenticated checkpoint mode introduces a
versioned checkpoint containing:

- checkpoint format version;
- expected audit-entry count;
- expected terminal audit hash;
- per-store checkpoint salt;
- keyed checkpoint MAC.

The authenticated checkpoint authority is derived from a database-global
`store_secret`.

The store secret is distinct from the per-owner record-encryption password.

The authenticated checkpoint path:

- derives store key material from `store_secret` and the persisted store salt;
- derives a checkpoint MAC key using the named BLAKE3 key-derivation context;
- computes the checkpoint MAC over the canonical domain-separated input
  `domain || big-endian expected_count || expected_head`;
- rejects unsupported checkpoint versions;
- rejects a wrong or tampered store secret;
- rejects count, head, MAC, or salt tampering;
- validates authenticated expected count and head against the actual audit
  history before accepting the database state.

The legacy and authenticated checkpoint representations both use strict Serde
field validation.

An authenticated checkpoint cannot silently deserialize as the legacy
checkpoint representation.

Authenticated open also does not silently adopt a nonempty legacy checkpoint.

No implicit legacy-to-authenticated migration is performed by this slice.

## Store-Secret Authority Separation

P3.5 establishes a separate database-global checkpoint authority rather than
reusing an owner's record password.

The high-level executor and Rust SDK therefore expose authenticated
constructors that receive both:

- the owner's record-encryption password; and
- a distinct `store_secret`.

Dynamic coverage demonstrates that two different owners can operate on the
same authenticated database using:

- different owner passwords; and
- the same database-global store secret.

Possession of the store secret does not bypass record authorization.

A non-owner Critical read remains denied even when the caller uses the correct
store secret.

The owner can later reopen and decrypt the owner's own Critical record using
the owner's own record password.

A wrong store secret fails closed at authenticated checkpoint open with the
audit-chain failure boundary rather than being treated as an owner-password
failure.

## Backend Persistence

Authenticated checkpoint persistence is implemented for both supported
storage backends.

Redb authenticated mode persists the authenticated checkpoint through the
existing save boundary.

Fjall authenticated mode retains the derived checkpoint authentication
context and updates authenticated checkpoint state together with the related
audit mutation.

Explicit Fjall regressions cover authenticated checkpoint preservation after:

- record write;
- granted read audit append;
- denied read audit append;
- record delete.

Both legacy-open/authenticated-checkpoint and
authenticated-open/legacy-checkpoint downgrade directions are rejected.

## Server Boundary

The server process obtains one database-global checkpoint authority from:

`EDISONDB_STORE_SECRET`

That value is process-startup state and is not sourced from an HTTP or gRPC
request.

The request `x-password` value remains the per-owner record credential.

Server startup fails closed when `EDISONDB_STORE_SECRET` is absent or empty,
before database creation.

REST and gRPC database opens both use the authenticated SDK seam.

The existing wrong-owner gRPC authorization regression continues to pass.

This evidence does not claim that an environment variable provides hardware
secret storage, kernel isolation, or protection against a host compromise.

## Dynamic Verification

Commit-bound default regression result:

- passed: `297`;
- failed: `0`;
- ignored: `0`.

Commit-bound mobile-library regression result:

- passed: `105`;
- failed: `0`;
- ignored: `0`.

Focused `p35_` regression result:

- passed: `23`;
- failed: `0`;
- ignored: `0`.

Explicit high-level Fjall authenticated-seam results:

- executor: `1` passed / `0` failed;
- SDK: `1` passed / `0` failed.

The default all-target Cargo check and mobile-library Cargo check both
completed successfully.

The mobile configuration continues to emit the previously characterized
Rust-2024 unsafe-operation warnings. P3.5 introduces no new mobile Clippy
diagnostics relative to its baseline.

## Clippy Verification

Baseline-aware commit-bound Clippy comparison uses the P3 evidence-closure
commit `824182b556b63d18c70f343122a1a200edf6a411` as baseline.

Default configuration:

- baseline diagnostics: `23`;
- current diagnostics: `23`;
- new diagnostics: `0`.

Mobile-library configuration:

- baseline diagnostics: `29`;
- current diagnostics: `29`;
- new diagnostics: `0`.

Classification:

`PASS — NO NEW CLIPPY/COMPILER DIAGNOSTICS RELATIVE TO P3 CLOSURE`

The raw evidence uses Cargo JSON compiler-message accounting. Those archived
counts are the commit-bound evidence values for this slice.

## Targeted Kani Verification

Commit-bound targeted harness:

`kani_p35_checkpoint_mac_input_canonical_layout`

Result:

- checks: `381`;
- failed checks: `0`;
- unreachable checks: `7`;
- successfully verified harnesses: `1 / 1`;
- final verifier result: `VERIFICATION:- SUCCESSFUL`.

The harness establishes the canonical byte layout used as input to checkpoint
MAC computation:

`domain || big-endian expected_count || expected_head`

Symbolic indices cover the domain bytes, every count byte, and every checkpoint
head byte.

## Formal Claim Boundary

The targeted Kani proof is a structural encoding proof only.

It does **not** formally verify:

- BLAKE3 implementation correctness;
- BLAKE3 cryptographic security;
- Argon2 implementation correctness;
- Argon2 cryptographic security;
- MAC unforgeability;
- resistance to cryptanalysis;
- constant-time execution;
- operating-system secret handling;
- the complete EdisonDB Kani suite.

Cryptographic primitive implementations remain trusted dependencies unless
separately verified.

## Rollback and State-Replacement Boundary

P3.5 authenticates the checkpoint against a holder of the external store
secret.

It does not create a monotonic external freshness oracle.

An attacker who can replace the complete EdisonDB state with an older
internally consistent state carrying an older valid authenticated checkpoint
is outside the anti-rollback property established here.

P3.5 therefore does not claim global rollback resistance.

Total destruction or replacement of all Edison-owned local state remains the
separate trust boundary recorded by `LIMIT-008`.

The authenticated checkpoint also depends on custody of `store_secret`.

Compromise of that authority permits creation of checkpoint MACs and is
outside this claim.

Possession of the checkpoint authority does not itself provide the
per-record owner password required to decrypt Critical or Personal payloads.

## Legacy-Mode Boundary

The legacy `Store` and SDK construction seams are retained for compatibility.

The authenticated-checkpoint claim applies only when the authenticated
open/save/connect seam is used.

The production server path added by P3.5 requires the authenticated store
secret and therefore does not silently fall back to legacy checkpoint mode.

No automatic migration of an existing nonempty legacy checkpoint is claimed.

## Existing Limitations

`LIMIT-001` local tail-truncation and local checkpoint re-anchoring protection
is now strengthened in authenticated mode by keyed checkpoint sealing.

Residual replay/rollback and complete-state replacement are not closed by
that result.

`LIMIT-004 — Mobile fail-closed provenance validation` remains open and
assigned to FV-5.

`LIMIT-005 — Mobile counter crash consistency` remains open as the P3 witness;
crash-consistent remediation remains assigned to FV-6.

`LIMIT-012 — Persisted created_at authenticity` remains open. P3.5
authenticates checkpoint count/head state; it does not establish a separate
formal authenticity property for `Record.created_at`.

P3.5 does not close unrelated FV-5 limitations.

## Full Kani Suite Classification

The complete EdisonDB Kani suite was not rerun for P3.5.

Earlier FV-5 evidence already characterized the audit-related verifier
resource ceiling. P3.5 does not reinterpret that historical resource result as
green and does not weaken unrelated audit harnesses to obtain a passing
complete-suite result.

Accordingly, P3.5 is classified as targeted commit-bound verification, not
complete-suite formal verification.

## Source Signature

The source commit carries a successfully verified project-root signature.

Raw `git verify-commit` output is archived in:

`verification/evidence/raw/fv5/p35-f5e14886304d-r1/commit-metadata.txt`

## Lockfile and Source Identity

Verified `Cargo.lock` SHA-256:

`9b33517f58b16900e774e26132fbbb7a48179f121d2795365c9608d45bc19c8b`

Source-tree manifest SHA-256:

`d49cbdbf98496475499ab6d2909981093c2b18a1d6799da962a94de81ded5f7f`

Raw evidence `summary.json` SHA-256:

`b5a3b85c612bf40045bcb60766e43bc64ca9a233ea37af36929f4ce1eddef90f`

Raw evidence checksum manifest SHA-256:

`880eb32f66f95b64ed7af9223ba4a0f76a4a40953bfe37f153f0fa98bbe469a4`

## Raw Evidence

Archived commit-bound evidence:

`verification/evidence/raw/fv5/p35-f5e14886304d-r1/`

Checksum manifest:

`verification/evidence/raw/fv5/p35-f5e14886304d-r1/SHA256SUMS`

The checksum manifest verifies all `23` raw artifacts covered
by the manifest. The manifest itself is the additional package index file.
