# FV-5 P2 AAD Metadata Authority Evidence

Copyright (c) 2026 Edison Lepiten / AIEONYX

## Status

`COMMIT-BOUND TARGETED VERIFICATION PASS`

`FULL KANI SUITE: NOT RERUN / PREVIOUSLY CHARACTERIZED RESOURCE CEILING REMAINS`

This document records FV-5 P2 hardening of the existing record ID and tier
AES-GCM associated-data authority boundary and the commit-bound evidence
generated for that source.

The verified source commit is:

`6793c15c77b07c8f8cdbb51934bf4be1eee5e883`

Its parent is the FV-5 P1c-B evidence-closure commit:

`b082d11824efcab8330df804d5556601ca673d82`

Its Git tree is:

`23daf4e15cc907531bbfaee155103a9cc6336afc`

The evidence-closure commit that will contain this document and the raw
evidence is documentation/evidence only. It does not replace the source
commit identified above as the subject of verification.

## Scope

The record payload encryption path already bound AES-GCM associated data to
the record identifier and data tier before FV-5 P2.

P2 does not introduce a new AAD byte format and does not intentionally change
the persisted version-1 encrypted-payload compatibility boundary.

At the verified source commit:

- `Record.id` is private and exposed only through immutable access;
- `Record.tier` is private and exposed only through immutable access;
- external callers cannot independently mutate those AAD-authority metadata
  fields after record construction;
- the public `Record::new` constructor accepts plaintext and the encryption
  key rather than an externally constructed encrypted payload;
- the public constructor performs encryption internally using the same
  identifier and tier stored in the resulting record;
- the crate-private reconstruction seam remains available for validated
  persisted reconstruction and verification;
- executor construction no longer performs a split encrypt-then-record
  construction sequence;
- the existing AAD representation remains the record ID plus canonical tier
  label used by both encryption and decryption;
- decryption with a different record ID or different tier continues to fail.

This phase hardens authority over metadata participating in the existing AAD
boundary. It does not formally verify the AES-GCM primitive.

## Construction Authority

Before P2, the public record constructor accepted an `EncryptedPayload`
together with independently supplied record ID and tier metadata.

That API shape allowed an external caller to create an internally inconsistent
record by supplying ciphertext produced under one ID/tier context while
supplying different record metadata.

Authenticated decryption would subsequently fail, but the inconsistent record
state could still be constructed through the public API.

P2 removes that split authority from public construction.

The public constructor now receives plaintext plus key material and performs
payload encryption inside record construction. The identifier and tier used
for encryption are therefore the same values assigned to the constructed
record through that public seam.

## Compile-Time Mutation Boundary

The P2 compile-fail suite includes:

- `tests/ui/p2_record_id_mutation.rs`;
- `tests/ui/p2_record_tier_mutation.rs`.

Both confirm that external code cannot directly mutate the record identifier
or tier.

This is a Rust visibility/type-system enforcement result. It is not a Kani
cryptographic proof.

## Dynamic Verification

Commit-bound dynamic result:

- Cargo test result summaries: `16`;
- passed: `273`;
- failed: `0`;
- ignored: `0`.

The suite includes:

- `p2_record_constructor_binds_payload_to_immutable_id_and_tier`;
- `aad_mismatch_fails_decryption`;
- `aad_tier_mismatch_fails_decryption`;
- the P2 compile-fail metadata-mutation boundary;
- existing storage, audit, checkpoint, migration, verification, compliance,
  gRPC, SDK, and persistence-envelope regressions.

The constructor regression demonstrates that a normally constructed record
decrypts with its own ID/tier context and fails authenticated decryption when
either ID or tier is substituted.

## Clippy Verification

Baseline-aware commit-bound Clippy comparison:

- baseline source:
  `dba00ea58cd160a69c9a4fc6bb041e361fa40e47`;
- baseline diagnostics: `23`;
- current P2 diagnostics: `23`;
- new diagnostics: `0`;
- removed diagnostics: `0`;
- Clippy exit code: `0`;
- comparison exit code: `0`.

Classification:

`PASS — NO NEW CLIPPY DIAGNOSTICS RELATIVE TO P1c-A`

Existing baseline diagnostics were not expanded into unrelated cleanup during
this security-boundary slice.

## Targeted Kani Verification

Commit-bound targeted harness:

`kani_p2_record_metadata_authority`

Result:

- checks: `500`;
- failed: `0`;
- unreachable: `7`;
- harnesses successfully verified: `1 / 1`;
- final verifier result: `VERIFICATION:- SUCCESSFUL`.

The harness exercises two distinct record identifiers and all three
`DataTier` variants and proves, through the production
`Record::new_with_created_at` construction seam, that the constructed record
preserves the selected identifier and tier metadata.

Kani reported unsupported `caller_location` and foreign-function constructs.
Those notices are retained in the raw log.

The successful targeted run is not interpreted as verification of behavior
represented by unsupported constructs themselves.

## Formal Claim Boundary

The targeted Kani result establishes a metadata-construction property:

- the selected record identifier is preserved by the modeled production
  construction seam;
- the selected data tier is preserved by the modeled production construction
  seam.

The compile-fail tests separately establish that external callers cannot
directly mutate those private fields.

The dynamic cryptographic regressions separately demonstrate that authenticated
decryption fails when the ID or tier context is substituted.

These results must not be collapsed into a broader cryptographic proof.

In particular, this evidence does **not** claim formal verification of:

- AES-GCM implementation correctness;
- AES-GCM confidentiality;
- AES-GCM authenticity security;
- nonce-generation security;
- resistance to cryptanalysis;
- third-party cryptographic implementation internals.

AES-GCM remains a trusted cryptographic dependency unless separately verified.

## Full Kani Suite Classification

The complete EdisonDB Kani suite was not rerun for P2.

P1c-B already documented a reproduced verifier resource ceiling in the
audit-related full-suite portion, including CBMC memory exhaustion also
reproduced against the P1c-A baseline.

P2 does not reinterpret that historical resource result as green and does not
weaken unrelated audit harnesses to obtain a passing full-suite result.

Accordingly, the P2 closure classification is targeted commit-bound
verification, not complete-suite formal verification.

## Existing Limitations

P2 does not close unrelated FV-5 limitations.

In particular:

- `LIMIT-009` remains open: payload encryption does not conceal clear record
  metadata such as existence, owner, or tier;
- `LIMIT-012` remains open: persisted `created_at` authenticity is not yet
  cryptographically bound by the current checkpoint boundary;
- `LIMIT-013` remains open: local construction may still observe the documented
  zero-timestamp clock anomaly;
- `LIMIT-010` remains source-remediated with wider FV-5 phase closure pending.

P2 specifically hardens authority over ID/tier metadata used by the existing
payload AAD boundary.

## Lockfile and Source Identity

Verified `Cargo.lock` SHA-256:

`9b33517f58b16900e774e26132fbbb7a48179f121d2795365c9608d45bc19c8b`

Source-tree manifest SHA-256:

`d816e96935dbfd207966ff90986e7103860e2efe075f0b8983f0889dc17a30d1`

Raw evidence `summary.json` SHA-256:

`95c55e1fa75a362892f4a998f4700aec992b35ac52e44fff946d1395d8c74c3e`

Raw evidence checksum manifest SHA-256:

`9a3eafd6598225cae99ef2f0b4ded835926384e22966fcc6d9a6eef6383d3189`

## Raw Evidence

Archived commit-bound evidence:

`verification/evidence/raw/fv5/p2-6793c15c77b0-r1/`

Checksum manifest:

`verification/evidence/raw/fv5/p2-6793c15c77b0-r1/SHA256SUMS`

The checksum manifest verifies all raw artifacts in the P2 package.
