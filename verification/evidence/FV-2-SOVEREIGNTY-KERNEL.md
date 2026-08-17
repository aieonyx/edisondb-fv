# FV-2 Sovereignty Kernel Evidence

Copyright (c) 2026 Edison Lepiten / AIEONYX
License: Apache-2.0

**Status:** Verification complete; phase closure pending commit and push
**Branch:** `fv/sovereignty-kernel`
**Date:** 2026-08-04

## Verified Claim

For data classified as `Critical`, access is permitted only when the requester
is the authenticated owner.

Administrator roles, delegated roles, and explicit allow rules cannot expand
the Critical-tier ceiling.

    Critical access permitted <=> requester is owner

## Specification Trace

Source: `docs/TIER_ENFORCEMENT.md`

Relevant requirements:

- Critical-tier access is restricted to the authenticated owner.
- There is no administrator override.
- There is no escalation path.
- Role and policy grants cannot bypass the Critical-tier ceiling.

## Implementation Boundary

The sovereignty boundary is implemented in:

    src/policy.rs

Function:

    tier_ceiling_allows(is_owner, tier)

The ceiling is evaluated before delegated roles and explicit allow rules.

## Formal Verification

Harness:

    kani_policy_tier_ceiling

Location:

    src/verification.rs

Original recorded result:

    194 checks
    0 failures
    4 unreachable checks
    3 harnesses successfully verified

FV-4b evidence-integrity re-audit established that the `194 checks /
4 unreachable` values belonged only to the final
`kani_owner_nonempty_invariant` harness. They were not an aggregate count for
all three harnesses.

Independent historical reproduction at commit
`feea60da7e70982945cf16e178d55f91c6f5e9f0` with Kani 0.67.0 and CBMC 6.8.0
verified all 3 harnesses with 0 failures.

Per-harness summaries:

- `kani_owner_nonempty_invariant`: 194 checks, 4 unreachable
- `kani_tier_gate_critical`: 237 checks, 5 unreachable
- `kani_policy_tier_ceiling`: 7 checks, 0 unreachable

Arithmetic sum: 438 checks, 0 failures, 9 unreachable. This arithmetic sum is
not a Kani-emitted aggregate count.

Combined raw evidence:

`verification/evidence/raw/fv2-historical-all-harnesses.log`

SHA-256:

`a1029daac86d6131e0a259c0ff9cc883fd7cab9bad3a754b00ada2f7574c8366`

The policy harness symbolically evaluates both ownership states and proves
that Critical-tier access equals the requester ownership state.

## Deterministic Verification

Policy tests:

    22 passed
    0 failed

New regression cases prove:

- An administrator delegation cannot access Critical data.
- An explicit allow rule cannot access Critical data.

gRPC integration tests:

    8 passed
    0 failed

Confirmed behavior includes:

- Wrong-owner Critical reads return `PERMISSION_DENIED`.
- Requests without authentication are rejected.
- Read audit entries are persisted.
- Concurrent writes do not collide during database reopen/save operations.

Complete repository suite:

    198 tests and doctests passed
    0 failed

## Supporting Correctness Changes

- Read audit state is saved before the read result is returned.
- Internal `AccessDenied` is mapped to gRPC `PERMISSION_DENIED`.
- gRPC database operations use a process-local serialization gate.
- Integration tests launch the actual `edisondb-server` binary.

## Assumptions

- `DataTier::Critical` correctly represents Critical classification.
- The ownership Boolean accurately reflects authenticated ownership.
- The policy boundary is invoked before protected data is returned.
- Trusted dependencies follow their documented behavior.

## Explicit Limitations

FV-2 does not prove:

- Cryptographic primitive correctness.
- Key derivation or secret-zeroization correctness.
- WAL or MVCC behavior.
- Crash consistency and recovery.
- Multi-process database concurrency.
- REST, CLI, SDK, or Connector equivalence.
- The full pipeline described in `docs/TIER_ENFORCEMENT.md`.
- Every source file or third-party dependency.

The gRPC operation gate is process-local and prioritizes correctness over
parallel database throughput. Its operating envelope will be measured during
release qualification.

## Reproduction Commands

    cargo test --test p3m6_policy_tests -- --test-threads=1
    cargo kani
    rm -f edison.redb edison.redb.vectors
    cargo test --test grpc_tests -- --test-threads=1
    rm -f edison.redb edison.redb.vectors
    cargo test --all -- --test-threads=1

## Assurance Statement

FV-2 provides formal evidence that non-owners cannot obtain Critical-tier
access through administrator roles, delegated roles, or explicit allow rules.

This assurance applies only to the verified boundary, assumptions, and
limitations documented above.
