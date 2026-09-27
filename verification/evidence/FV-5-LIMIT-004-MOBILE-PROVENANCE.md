# FV-5 LIMIT-004 Mobile Fail-Closed Provenance Evidence

Copyright (c) 2026 Edison Lepiten / AIEONYX

## Status

`COMMIT-BOUND TARGETED VERIFICATION PASS`

`PHYSICAL ANDROID JNI/RUST RUNTIME PASS`

`FULL KANI SUITE: NOT RERUN / PREVIOUSLY CHARACTERIZED RESOURCE CEILING REMAINS`

This document records FV-5 closure of the bounded mobile fail-closed
provenance-validation boundary identified as `LIMIT-004`.

The verified final source commit is:

`bc60c1da158466c90ce2c0dd96e60e3e7c7f71b3`

Its parent is the initial LIMIT-004 production-remediation commit:

`2f3c8fca6860e9f97e79e799a9e8050de38012e0`

The P3.5 evidence-closure baseline preceding LIMIT-004 implementation is:

`2726c316051bdebe6c1d04c53200327746bf0c9b`

The final verified source tree is:

`06f287d08d75043cb7d86faf6de7531cec85ceaf`

The evidence-closure commit that will contain this document and the archived
raw evidence is documentation/evidence only. It does not replace the final
source commit identified above as the subject of verification.

## Scope

The mobile write-provenance boundary uses a fixed 78-byte mobile ARPi header.

This mobile storage header is distinct from the separate core ARPi
response/protocol header.

The verified mobile write header contains:

- `ARPi` magic;
- caller-supplied write-counter field whose final value is replaced by
  EdisonDB local monotonic state;
- timestamp field;
- tier byte;
- three reserved bytes;
- 32-byte BLAKE3 content digest;
- 22-byte zero-padded node identifier.

The verified structural acceptance boundary requires:

- exactly `78` bytes;
- exact `ARPi` magic;
- tier in the range `0..=2`;
- all three reserved bytes equal to zero.

No additional timestamp-freshness or node-identity authenticity property is
claimed by this slice.

## Fail-Closed Content Binding

The mobile insertion path recomputes BLAKE3 over the supplied value and
compares that digest with the content-digest field carried by the mobile ARPi
header.

A mismatched digest fails closed before the local monotonic write-counter
transition.

The committed regression:

`mobile::p3_counter_tests::limit004_rejected_provenance_does_not_advance_counter_or_persist`

demonstrates in the exercised path that rejected mismatched provenance:

- returns `DbError::InvalidArpi`;
- leaves the in-memory write counter unchanged;
- does not persist the rejected record;
- does not persist a new write-counter value;
- permits the following valid write to receive counter value `1`;
- preserves that counter value across reopen.

This state-invariance regression complements the earlier P3 arithmetic proof.
It does not establish crash-consistent atomicity between record persistence and
counter persistence. That remains `LIMIT-005` and is assigned to FV-6
remediation.

## Android Producer and JNI Boundary

The Android SDK producer no longer uses the earlier SHA-256 stand-in.

BLAKE3 digest generation is provided by the linked EdisonDB Rust library
through:

`Java_com_aieonyx_edisondb_EdisonDbAndroid_nativeBlake3`

Android insertion uses:

`Java_com_aieonyx_edisondb_EdisonDbAndroid_nativeInsert`

The JNI insertion boundary requires the Java byte array to be exactly
`78` bytes before passing the header into the lower mobile insertion path.

The direct C FFI remains a pointer contract whose caller is required to supply
exactly 78 readable bytes. This evidence does not claim arbitrary C-caller
length validation.

## Android Cross-Build Verification

Commit-bound `cargo-ndk` evidence successfully cross-builds the final source
for Android API level `26` for:

- `arm64-v8a`;
- `x86_64`.

The resulting shared libraries were identified as the expected AArch64 and
x86-64 ELF shared objects.

Both generated libraries export the required provenance JNI symbols:

- `nativeBlake3`;
- `nativeInsert`.

The Android cross-build result proves target compilation and exported-symbol
presence. By itself it is not deployed-runtime proof.

## Physical Android Runtime Verification

Additional commit-bound evidence executes the production EdisonDB JNI/Rust
exports on a physical Android device with:

- Android release: `11`;
- Android SDK: `30`;
- ABI: `arm64-v8a`.

The device serial was not retained in the archived evidence.

A temporary Java harness invoked the production JNI exports from the
commit-bound ARM64 library. The physical runtime demonstrated:

- native BLAKE3 execution;
- successful EdisonDB mobile database open;
- acceptance and round-trip of valid provenance;
- rejection of a mismatched BLAKE3 content digest;
- absence of the rejected mismatched record;
- rejection of tier value `3`;
- rejection of a nonzero reserved byte;
- rejection of a `77`-byte JNI header;
- rejection of a `79`-byte JNI header;
- successful valid insertion after the rejected cases.

The physical-runtime marker is:

`PHYSICAL_ANDROID_LIMIT004_R2_RUNTIME=PASS`

This establishes the exercised production JNI/Rust path on a physical Android
runtime.

It does not establish execution of the complete production Kotlin
application, Android framework correctness, JNI/JVM correctness, or formal
verification of those components.

## Dynamic Verification

Commit-bound default regression aggregate:

- passed: `296`;
- failed: `0`;
- ignored: `0`;
- test-result summaries: `17`.

Commit-bound mobile-library regression:

- passed: `106`;
- failed: `0`;
- ignored: `0`.

Focused LIMIT-004 integration tests:

- passed: `5`;
- failed: `0`;
- ignored: `0`.

Rejected-provenance state-invariance regression:

- passed: `1`;
- failed: `0`;
- ignored: `0`.

The default all-target Cargo check and the mobile-library Cargo check both
completed successfully.

## Clippy Verification

The commit-bound baseline-aware comparison uses the P3.5 evidence-closure
commit:

`2726c316051bdebe6c1d04c53200327746bf0c9b`

Default configuration:

- baseline diagnostics: `23`;
- current diagnostics: `23`;
- new diagnostics: `0`.

Server-plus-mobile test surface:

- baseline diagnostics: `60`;
- current diagnostics: `60`;
- new diagnostics: `0`.

Classification:

`PASS — NO NEW CLIPPY/COMPILER DIAGNOSTICS RELATIVE TO P3.5 CLOSURE`

The mobile build continues to emit previously characterized Rust-2024
unsafe-operation warnings. They are not new LIMIT-004 diagnostics.

## Targeted Kani Verification

Commit-bound targeted harness:

`kani_limit004_mobile_arpi_fail_closed_structure`

Result:

- checks: `158`;
- failed checks: `0`;
- unreachable checks: `4`;
- successfully verified harnesses: `1 / 1`;
- final verifier result: `VERIFICATION:- SUCCESSFUL`.

The harness proves only the deterministic structural acceptance relation of
the Rust mobile `ArpiHeader::from_bytes` parser.

For an exactly 78-byte symbolic candidate, parser acceptance is equivalent to:

- bytes `0..4` equal `ARPi`;
- tier byte at offset `20` is at most `2`;
- bytes `21`, `22`, and `23` are zero.

The harness also covers rejection of non-exact-length candidates through the
named structural boundary.

## Formal Claim Boundary

The targeted Kani proof does **not** formally verify:

- BLAKE3 implementation correctness;
- BLAKE3 collision resistance or other cryptographic-security properties;
- JNI;
- JVM;
- Android;
- Kotlin;
- Java;
- Fjall persistence internals;
- crash consistency;
- replay resistance;
- anti-rollback;
- timestamp freshness;
- node-id authenticity;
- the complete EdisonDB Kani suite.

Cryptographic primitive implementations remain trusted dependencies unless
separately verified.

## Port-Hygiene Methodology

The preserved first raw-evidence attempt:

`verification/evidence/raw/fv5/limit004-2f3c8fca6860-r1/`

is retained unchanged as a historical failed-methodology attempt.

That attempt failed only an obsolete immediate post-test plain TCP bind
criterion.

Follow-up diagnosis established TCP `TIME_WAIT` with:

- no LISTEN socket on TCP port `50051`;
- no surviving `edisondb-server` process;
- successful bind when `SO_REUSEADDR` is enabled.

The final r2 methodology therefore uses those three conditions instead of a
plain bind as the leak criterion.

Both corrected pre-test and post-test port-hygiene gates pass.

The failed r1 methodology attempt is not represented as passing evidence.

## Relationship to Other Limitations

This evidence closes `LIMIT-004` only for the bounded mobile fail-closed
provenance-validation property recorded here.

It does not close:

- `LIMIT-002` — ARPi production integration;
- `LIMIT-003` — mobile verified-kernel bypass;
- `LIMIT-005` — mobile counter crash consistency.

The physical Android JNI/Rust execution evidence does not convert those
separate integration, kernel, or crash-consistency boundaries into closed
claims.

No anti-rollback property is established.

## Source Signature

Both LIMIT-004 source commits carry successfully verified project-root
signatures associated with Edison Lepiten / AIEONYX.

The archived raw evidence contains the `git verify-commit` outputs.

## Lockfile and Source Identity

Verified `Cargo.lock` SHA-256:

`9b33517f58b16900e774e26132fbbb7a48179f121d2795365c9608d45bc19c8b`

Final source commit:

`bc60c1da158466c90ce2c0dd96e60e3e7c7f71b3`

Final source tree:

`06f287d08d75043cb7d86faf6de7531cec85ceaf`

Raw r2 `summary.json` SHA-256:

`e1deb76b2bbfac5eb3d7ea6345e3e068a8823328aab5caf18295fd3472c2c3f3`

Final r2 checksum-manifest SHA-256:

`89bca14d37244740f8d93448d612cc4de7bb3e943ae7821f41c161e44e930891`

## Raw Evidence

Final passing commit-bound evidence:

`verification/evidence/raw/fv5/limit004-bc60c1da1584-r2/`

Final checksum manifest:

`verification/evidence/raw/fv5/limit004-bc60c1da1584-r2/SHA256SUMS.txt`

Preserved historical failed-methodology attempt:

`verification/evidence/raw/fv5/limit004-2f3c8fca6860-r1/`

The final r2 checksum manifest verifies every raw artifact included in the
sealed r2 package.
