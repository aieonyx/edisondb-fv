# EdisonDB Mobile SDK — Android

**Copyright (c) 2026 Edison Lepiten / AIEONYX**  
**License: Apache-2.0**

EdisonDB v0.6.0 expands to Android with a full embedded-mode mobile SDK.
No gRPC. No server. Sovereign storage + ARPi provenance on every write,
running natively on Android via JNI.

The mobile 78-byte write-provenance header is distinct from the 78-byte
response/protocol `ArpiHeader` in `src/arpi.rs`. They serve different
boundaries and are not wire-compatible. FV-5 LIMIT-004 concerns the mobile
write-provenance path.

---

## Why Mobile

EdisonDB's core guarantees — ARPi provenance headers, AES-256-GCM at rest,
BLAKE3-bound writes, Inverted Admin Model — are just as necessary on a
mobile device as on a server node. The first integration target is
[AI Stop](https://github.com/aieonyx/aistop) (`com.aieonyx.aistop`), an
Android privacy guard app that logs every AI data exposure event.

Every exposure log entry backed by EdisonDB carries:
- An ARPi (AXON Receptor Protocol Interface) 78-byte provenance header
- BLAKE3 content hash
- AES-256-GCM encryption at rest via Android Keystore
- Monotonic write counter for tamper detection

---

## Phases

### Phase M1 — Rust FFI Bridge (EdisonDB side)

Add Android cross-compilation targets and a `mobile` feature flag to
`Cargo.toml`. The `mobile` feature strips the gRPC/tonic server and exposes
a minimal C-ABI surface:

```
edisondb_open(path)   → DbHandle
edisondb_insert(db, key, value, arpi_header)
edisondb_query(db, key)
edisondb_delete(db, key)
edisondb_close(db)
edisondb_free_string(s)
```

Cross-compiled via `cargo-ndk` to `arm64-v8a` + `x86_64`.
Output: `libeditsondb.so` placed in AI Stop's `jniLibs/`.

### Phase M2 — Kotlin Android SDK

- `EdisonDbAndroid.kt` — singleton JNI wrapper, lifecycle-aware
- `ArpiHeader.kt` — generates the 78-byte mobile provenance header per write using Rust-owned BLAKE3
- `ExposureStore.kt` — interface that mirrors `ExposureDao` exactly (drop-in)
- `EdisonDbExposureStore.kt` — implements `ExposureStore` via EdisonDB
- AES-256-GCM encryption at rest using Android Keystore (no key ever leaves device)

### Phase M3 — AI Stop Integration

- Swap `ExposureDatabase` (Room) → `EdisonDbAndroid` in AI Stop
- Every `ExposureEvent` gains ARPi provenance chain
- Signed export bundle now includes EdisonDB provenance manifest
- Commits to both `edisondb` (SDK) and `aistop` (integration)

---

## Target Devices

| ABI        | Target triple                    |
|------------|----------------------------------|
| arm64-v8a  | aarch64-linux-android            |
| x86_64     | x86_64-linux-android             |

Min SDK: Android 26 (API 26) — required for AES-GCM Keystore key generation.

---

## Sovereign Guarantees Preserved on Mobile

| Guarantee           | Mechanism                            |
|---------------------|--------------------------------------|
| Provenance          | ARPi 78-byte header on every write   |
| Integrity           | BLAKE3 hash per record               |
| Confidentiality     | AES-256-GCM, Android Keystore        |
| Non-repudiation     | Ed25519 export signing               |
| GDPR Art.17         | Keyed delete (key destruction = erasure) |

---

## Status

- [ ] M1: Rust FFI bridge + cargo-ndk cross-compile
- [ ] M2: Kotlin Android SDK
- [ ] M3: AI Stop integration + dual-repo commit

Tracking issue: see `mobile/` directory for implementation.
