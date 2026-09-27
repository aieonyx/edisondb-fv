// Copyright (c) 2026 Edison Lepiten / AIEONYX
// License: Apache-2.0
//
// ArpiHeader — 78-byte mobile ARPi write-provenance header.
// Generated on Android for every EdisonDB write.
// Rust owns BLAKE3 digest generation and validates the same content binding
// again before persistence.
//
// Layout:
//   Offset  Size  Field
//    0       4    magic: "ARPi"
//    4       8    write_counter (u64 LE) — Rust assigns final monotonic value
//   12       8    timestamp_us (u64 LE, Unix epoch microseconds)
//   20       1    tier (0=Critical, 1=Personal, 2=Noise)
//   21       3    reserved (zero)
//   24      32    BLAKE3 content hash
//   56      22    node_id (UTF-8, zero-padded)

package com.aieonyx.edisondb

import java.nio.ByteBuffer
import java.nio.ByteOrder

object ArpiHeader {

    const val SIZE = 78
    private val MAGIC = byteArrayOf(0x41, 0x52, 0x50, 0x69)  // "ARPi"

    /**
     * Build a 78-byte provenance header for [value] at [tier].
     *
     * [tier]: 0=Critical (AI exposure events), 1=Personal, 2=Noise (index keys)
     * [nodeId]: device ARPi node identifier (empty = zero-padded)
     *
     * The BLAKE3 content digest is produced by the linked EdisonDB Rust
     * library. MobileDb validates that digest again against the exact value
     * before persistence.
     */
    fun build(value: String, tier: Byte = 1, nodeId: String = ""): ByteArray {
        val buf = ByteBuffer.allocate(SIZE).order(ByteOrder.LITTLE_ENDIAN)

        buf.put(MAGIC)                                    //  0–3   magic
        buf.putLong(0L)                                   //  4–11  write_counter (Rust sets final)
        buf.putLong(System.currentTimeMillis() * 1_000L) // 12–19  timestamp_us
        buf.put(tier)                                     // 20     tier
        buf.put(ByteArray(3))                             // 21–23  reserved
        buf.put(EdisonDbAndroid.blake3Hash(value))                      // 24–55  hash
        buf.put(nodeId.toByteArray(Charsets.UTF_8).copyOf(22))   // 56–77  node_id

        return buf.array()
    }

}
