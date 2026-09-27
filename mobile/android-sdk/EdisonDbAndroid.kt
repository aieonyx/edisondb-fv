// Copyright (c) 2026 Edison Lepiten / AIEONYX
// License: Apache-2.0
//
// EdisonDbAndroid — singleton JNI wrapper for EdisonDB embedded on Android.
// Loads libedisondb.so (arm64-v8a or x86_64 via ABI split).
// Thread-safe: underlying Rust layer uses Mutex<MobileDb>.

package com.aieonyx.edisondb

import android.content.Context
import android.util.Log
import java.io.File

object EdisonDbAndroid {

    private const val TAG      = "EdisonDB"
    private const val LIB_NAME = "edisondb"   // → libedisondb.so

    @Volatile private var dbHandle: Long = 0L

    init {
        System.loadLibrary(LIB_NAME)
    }

    // ─── Lifecycle ────────────────────────────────────────────────────────────

    @Synchronized
    fun open(context: Context) {
        if (dbHandle != 0L) return
        val dbDir = File(context.filesDir, "edisondb").also { it.mkdirs() }
        dbHandle = nativeOpen(dbDir.absolutePath)
        if (dbHandle == 0L) {
            Log.e(TAG, "Failed to open EdisonDB at ${dbDir.absolutePath}")
            throw IllegalStateException("EdisonDB open failed")
        }
        Log.i(TAG, "EdisonDB opened at ${dbDir.absolutePath}")
    }

    @Synchronized
    fun close() {
        if (dbHandle != 0L) {
            nativeClose(dbHandle)
            dbHandle = 0L
            Log.i(TAG, "EdisonDB closed")
        }
    }

    // ─── Public API ───────────────────────────────────────────────────────────

    /**
     * Insert [value] at [key] with ARPi provenance header [arpi].
     * [tier]: 0=Critical, 1=Personal, 2=Noise.
     * Returns true on success.
     */
    fun insert(key: String, value: String, arpi: ByteArray): Boolean {
        checkOpen()
        val rc = nativeInsert(dbHandle, key, value, arpi)
        if (rc != 0) Log.w(TAG, "insert($key) rc=$rc")
        return rc == 0
    }

    /**
     * Convenience overload — builds ArpiHeader automatically.
     */
    fun insert(key: String, value: String, tier: Byte = 1): Boolean {
        val header = ArpiHeader.build(value, tier)
        return insert(key, value, header)
    }

    internal fun blake3Hash(value: String): ByteArray {
        val hash = nativeBlake3(value)
            ?: error("EdisonDB native BLAKE3 generation failed")
        check(hash.size == 32) {
            "EdisonDB native BLAKE3 returned invalid digest length"
        }
        return hash
    }

    fun query(key: String): String? {
        checkOpen()
        return nativeQuery(dbHandle, key)
    }

    fun delete(key: String): Boolean {
        checkOpen()
        return nativeDelete(dbHandle, key) == 0
    }

    // ─── Internal ─────────────────────────────────────────────────────────────

    private fun checkOpen() {
        check(dbHandle != 0L) {
            "EdisonDB not open — call EdisonDbAndroid.open(context) first"
        }
    }

    // ─── JNI declarations ─────────────────────────────────────────────────────

    private external fun nativeOpen(path: String): Long
    private external fun nativeClose(handle: Long)
    private external fun nativeBlake3(value: String): ByteArray?
    private external fun nativeInsert(handle: Long, key: String, value: String, arpi: ByteArray): Int
    private external fun nativeQuery(handle: Long, key: String): String?
    private external fun nativeDelete(handle: Long, key: String): Int
}
