// Copyright (c) 2026 Edison Lepiten / AIEONYX
// License: Apache-2.0
//
// jni_bridge.rs — JNI entry points that Kotlin's `external fun` resolves to.
// These are thin shims: they convert JNI types → Rust-native types,
// delegate to the C-ABI FFI layer, and convert back.
//
// Naming convention: Java_<package_underscored>_<ClassName>_<methodName>
// Package: com.aieonyx.edisondb → com_aieonyx_edisondb
// Class:   EdisonDbAndroid

#![allow(non_snake_case, clippy::missing_safety_doc)]

use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jint, jlong, jstring};
use jni::JNIEnv;

use super::ffi::{
    edisondb_close, edisondb_delete, edisondb_free_string, edisondb_insert, edisondb_open,
    edisondb_query,
};

/// com.aieonyx.edisondb.EdisonDbAndroid.nativeOpen(path: String): Long
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_aieonyx_edisondb_EdisonDbAndroid_nativeOpen(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
) -> jlong {
    let path_str: String = match env.get_string(&path) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };
    let c_path = match std::ffi::CString::new(path_str) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    edisondb_open(c_path.as_ptr()) as jlong
}

/// com.aieonyx.edisondb.EdisonDbAndroid.nativeClose(handle: Long)
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_aieonyx_edisondb_EdisonDbAndroid_nativeClose(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    edisondb_close(handle as *mut super::ffi::DbHandle);
}

/// com.aieonyx.edisondb.EdisonDbAndroid.nativeBlake3(value): ByteArray?
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_aieonyx_edisondb_EdisonDbAndroid_nativeBlake3(
    mut env: JNIEnv,
    _class: JClass,
    value: JString,
) -> jbyteArray {
    let value_str: String = match env.get_string(&value) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };

    let digest = blake3::hash(value_str.as_bytes());

    match env.byte_array_from_slice(digest.as_bytes()) {
        Ok(bytes) => bytes.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// com.aieonyx.edisondb.EdisonDbAndroid.nativeInsert(handle, key, value, arpi): Int
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_aieonyx_edisondb_EdisonDbAndroid_nativeInsert(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    key: JString,
    value: JString,
    arpi: JByteArray,
) -> jint {
    let db = handle as *mut super::ffi::DbHandle;

    let key_str: String = match env.get_string(&key) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let value_str: String = match env.get_string(&value) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };

    // Accept exactly one canonical mobile provenance header.
    let arpi_len = env.get_array_length(&arpi).unwrap_or(0) as usize;
    if arpi_len != super::ArpiHeader::SIZE {
        return -5;
    }
    let mut arpi_bytes = vec![0i8; arpi_len];
    if env.get_byte_array_region(&arpi, 0, &mut arpi_bytes).is_err() {
        return -6;
    }
    let arpi_u8: Vec<u8> = arpi_bytes.iter().map(|b| *b as u8).collect();

    let c_key = match std::ffi::CString::new(key_str) {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let c_val = match std::ffi::CString::new(value_str) {
        Ok(s) => s,
        Err(_) => return -2,
    };

    edisondb_insert(db, c_key.as_ptr(), c_val.as_ptr(), arpi_u8.as_ptr())
}

/// com.aieonyx.edisondb.EdisonDbAndroid.nativeQuery(handle, key): String?
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_aieonyx_edisondb_EdisonDbAndroid_nativeQuery(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    key: JString,
) -> jstring {
    let db = handle as *mut super::ffi::DbHandle;
    let key_str: String = match env.get_string(&key) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };
    let c_key = match std::ffi::CString::new(key_str) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let raw = edisondb_query(db, c_key.as_ptr());
    if raw.is_null() {
        return std::ptr::null_mut();
    }
    let result_str = std::ffi::CStr::from_ptr(raw)
        .to_str()
        .unwrap_or("");
    let jstr = env.new_string(result_str).unwrap_or_else(|_| {
        env.new_string("").unwrap()
    });
    edisondb_free_string(raw);
    jstr.into_raw()
}

/// com.aieonyx.edisondb.EdisonDbAndroid.nativeDelete(handle, key): Int
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_aieonyx_edisondb_EdisonDbAndroid_nativeDelete(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    key: JString,
) -> jint {
    let db = handle as *mut super::ffi::DbHandle;
    let key_str: String = match env.get_string(&key) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let c_key = match std::ffi::CString::new(key_str) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    edisondb_delete(db, c_key.as_ptr())
}
