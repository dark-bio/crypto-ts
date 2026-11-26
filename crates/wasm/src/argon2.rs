// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Password-based key derivation with Argon2id.
//!
//! https://datatracker.ietf.org/doc/html/rfc9106

use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// Minimum salt length in bytes, per the argon2 crate's hashing bounds.
const MIN_SALT_LEN: usize = 8;

/// Minimum memory cost per lane in KiB.
const MIN_MEMORY_KIB: u32 = 8;

/// Largest working memory allocation in KiB that fits the WASM address space.
const MAX_MEMORY_KIB: u32 = 2 * 1024 * 1024 - 1;

/// Maximum lane count at 8 KiB per lane.
const MAX_THREADS: u32 = MAX_MEMORY_KIB / 8;

/// Minimum output length in bytes, per the argon2 crate's Params bounds.
const MIN_OUTPUT_LEN: usize = 4;

/// Maximum output length in bytes, the largest single allocation on WASM's
/// 32-bit address space. A longer output could never be allocated.
const MAX_OUTPUT_LEN: usize = isize::MAX as usize;

/// Derives a key from a password and salt with the supplied Argon2id costs.
///
/// RFC 9106 Section 4 recommends time=1, memory=2 GiB and threads=4, or, where
/// that much memory is not available, time=3, memory=64 MiB and threads=4. The
/// first profile exceeds the WASM allocation limit. The `threads` parameter
/// sets the lane count and affects the derived key.
#[wasm_bindgen]
pub fn argon2_key(
    password: Vec<u8>,
    salt: &[u8],
    time: u32,
    memory: u32,
    threads: u32,
    out_len: usize,
) -> Result<js_sys::Uint8Array, JsError> {
    // Guard the password before checking any argument
    let password = Zeroizing::new(password);
    if salt.len() < MIN_SALT_LEN {
        return Err(JsError::new("salt must be at least 8 bytes"));
    }
    if memory < MIN_MEMORY_KIB {
        return Err(JsError::new("memory cost must be at least 8 KiB"));
    }
    if memory > MAX_MEMORY_KIB {
        return Err(JsError::new("memory cost must be at most 2097151 KiB"));
    }
    if time < 1 {
        return Err(JsError::new("time cost must be at least 1"));
    }
    if !(1..=MAX_THREADS).contains(&threads) {
        return Err(JsError::new("threads must be between 1 and 262143"));
    }
    if memory < MIN_MEMORY_KIB * threads {
        return Err(JsError::new(
            "memory cost must be at least 8 KiB per thread",
        ));
    }
    if out_len < MIN_OUTPUT_LEN {
        return Err(JsError::new("output length must be at least 4 bytes"));
    }
    if out_len > MAX_OUTPUT_LEN {
        return Err(JsError::new(
            "output length must be at most 2147483647 bytes",
        ));
    }

    // Copy the derived key into JavaScript before its WASM buffer is wiped
    let key = darkbio_crypto::argon2::key_with_len(&password, salt, time, memory, threads, out_len);
    Ok(js_sys::Uint8Array::from(&key[..]))
}
