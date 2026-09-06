// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Argon2id cryptography wrappers and parametrization.
//!
//! https://datatracker.ietf.org/doc/html/rfc9106

use wasm_bindgen::prelude::*;

/// Minimum salt length in bytes, per the argon2 crate's hashing bounds.
const MIN_SALT_LEN: usize = 8;

/// Minimum memory cost in KiB (2 blocks per slice, 4 slices), per the argon2
/// crate's Params bounds.
const MIN_MEMORY_KIB: u32 = 8;

/// Maximum memory cost in KiB (2 GiB). Matches the RFC 9106 recommended upper
/// bound and keeps allocations within WASM's 32-bit address space; anything
/// larger would abort the instance on allocation failure instead of erroring.
const MAX_MEMORY_KIB: u32 = 2 * 1024 * 1024;

/// Maximum degree of parallelism. The argon2 crate rounds the memory cost up
/// to 8 blocks per lane, so the lane count must also respect the memory cap
/// (far above any real parallelism need either way).
const MAX_THREADS: u32 = MAX_MEMORY_KIB / 8;

/// Minimum output length in bytes, per the argon2 crate's Params bounds.
const MIN_OUTPUT_LEN: usize = 4;

/// Derives a key from the password, salt, and cost parameters using Argon2id,
/// returning a byte array that can be used as a cryptographic key. The CPU cost
/// and parallelism degree must be greater than zero.
///
/// RFC 9106 Section 7.4 recommends time=1, and memory=2048*1024 as a sensible
/// number. If using that amount of memory (2GB) is not possible in some contexts
/// then the time parameter can be increased to compensate.
///
/// The time parameter specifies the number of passes over the memory and the
/// memory parameter specifies the size of the memory in KiB. The number of threads
/// can be adjusted to the numbers of available CPUs. The cost parameters should be
/// increased as memory latency and CPU parallelism increases. Remember to get a
/// good random salt.
///
/// All parameters are validated up front: the underlying implementation panics
/// on invalid inputs, which inside WASM would trap and poison the instance.
#[wasm_bindgen]
pub fn argon2_key(
    password: &[u8],
    salt: &[u8],
    time: u32,
    memory: u32,
    threads: u32,
    out_len: usize,
) -> Result<Vec<u8>, JsError> {
    if salt.len() < MIN_SALT_LEN {
        return Err(JsError::new("salt must be at least 8 bytes"));
    }
    if memory < MIN_MEMORY_KIB {
        return Err(JsError::new("memory cost must be at least 8 KiB"));
    }
    if memory > MAX_MEMORY_KIB {
        return Err(JsError::new("memory cost must be at most 2097152 KiB"));
    }
    if time < 1 {
        return Err(JsError::new("time cost must be at least 1"));
    }
    if !(1..=MAX_THREADS).contains(&threads) {
        return Err(JsError::new("threads must be between 1 and 262144"));
    }
    if out_len < MIN_OUTPUT_LEN {
        return Err(JsError::new("output length must be at least 4 bytes"));
    }
    let key = darkbio_crypto::argon2::key_with_len(password, salt, time, memory, threads, out_len);
    Ok(key.to_vec())
}
