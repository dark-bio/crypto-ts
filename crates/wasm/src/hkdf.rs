// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Key extraction and expansion with HKDF-SHA256.
//!
//! https://datatracker.ietf.org/doc/html/rfc5869

use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// Maximum HKDF-SHA256 output length in bytes, per RFC 5869.
const MAX_OUTPUT_LEN: usize = 255 * 32;

/// Derives up to 8160 bytes of key material from a secret, salt and context.
#[wasm_bindgen]
pub fn hkdf_key(
    secret: Vec<u8>,
    salt: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<js_sys::Uint8Array, JsError> {
    let secret = Zeroizing::new(secret);
    if out_len > MAX_OUTPUT_LEN {
        return Err(JsError::new("output length must be at most 8160 bytes"));
    }
    let key = darkbio_crypto::hkdf::key_with_len(&secret, salt, info, out_len);
    Ok(js_sys::Uint8Array::from(&key[..]))
}

/// Extracts a pseudorandom key for use with [`hkdf_expand`].
#[wasm_bindgen]
pub fn hkdf_extract(secret: Vec<u8>, salt: &[u8]) -> js_sys::Uint8Array {
    let secret = Zeroizing::new(secret);
    let prk = darkbio_crypto::hkdf::extract(&secret, salt);
    js_sys::Uint8Array::from(&prk[..])
}

/// Expands a 32-byte pseudorandom key into up to 8160 bytes of key material.
#[wasm_bindgen]
pub fn hkdf_expand(
    prk: Vec<u8>,
    info: &[u8],
    out_len: usize,
) -> Result<js_sys::Uint8Array, JsError> {
    let prk = Zeroizing::new(prk);
    if out_len > MAX_OUTPUT_LEN {
        return Err(JsError::new("output length must be at most 8160 bytes"));
    }
    let prk: &[u8; 32] = prk
        .as_slice()
        .try_into()
        .map_err(|_| JsError::new("prk must be 32 bytes"))?;
    let key = darkbio_crypto::hkdf::expand_with_len(prk, info, out_len);
    Ok(js_sys::Uint8Array::from(&key[..]))
}
