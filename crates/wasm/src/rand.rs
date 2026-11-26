// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Random bytes for JavaScript callers.

use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// Maximum size of a single randomness request, in bytes.
const MAX_OUTPUT_LEN: usize = 64 * 1024 * 1024;

/// Generates up to 64 MiB of random bytes and wipes the WASM output buffer.
#[wasm_bindgen]
pub fn rand_generate(bytes: usize) -> Result<js_sys::Uint8Array, JsError> {
    if bytes > MAX_OUTPUT_LEN {
        return Err(JsError::new(
            "requested size must be at most 67108864 bytes",
        ));
    }
    let random = Zeroizing::new(darkbio_crypto::rand::generate(bytes));
    Ok(js_sys::Uint8Array::from(&random[..]))
}
