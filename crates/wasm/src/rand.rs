// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use wasm_bindgen::prelude::*;

/// Maximum size of a single randomness request (64 MiB). Far beyond any key or
/// nonce material need; absurd sizes (including negative JS numbers coerced to
/// huge unsigned values) fail cleanly instead of aborting the instance on
/// allocation failure.
const MAX_OUTPUT_LEN: usize = 64 * 1024 * 1024;

/// Generates a buffer of up to 64 MiB filled with randomness.
#[wasm_bindgen]
pub fn rand_generate(bytes: usize) -> Result<Vec<u8>, JsError> {
    if bytes > MAX_OUTPUT_LEN {
        return Err(JsError::new(
            "requested size must be at most 67108864 bytes",
        ));
    }
    Ok(darkbio_crypto::rand::generate(bytes))
}
