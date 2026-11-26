// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Validation and encoding of CBOR bytes supplied by JavaScript.

use darkbio_crypto::cbor;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// Encoded CBOR item borrowed from its owner's buffer.
pub(crate) struct Encoded<'a>(pub(crate) &'a [u8]);

impl cbor::Encode for Encoded<'_> {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), cbor::Error> {
        buf.extend_from_slice(self.0);
        Ok(())
    }
}

/// Verifies that data is valid CBOR using the restricted type system.
#[wasm_bindgen]
pub fn cbor_verify(data: Vec<u8>) -> Result<(), JsError> {
    let data = Zeroizing::new(data);
    cbor::verify(&data).map_err(|e| JsError::new(&e.to_string()))
}
