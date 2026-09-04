// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! CWT (CBOR Web Token) wrappers on top of COSE Sign1.
//!
//! https://datatracker.ietf.org/doc/html/rfc8392

use darkbio_crypto::{cbor, cwt};
use wasm_bindgen::prelude::*;

use crate::xdsa::{XdsaFingerprint, XdsaPublicKey, XdsaSecretKey};

/// Issues a CWT by signing pre-encoded CBOR claims with COSE Sign1.
#[wasm_bindgen]
pub fn cwt_issue(
    claims_cbor: &[u8],
    signer: &XdsaSecretKey,
    domain: &[u8],
) -> Result<Vec<u8>, JsError> {
    cbor::verify(claims_cbor).map_err(|e| JsError::new(&format!("invalid claims CBOR: {}", e)))?;

    cwt::issue(&cbor::Raw(claims_cbor.to_vec()), &signer.inner, domain)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Verifies a CWT's COSE signature and temporal validity, returning
/// the raw CBOR-encoded claims.
#[wasm_bindgen]
pub fn cwt_verify(
    token: &[u8],
    verifier: &XdsaPublicKey,
    domain: &[u8],
    now: Option<u64>,
) -> Result<Vec<u8>, JsError> {
    let raw: cbor::Raw = cwt::verify(token, &verifier.inner, domain, now)
        .map_err(|e| JsError::new(&e.to_string()))?;
    cbor::verify(&raw.0).map_err(|e| JsError::new(&format!("invalid payload CBOR: {}", e)))?;
    Ok(raw.0)
}

/// Extracts the signer's fingerprint from a CWT without verifying.
#[wasm_bindgen]
pub fn cwt_signer(token: &[u8]) -> Result<XdsaFingerprint, JsError> {
    let fp = cwt::signer(token).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(XdsaFingerprint { inner: fp })
}

/// Extracts and decodes claims from a CWT without verifying the signature.
#[wasm_bindgen]
pub fn cwt_peek(token: &[u8]) -> Result<Vec<u8>, JsError> {
    let raw: cbor::Raw = cwt::peek(token).map_err(|e| JsError::new(&e.to_string()))?;
    cbor::verify(&raw.0).map_err(|e| JsError::new(&format!("invalid payload CBOR: {}", e)))?;
    Ok(raw.0)
}
