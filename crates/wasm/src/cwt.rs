// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Issues and verifies CBOR Web Tokens signed with COSE_Sign1.

use darkbio_crypto::{cbor, cwt};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::cbor::Encoded;
use crate::xdsa::{XdsaFingerprint, XdsaPublicKey, XdsaSecretKey};

/// Signs a canonical claims map using the current system time.
#[wasm_bindgen]
pub fn cwt_issue(
    claims_cbor: Vec<u8>,
    signer: &XdsaSecretKey,
    domain: &[u8],
) -> Result<js_sys::Uint8Array, JsError> {
    let claims = Zeroizing::new(claims_cbor);
    let token = cwt::issue(&Encoded(&claims), &signer.inner, domain)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(js_sys::Uint8Array::from(&Zeroizing::new(token)[..]))
}

/// Signs a canonical claims map with the supplied Unix timestamp in seconds.
#[wasm_bindgen]
pub fn cwt_issue_at(
    claims_cbor: Vec<u8>,
    signer: &XdsaSecretKey,
    domain: &[u8],
    timestamp: i64,
) -> Result<js_sys::Uint8Array, JsError> {
    let claims = Zeroizing::new(claims_cbor);
    let token = cwt::issue_at(&Encoded(&claims), &signer.inner, domain, timestamp)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(js_sys::Uint8Array::from(&Zeroizing::new(token)[..]))
}

/// Verifies the signature and claims map, checking time bounds when requested.
#[wasm_bindgen]
pub fn cwt_verify(
    token: Vec<u8>,
    verifier: &XdsaPublicKey,
    domain: &[u8],
    now: Option<u64>,
) -> Result<js_sys::Uint8Array, JsError> {
    let token = Zeroizing::new(token);
    let raw: cbor::Raw = cwt::verify(&token, &verifier.inner, domain, now)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(js_sys::Uint8Array::from(&Zeroizing::new(raw.0)[..]))
}

/// Extracts the signer's fingerprint from a CWT without verifying.
#[wasm_bindgen]
pub fn cwt_signer(token: Vec<u8>) -> Result<XdsaFingerprint, JsError> {
    let token = Zeroizing::new(token);
    let fp = cwt::signer(&token).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(XdsaFingerprint { inner: fp })
}

/// Extracts and decodes claims from a CWT without verifying the signature.
#[wasm_bindgen]
pub fn cwt_peek(token: Vec<u8>) -> Result<js_sys::Uint8Array, JsError> {
    let token = Zeroizing::new(token);
    let raw: cbor::Raw = cwt::peek(&token).map_err(|e| JsError::new(&e.to_string()))?;
    let claims = Zeroizing::new(raw.0);

    // A raw peek extracts the payload without checking its claims map
    cbor::verify(&claims).map_err(|e| JsError::new(&format!("invalid payload CBOR: {e}")))?;
    cbor::Decoder::new(&claims)
        .decode_map_header()
        .map_err(|e| JsError::new(&format!("invalid claims map: {e}")))?;
    Ok(js_sys::Uint8Array::from(&claims[..]))
}
