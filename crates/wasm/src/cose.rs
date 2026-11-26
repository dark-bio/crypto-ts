// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! COSE wrappers for xDSA and xHPKE.
//!
//! https://datatracker.ietf.org/doc/html/rfc9052
//! https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke

use darkbio_crypto::{cbor, cose};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::cbor::Encoded;
use crate::xdsa::{XdsaFingerprint, XdsaPublicKey, XdsaSecretKey};
use crate::xhpke::{XhpkeFingerprint, XhpkePublicKey, XhpkeSecretKey};

/// Opaque padding policy for a single sealing call.
#[wasm_bindgen]
pub struct CosePadding {
    /// Policy applied before encryption.
    inner: cose::Padding,
}

#[wasm_bindgen]
impl CosePadding {
    /// Creates a policy that adds no padding.
    pub fn none() -> Self {
        Self {
            inner: cose::Padding::None,
        }
    }

    /// Pads to the smallest bucket that fits the signed envelope.
    ///
    /// Sizes start at `floor` bytes and grow by the current size divided by
    /// `step`, rounded up.
    pub fn buckets(floor: usize, step: usize) -> Self {
        Self {
            inner: cose::Padding::Buckets { floor, step },
        }
    }
}

/// Checks that an encoded payload contains one canonical CBOR item.
fn payload(bytes: &[u8]) -> Result<Encoded<'_>, JsError> {
    cbor::verify(bytes).map_err(|e| JsError::new(&format!("invalid payload CBOR: {e}")))?;
    Ok(Encoded(bytes))
}

/// Checks that the external authenticated data contains one canonical CBOR item.
fn aad(bytes: &[u8]) -> Result<Encoded<'_>, JsError> {
    cbor::verify(bytes).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {e}")))?;
    Ok(Encoded(bytes))
}

/// Copies a decoded payload to JavaScript after checking its CBOR encoding.
fn copy_payload(raw: cbor::Raw) -> Result<js_sys::Uint8Array, JsError> {
    let bytes = Zeroizing::new(raw.0);
    payload(&bytes)?;
    Ok(js_sys::Uint8Array::from(&bytes[..]))
}

/// Signs an embedded payload using the current system time.
#[wasm_bindgen]
pub fn cose_sign(
    msg_to_embed: Vec<u8>,
    msg_to_auth: Vec<u8>,
    signer: &XdsaSecretKey,
    domain: &[u8],
) -> Result<js_sys::Uint8Array, JsError> {
    let bytes = Zeroizing::new(msg_to_embed);
    let auth = Zeroizing::new(msg_to_auth);
    let signed = cose::sign(payload(&bytes)?, aad(&auth)?, &signer.inner, domain)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(js_sys::Uint8Array::from(&Zeroizing::new(signed)[..]))
}

/// Signs an embedded payload with the supplied Unix timestamp in seconds.
#[wasm_bindgen]
pub fn cose_sign_at(
    msg_to_embed: Vec<u8>,
    msg_to_auth: Vec<u8>,
    signer: &XdsaSecretKey,
    domain: &[u8],
    timestamp: i64,
) -> Result<js_sys::Uint8Array, JsError> {
    let bytes = Zeroizing::new(msg_to_embed);
    let auth = Zeroizing::new(msg_to_auth);
    let signed = cose::sign_at(
        payload(&bytes)?,
        aad(&auth)?,
        &signer.inner,
        domain,
        timestamp,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(js_sys::Uint8Array::from(&Zeroizing::new(signed)[..]))
}

/// Creates a COSE_Sign1 signature without an embedded payload (detached mode).
#[wasm_bindgen]
pub fn cose_sign_detached(
    msg_to_auth: Vec<u8>,
    signer: &XdsaSecretKey,
    domain: &[u8],
) -> Result<Vec<u8>, JsError> {
    let auth = Zeroizing::new(msg_to_auth);
    cose::sign_detached(aad(&auth)?, &signer.inner, domain)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Signs a detached payload with the supplied Unix timestamp in seconds.
#[wasm_bindgen]
pub fn cose_sign_detached_at(
    msg_to_auth: Vec<u8>,
    signer: &XdsaSecretKey,
    domain: &[u8],
    timestamp: i64,
) -> Result<Vec<u8>, JsError> {
    let auth = Zeroizing::new(msg_to_auth);
    cose::sign_detached_at(aad(&auth)?, &signer.inner, domain, timestamp)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Verifies a COSE_Sign1 signature and returns the embedded payload.
#[wasm_bindgen]
pub fn cose_verify(
    msg_to_check: Vec<u8>,
    msg_to_auth: Vec<u8>,
    verifier: &XdsaPublicKey,
    domain: &[u8],
    max_drift_secs: Option<u64>,
) -> Result<js_sys::Uint8Array, JsError> {
    let signed = Zeroizing::new(msg_to_check);
    let auth = Zeroizing::new(msg_to_auth);
    let raw = cose::verify(
        &signed,
        aad(&auth)?,
        &verifier.inner,
        domain,
        max_drift_secs,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    copy_payload(raw)
}

/// Verifies an embedded payload against the supplied Unix time in seconds.
#[wasm_bindgen]
pub fn cose_verify_at(
    msg_to_check: Vec<u8>,
    msg_to_auth: Vec<u8>,
    verifier: &XdsaPublicKey,
    domain: &[u8],
    max_drift_secs: Option<u64>,
    now: i64,
) -> Result<js_sys::Uint8Array, JsError> {
    let signed = Zeroizing::new(msg_to_check);
    let auth = Zeroizing::new(msg_to_auth);
    let raw = cose::verify_at(
        &signed,
        aad(&auth)?,
        &verifier.inner,
        domain,
        max_drift_secs,
        now,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    copy_payload(raw)
}

/// Verifies a COSE_Sign1 signature with a detached payload.
#[wasm_bindgen]
pub fn cose_verify_detached(
    msg_to_check: &[u8],
    msg_to_auth: Vec<u8>,
    verifier: &XdsaPublicKey,
    domain: &[u8],
    max_drift_secs: Option<u64>,
) -> Result<(), JsError> {
    let auth = Zeroizing::new(msg_to_auth);
    cose::verify_detached(
        msg_to_check,
        aad(&auth)?,
        &verifier.inner,
        domain,
        max_drift_secs,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Verifies a detached payload against the supplied Unix time in seconds.
#[wasm_bindgen]
pub fn cose_verify_detached_at(
    msg_to_check: &[u8],
    msg_to_auth: Vec<u8>,
    verifier: &XdsaPublicKey,
    domain: &[u8],
    max_drift_secs: Option<u64>,
    now: i64,
) -> Result<(), JsError> {
    let auth = Zeroizing::new(msg_to_auth);
    cose::verify_detached_at(
        msg_to_check,
        aad(&auth)?,
        &verifier.inner,
        domain,
        max_drift_secs,
        now,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Extracts the signer's fingerprint without verifying the signature.
#[wasm_bindgen]
pub fn cose_signer(signature: Vec<u8>) -> Result<XdsaFingerprint, JsError> {
    let signature = Zeroizing::new(signature);
    let fp = cose::signer(&signature).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(XdsaFingerprint { inner: fp })
}

/// Extracts a canonical CBOR payload without verifying the signature.
#[wasm_bindgen]
pub fn cose_peek(signature: Vec<u8>) -> Result<js_sys::Uint8Array, JsError> {
    let signature = Zeroizing::new(signature);
    let raw = cose::peek(&signature).map_err(|e| JsError::new(&e.to_string()))?;
    copy_payload(raw)
}

/// Extracts the recipient's fingerprint from a COSE_Encrypt0 without decrypting.
#[wasm_bindgen]
pub fn cose_recipient(ciphertext: &[u8]) -> Result<XhpkeFingerprint, JsError> {
    let fp = cose::recipient(ciphertext).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(XhpkeFingerprint { inner: fp })
}

/// Signs and encrypts a payload, wiping the binding's plaintext buffer.
#[wasm_bindgen]
pub fn cose_seal(
    msg_to_seal: Vec<u8>,
    msg_to_auth: Vec<u8>,
    signer: &XdsaSecretKey,
    recipient: &XhpkePublicKey,
    domain: &[u8],
    padding: &CosePadding,
) -> Result<Vec<u8>, JsError> {
    let bytes = Zeroizing::new(msg_to_seal);
    let auth = Zeroizing::new(msg_to_auth);
    cose::seal(
        payload(&bytes)?,
        aad(&auth)?,
        &signer.inner,
        &recipient.inner,
        domain,
        &padding.inner,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Signs and encrypts a payload with the supplied Unix timestamp in seconds.
#[wasm_bindgen]
pub fn cose_seal_at(
    msg_to_seal: Vec<u8>,
    msg_to_auth: Vec<u8>,
    signer: &XdsaSecretKey,
    recipient: &XhpkePublicKey,
    domain: &[u8],
    padding: &CosePadding,
    timestamp: i64,
) -> Result<Vec<u8>, JsError> {
    let bytes = Zeroizing::new(msg_to_seal);
    let auth = Zeroizing::new(msg_to_auth);
    cose::seal_at(
        payload(&bytes)?,
        aad(&auth)?,
        &signer.inner,
        &recipient.inner,
        domain,
        &padding.inner,
        timestamp,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Decrypts and verifies a sealed payload using the current system time.
#[wasm_bindgen]
pub fn cose_open(
    msg_to_open: &[u8],
    msg_to_auth: Vec<u8>,
    recipient: &XhpkeSecretKey,
    sender: &XdsaPublicKey,
    domain: &[u8],
    max_drift_secs: Option<u64>,
) -> Result<js_sys::Uint8Array, JsError> {
    let auth = Zeroizing::new(msg_to_auth);
    let raw = cose::open(
        msg_to_open,
        aad(&auth)?,
        &recipient.inner,
        &sender.inner,
        domain,
        max_drift_secs,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    copy_payload(raw)
}

/// Decrypts and verifies a sealed payload against the supplied Unix time in seconds.
#[wasm_bindgen]
pub fn cose_open_at(
    msg_to_open: &[u8],
    msg_to_auth: Vec<u8>,
    recipient: &XhpkeSecretKey,
    sender: &XdsaPublicKey,
    domain: &[u8],
    max_drift_secs: Option<u64>,
    now: i64,
) -> Result<js_sys::Uint8Array, JsError> {
    let auth = Zeroizing::new(msg_to_auth);
    let raw = cose::open_at(
        msg_to_open,
        aad(&auth)?,
        &recipient.inner,
        &sender.inner,
        domain,
        max_drift_secs,
        now,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    copy_payload(raw)
}

/// Encrypts a signed envelope and wipes the binding's copy of its plaintext.
#[wasm_bindgen]
pub fn cose_encrypt(
    sign1: Vec<u8>,
    msg_to_auth: Vec<u8>,
    recipient: &XhpkePublicKey,
    domain: &[u8],
    padding: &CosePadding,
) -> Result<Vec<u8>, JsError> {
    let sign1 = Zeroizing::new(sign1);
    let auth = Zeroizing::new(msg_to_auth);
    cose::encrypt(
        &sign1,
        aad(&auth)?,
        &recipient.inner,
        domain,
        &padding.inner,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Decrypts a signed envelope and strips its padding without verifying it.
#[wasm_bindgen]
pub fn cose_decrypt(
    msg_to_open: &[u8],
    msg_to_auth: Vec<u8>,
    recipient: &XhpkeSecretKey,
    domain: &[u8],
) -> Result<js_sys::Uint8Array, JsError> {
    let auth = Zeroizing::new(msg_to_auth);
    let sign1 = Zeroizing::new(
        cose::decrypt(msg_to_open, aad(&auth)?, &recipient.inner, domain)
            .map_err(|e| JsError::new(&e.to_string()))?,
    );
    Ok(js_sys::Uint8Array::from(&sign1[..]))
}
