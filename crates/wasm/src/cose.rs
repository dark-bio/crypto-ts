// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! COSE wrappers for xDSA and xHPKE.
//!
//! https://datatracker.ietf.org/doc/html/rfc8152
//! https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke

use darkbio_crypto::{cbor, cose};
use wasm_bindgen::prelude::*;

use crate::xdsa::{XdsaFingerprint, XdsaPublicKey, XdsaSecretKey};
use crate::xhpke::{XhpkeFingerprint, XhpkePublicKey, XhpkeSecretKey};

/// Creates a COSE_Sign1 signature with an embedded payload.
#[wasm_bindgen]
pub fn cose_sign(
    msg_to_embed: &[u8],
    msg_to_auth: &[u8],
    signer: &XdsaSecretKey,
    domain: &[u8],
) -> Result<Vec<u8>, JsError> {
    cbor::verify(msg_to_embed)
        .map_err(|e| JsError::new(&format!("invalid payload CBOR: {}", e)))?;
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    cose::sign(
        cbor::Raw(msg_to_embed.to_vec()),
        cbor::Raw(msg_to_auth.to_vec()),
        &signer.inner,
        domain,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Creates a COSE_Sign1 signature without an embedded payload (detached mode).
#[wasm_bindgen]
pub fn cose_sign_detached(
    msg_to_auth: &[u8],
    signer: &XdsaSecretKey,
    domain: &[u8],
) -> Result<Vec<u8>, JsError> {
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    cose::sign_detached(cbor::Raw(msg_to_auth.to_vec()), &signer.inner, domain)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Verifies a COSE_Sign1 signature and returns the embedded payload.
#[wasm_bindgen]
pub fn cose_verify(
    msg_to_check: &[u8],
    msg_to_auth: &[u8],
    verifier: &XdsaPublicKey,
    domain: &[u8],
    max_drift_secs: Option<u64>,
) -> Result<Vec<u8>, JsError> {
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    let raw: cbor::Raw = cose::verify(
        msg_to_check,
        cbor::Raw(msg_to_auth.to_vec()),
        &verifier.inner,
        domain,
        max_drift_secs,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    cbor::verify(&raw.0).map_err(|e| JsError::new(&format!("invalid payload CBOR: {}", e)))?;
    Ok(raw.0)
}

/// Verifies a COSE_Sign1 signature with a detached payload.
#[wasm_bindgen]
pub fn cose_verify_detached(
    msg_to_check: &[u8],
    msg_to_auth: &[u8],
    verifier: &XdsaPublicKey,
    domain: &[u8],
    max_drift_secs: Option<u64>,
) -> Result<(), JsError> {
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    cose::verify_detached(
        msg_to_check,
        cbor::Raw(msg_to_auth.to_vec()),
        &verifier.inner,
        domain,
        max_drift_secs,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Extracts the signer's fingerprint from a COSE_Sign1 without verifying.
#[wasm_bindgen]
pub fn cose_signer(signature: &[u8]) -> Result<XdsaFingerprint, JsError> {
    let fp = cose::signer(signature).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(XdsaFingerprint { inner: fp })
}

/// Extracts the embedded payload from a COSE_Sign1 without verifying.
#[wasm_bindgen]
pub fn cose_peek(signature: &[u8]) -> Result<Vec<u8>, JsError> {
    let raw: cbor::Raw = cose::peek(signature).map_err(|e| JsError::new(&e.to_string()))?;
    cbor::verify(&raw.0).map_err(|e| JsError::new(&format!("invalid payload CBOR: {}", e)))?;
    Ok(raw.0)
}

/// Extracts the recipient's fingerprint from a COSE_Encrypt0 without decrypting.
#[wasm_bindgen]
pub fn cose_recipient(ciphertext: &[u8]) -> Result<XhpkeFingerprint, JsError> {
    let fp = cose::recipient(ciphertext).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(XhpkeFingerprint { inner: fp })
}

/// Signs a message then encrypts it to a recipient (sign-then-encrypt).
#[wasm_bindgen]
pub fn cose_seal(
    msg_to_seal: &[u8],
    msg_to_auth: &[u8],
    signer: &XdsaSecretKey,
    recipient: &XhpkePublicKey,
    domain: &[u8],
) -> Result<Vec<u8>, JsError> {
    cbor::verify(msg_to_seal).map_err(|e| JsError::new(&format!("invalid payload CBOR: {}", e)))?;
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    cose::seal(
        cbor::Raw(msg_to_seal.to_vec()),
        cbor::Raw(msg_to_auth.to_vec()),
        &signer.inner,
        &recipient.inner,
        domain,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Decrypts and verifies a sealed message.
#[wasm_bindgen]
pub fn cose_open(
    msg_to_open: &[u8],
    msg_to_auth: &[u8],
    recipient: &XhpkeSecretKey,
    sender: &XdsaPublicKey,
    domain: &[u8],
    max_drift_secs: Option<u64>,
) -> Result<Vec<u8>, JsError> {
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    let raw: cbor::Raw = cose::open(
        msg_to_open,
        cbor::Raw(msg_to_auth.to_vec()),
        &recipient.inner,
        &sender.inner,
        domain,
        max_drift_secs,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    cbor::verify(&raw.0).map_err(|e| JsError::new(&format!("invalid payload CBOR: {}", e)))?;
    Ok(raw.0)
}

/// Encrypts an already-signed COSE_Sign1 to a recipient.
#[wasm_bindgen]
pub fn cose_encrypt(
    sign1: &[u8],
    msg_to_auth: &[u8],
    recipient: &XhpkePublicKey,
    domain: &[u8],
) -> Result<Vec<u8>, JsError> {
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    cose::encrypt(
        sign1,
        cbor::Raw(msg_to_auth.to_vec()),
        &recipient.inner,
        domain,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Decrypts a sealed message without verifying the signature.
#[wasm_bindgen]
pub fn cose_decrypt(
    msg_to_open: &[u8],
    msg_to_auth: &[u8],
    recipient: &XhpkeSecretKey,
    domain: &[u8],
) -> Result<Vec<u8>, JsError> {
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    cose::decrypt(
        msg_to_open,
        cbor::Raw(msg_to_auth.to_vec()),
        &recipient.inner,
        domain,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}
