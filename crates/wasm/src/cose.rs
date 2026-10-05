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
use zeroize::{Zeroize, Zeroizing};

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

/// Extracts the signer's fingerprint from a COSE_Sign1 without verifying. The
/// binding's own copy of the signed message is wiped before return.
#[wasm_bindgen]
pub fn cose_signer(signature: Vec<u8>) -> Result<XdsaFingerprint, JsError> {
    let signature = Zeroizing::new(signature);
    let fp = cose::signer(&signature).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(XdsaFingerprint { inner: fp })
}

/// Extracts the embedded payload from a COSE_Sign1 without verifying. The
/// payload is copied straight into JS memory and the binding's own copies are
/// wiped; copies made inside crypto-rs are outside its reach.
#[wasm_bindgen]
pub fn cose_peek(signature: Vec<u8>) -> Result<js_sys::Uint8Array, JsError> {
    let signature = Zeroizing::new(signature);
    let raw: cbor::Raw = cose::peek(&signature).map_err(|e| JsError::new(&e.to_string()))?;
    let payload = Zeroizing::new(raw.0);
    cbor::verify(&payload).map_err(|e| JsError::new(&format!("invalid payload CBOR: {}", e)))?;
    Ok(js_sys::Uint8Array::from(&payload[..]))
}

/// Extracts the recipient's fingerprint from a COSE_Encrypt0 without decrypting.
#[wasm_bindgen]
pub fn cose_recipient(ciphertext: &[u8]) -> Result<XhpkeFingerprint, JsError> {
    let fp = cose::recipient(ciphertext).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(XhpkeFingerprint { inner: fp })
}

/// Signs a plaintext for sealing, so TypeScript can validate its padded size
/// before encryption. The binding's plaintext and signature copies are wiped;
/// copies made inside crypto-rs are outside its reach.
#[wasm_bindgen]
pub fn cose_prepare_seal(
    msg_to_seal: Vec<u8>,
    msg_to_auth: &[u8],
    signer: &XdsaSecretKey,
    domain: &[u8],
) -> Result<js_sys::Uint8Array, JsError> {
    // Wipe the input on both success and failure, then guard the signed copy
    let mut plaintext = cbor::Raw(msg_to_seal);
    let result = sign_for_seal(&plaintext, msg_to_auth, signer, domain);
    plaintext.0.zeroize();
    let sign1 = Zeroizing::new(result?);
    Ok(js_sys::Uint8Array::from(&sign1[..]))
}

/// Validates and signs a borrowed plaintext that the caller wipes afterwards.
fn sign_for_seal(
    plaintext: &cbor::Raw,
    msg_to_auth: &[u8],
    signer: &XdsaSecretKey,
    domain: &[u8],
) -> Result<Vec<u8>, JsError> {
    // Validate both messages before producing the signature
    cbor::verify(&plaintext.0)
        .map_err(|e| JsError::new(&format!("invalid payload CBOR: {}", e)))?;
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    cose::sign(
        plaintext,
        cbor::Raw(msg_to_auth.to_vec()),
        &signer.inner,
        domain,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Decrypts and verifies a sealed message. The plaintext is copied straight
/// into JS memory and the binding's own copy is wiped; copies made inside
/// crypto-rs are outside its reach.
#[wasm_bindgen]
pub fn cose_open(
    msg_to_open: &[u8],
    msg_to_auth: &[u8],
    recipient: &XhpkeSecretKey,
    sender: &XdsaPublicKey,
    domain: &[u8],
    max_drift_secs: Option<u64>,
) -> Result<js_sys::Uint8Array, JsError> {
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
    let plaintext = Zeroizing::new(raw.0);
    cbor::verify(&plaintext).map_err(|e| JsError::new(&format!("invalid payload CBOR: {}", e)))?;
    Ok(js_sys::Uint8Array::from(&plaintext[..]))
}

/// Encrypts a COSE_Sign1 to a recipient using the padded size validated by
/// TypeScript. The binding's copy of the signed message is wiped before return.
#[wasm_bindgen]
pub fn cose_encrypt(
    sign1: Vec<u8>,
    msg_to_auth: &[u8],
    recipient: &XhpkePublicKey,
    domain: &[u8],
    padded_len: usize,
) -> Result<Vec<u8>, JsError> {
    let sign1 = Zeroizing::new(sign1);
    if padded_len < sign1.len() || padded_len > i32::MAX as usize - 4096 {
        return Err(JsError::new("invalid padded plaintext size"));
    }
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    // The first bucket already fits, so Rust never repeats the size calculation
    let padding = if padded_len == sign1.len() {
        cose::Padding::None
    } else {
        cose::Padding::Buckets {
            floor: padded_len,
            step: 1,
        }
    };
    cose::encrypt(
        &sign1,
        cbor::Raw(msg_to_auth.to_vec()),
        &recipient.inner,
        domain,
        &padding,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Decrypts a sealed message without verifying the signature. The decrypted
/// COSE_Sign1 is copied straight into JS memory and the binding's own copy is
/// wiped; copies made inside crypto-rs are outside its reach.
#[wasm_bindgen]
pub fn cose_decrypt(
    msg_to_open: &[u8],
    msg_to_auth: &[u8],
    recipient: &XhpkeSecretKey,
    domain: &[u8],
) -> Result<js_sys::Uint8Array, JsError> {
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    let sign1 = Zeroizing::new(
        cose::decrypt(
            msg_to_open,
            cbor::Raw(msg_to_auth.to_vec()),
            &recipient.inner,
            domain,
        )
        .map_err(|e| JsError::new(&e.to_string()))?,
    );
    Ok(js_sys::Uint8Array::from(&sign1[..]))
}
