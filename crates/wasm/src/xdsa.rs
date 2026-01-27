// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Composite ML-DSA cryptography wrappers and parametrization.
//!
//! https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs

use darkbio_crypto::xdsa;
use wasm_bindgen::prelude::*;

/// Size of the secret key in bytes.
/// Format: ML-DSA seed (32 bytes) || Ed25519 seed (32 bytes)
#[wasm_bindgen]
pub fn xdsa_secret_key_size() -> usize {
    xdsa::SECRET_KEY_SIZE
}

/// Size of the public key in bytes.
/// Format: ML-DSA (1952 bytes) || Ed25519 (32 bytes)
#[wasm_bindgen]
pub fn xdsa_public_key_size() -> usize {
    xdsa::PUBLIC_KEY_SIZE
}

/// Size of a composite signature in bytes.
/// Format: ML-DSA (3309 bytes) || Ed25519 (64 bytes)
#[wasm_bindgen]
pub fn xdsa_signature_size() -> usize {
    xdsa::SIGNATURE_SIZE
}

/// Size of a key fingerprint in bytes.
#[wasm_bindgen]
pub fn xdsa_fingerprint_size() -> usize {
    xdsa::FINGERPRINT_SIZE
}

/// Generates a new random private key.
#[wasm_bindgen]
pub fn xdsa_generate() -> Vec<u8> {
    xdsa::SecretKey::generate().to_bytes().to_vec()
}

/// Derives the public key from a secret key.
#[wasm_bindgen]
pub fn xdsa_public_key(secret_key: &[u8]) -> Result<Vec<u8>, JsError> {
    let seed: [u8; 64] = secret_key
        .try_into()
        .map_err(|_| JsError::new("secret key must be 64 bytes"))?;
    let sk = xdsa::SecretKey::from_bytes(&seed);
    Ok(sk.public_key().to_bytes().to_vec())
}

/// Computes the fingerprint (SHA-256 hash) of a public key.
#[wasm_bindgen]
pub fn xdsa_fingerprint(public_key: &[u8]) -> Result<Vec<u8>, JsError> {
    let bytes: [u8; 1984] = public_key
        .try_into()
        .map_err(|_| JsError::new("public key must be 1984 bytes"))?;
    let pk = xdsa::PublicKey::from_bytes(&bytes).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(pk.fingerprint().to_bytes().to_vec())
}

/// Signs a message with a secret key.
#[wasm_bindgen]
pub fn xdsa_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsError> {
    let seed: [u8; 64] = secret_key
        .try_into()
        .map_err(|_| JsError::new("secret key must be 64 bytes"))?;
    let sk = xdsa::SecretKey::from_bytes(&seed);
    Ok(sk.sign(message).to_bytes().to_vec())
}

/// Verifies a signature on a message with a public key.
#[wasm_bindgen]
pub fn xdsa_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsError> {
    let pk_bytes: [u8; 1984] = public_key
        .try_into()
        .map_err(|_| JsError::new("public key must be 1984 bytes"))?;
    let sig_bytes: [u8; 3373] = signature
        .try_into()
        .map_err(|_| JsError::new("signature must be 3373 bytes"))?;

    let pk = xdsa::PublicKey::from_bytes(&pk_bytes).map_err(|e| JsError::new(&e.to_string()))?;
    let sig = xdsa::Signature::from_bytes(&sig_bytes);

    match pk.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Parses a secret key from PEM format.
#[wasm_bindgen]
pub fn xdsa_secret_key_from_pem(pem: &str) -> Result<Vec<u8>, JsError> {
    let sk = xdsa::SecretKey::from_pem(pem).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(sk.to_bytes().to_vec())
}

/// Serializes a secret key to PEM format.
#[wasm_bindgen]
pub fn xdsa_secret_key_to_pem(secret_key: &[u8]) -> Result<String, JsError> {
    let seed: [u8; 64] = secret_key
        .try_into()
        .map_err(|_| JsError::new("secret key must be 64 bytes"))?;
    let sk = xdsa::SecretKey::from_bytes(&seed);
    Ok(sk.to_pem())
}

/// Parses a public key from PEM format.
#[wasm_bindgen]
pub fn xdsa_public_key_from_pem(pem: &str) -> Result<Vec<u8>, JsError> {
    let pk = xdsa::PublicKey::from_pem(pem).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(pk.to_bytes().to_vec())
}

/// Serializes a public key to PEM format.
#[wasm_bindgen]
pub fn xdsa_public_key_to_pem(public_key: &[u8]) -> Result<String, JsError> {
    let bytes: [u8; 1984] = public_key
        .try_into()
        .map_err(|_| JsError::new("public key must be 1984 bytes"))?;
    let pk = xdsa::PublicKey::from_bytes(&bytes).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(pk.to_pem())
}

/// Parses a public key from a PEM-encoded X.509 certificate, verifying the signature.
/// Returns: public key (1984 bytes) || not_before (8 bytes BE) || not_after (8 bytes BE)
#[wasm_bindgen]
pub fn xdsa_public_key_from_cert_pem(pem: &str, signer: &[u8]) -> Result<Vec<u8>, JsError> {
    let signer_bytes: [u8; 1984] = signer
        .try_into()
        .map_err(|_| JsError::new("signer must be 1984 bytes"))?;
    let signer_pk =
        xdsa::PublicKey::from_bytes(&signer_bytes).map_err(|e| JsError::new(&e.to_string()))?;

    let (pk, not_before, not_after) =
        xdsa::PublicKey::from_cert_pem(pem, signer_pk).map_err(|e| JsError::new(&e.to_string()))?;

    let mut result = Vec::with_capacity(1984 + 16);
    result.extend_from_slice(&pk.to_bytes());
    result.extend_from_slice(&not_before.to_be_bytes());
    result.extend_from_slice(&not_after.to_be_bytes());
    Ok(result)
}

/// Parses a public key from a DER-encoded X.509 certificate, verifying the signature.
/// Returns: public key (1984 bytes) || not_before (8 bytes BE) || not_after (8 bytes BE)
#[wasm_bindgen]
pub fn xdsa_public_key_from_cert_der(der: &[u8], signer: &[u8]) -> Result<Vec<u8>, JsError> {
    let signer_bytes: [u8; 1984] = signer
        .try_into()
        .map_err(|_| JsError::new("signer must be 1984 bytes"))?;
    let signer_pk =
        xdsa::PublicKey::from_bytes(&signer_bytes).map_err(|e| JsError::new(&e.to_string()))?;

    let (pk, not_before, not_after) = xdsa::PublicKey::from_cert_der(der, signer_pk)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let mut result = Vec::with_capacity(1984 + 16);
    result.extend_from_slice(&pk.to_bytes());
    result.extend_from_slice(&not_before.to_be_bytes());
    result.extend_from_slice(&not_after.to_be_bytes());
    Ok(result)
}

/// Generates a PEM-encoded X.509 certificate for a public key, signed by an issuer.
#[wasm_bindgen]
pub fn xdsa_public_key_to_cert_pem(
    public_key: &[u8],
    signer: &[u8],
    subject_name: &str,
    issuer_name: &str,
    not_before: u64,
    not_after: u64,
    is_ca: bool,
    path_len: Option<u8>,
) -> Result<String, JsError> {
    use darkbio_crypto::x509;

    let pk_bytes: [u8; 1984] = public_key
        .try_into()
        .map_err(|_| JsError::new("public key must be 1984 bytes"))?;
    let pk = xdsa::PublicKey::from_bytes(&pk_bytes).map_err(|e| JsError::new(&e.to_string()))?;

    let signer_seed: [u8; 64] = signer
        .try_into()
        .map_err(|_| JsError::new("signer must be 64 bytes"))?;
    let signer_sk = xdsa::SecretKey::from_bytes(&signer_seed);

    let params = x509::Params {
        subject_name,
        issuer_name,
        not_before,
        not_after,
        is_ca,
        path_len,
    };
    pk.to_cert_pem(&signer_sk, &params)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Generates a DER-encoded X.509 certificate for a public key, signed by an issuer.
#[wasm_bindgen]
pub fn xdsa_public_key_to_cert_der(
    public_key: &[u8],
    signer: &[u8],
    subject_name: &str,
    issuer_name: &str,
    not_before: u64,
    not_after: u64,
    is_ca: bool,
    path_len: Option<u8>,
) -> Result<Vec<u8>, JsError> {
    use darkbio_crypto::x509;

    let pk_bytes: [u8; 1984] = public_key
        .try_into()
        .map_err(|_| JsError::new("public key must be 1984 bytes"))?;
    let pk = xdsa::PublicKey::from_bytes(&pk_bytes).map_err(|e| JsError::new(&e.to_string()))?;

    let signer_seed: [u8; 64] = signer
        .try_into()
        .map_err(|_| JsError::new("signer must be 64 bytes"))?;
    let signer_sk = xdsa::SecretKey::from_bytes(&signer_seed);

    let params = x509::Params {
        subject_name,
        issuer_name,
        not_before,
        not_after,
        is_ca,
        path_len,
    };
    pk.to_cert_der(&signer_sk, &params)
        .map_err(|e| JsError::new(&e.to_string()))
}
