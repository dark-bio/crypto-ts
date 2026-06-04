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
#[wasm_bindgen]
pub fn xdsa_secret_key_size() -> usize {
    xdsa::SECRET_KEY_SIZE
}

/// Size of the public key in bytes.
#[wasm_bindgen]
pub fn xdsa_public_key_size() -> usize {
    xdsa::PUBLIC_KEY_SIZE
}

/// Size of a composite signature in bytes.
#[wasm_bindgen]
pub fn xdsa_signature_size() -> usize {
    xdsa::SIGNATURE_SIZE
}

/// Size of a key fingerprint in bytes.
#[wasm_bindgen]
pub fn xdsa_fingerprint_size() -> usize {
    xdsa::FINGERPRINT_SIZE
}

/// Opaque xDSA secret key. Key material stays inside WASM memory.
#[wasm_bindgen]
pub struct XdsaSecretKey {
    pub(crate) inner: xdsa::SecretKey,
}

#[wasm_bindgen]
impl XdsaSecretKey {
    /// Generates a new random private key.
    pub fn generate() -> Self {
        Self {
            inner: xdsa::SecretKey::generate(),
        }
    }

    /// Creates a private key from a 64-byte seed.
    pub fn from_bytes(bytes: &[u8]) -> Result<XdsaSecretKey, JsError> {
        let seed: [u8; 64] = bytes
            .try_into()
            .map_err(|_| JsError::new("secret key must be 64 bytes"))?;
        Ok(Self {
            inner: xdsa::SecretKey::from_bytes(&seed),
        })
    }

    /// Parses a secret key from PEM format.
    pub fn from_pem(pem: &str) -> Result<XdsaSecretKey, JsError> {
        Ok(Self {
            inner: xdsa::SecretKey::from_pem(pem).map_err(|e| JsError::new(&e.to_string()))?,
        })
    }

    /// Serializes the secret key to a 64-byte seed.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Serializes the secret key to PEM format.
    pub fn to_pem(&self) -> String {
        self.inner.to_pem().to_string()
    }

    /// Returns the public key corresponding to this private key.
    pub fn public_key(&self) -> XdsaPublicKey {
        XdsaPublicKey {
            inner: self.inner.public_key(),
        }
    }

    /// Returns a 32-byte fingerprint uniquely identifying this key.
    pub fn fingerprint(&self) -> XdsaFingerprint {
        XdsaFingerprint {
            inner: self.inner.fingerprint(),
        }
    }

    /// Signs a message with this secret key.
    pub fn sign(&self, message: &[u8]) -> XdsaSignature {
        XdsaSignature {
            inner: self.inner.sign(message),
        }
    }
}

/// Opaque xDSA public key. Key material stays inside WASM memory.
#[wasm_bindgen]
pub struct XdsaPublicKey {
    pub(crate) inner: xdsa::PublicKey,
}

#[wasm_bindgen]
impl XdsaPublicKey {
    /// Creates a public key from a 1984-byte array.
    pub fn from_bytes(bytes: &[u8]) -> Result<XdsaPublicKey, JsError> {
        let arr: [u8; 1984] = bytes
            .try_into()
            .map_err(|_| JsError::new("public key must be 1984 bytes"))?;
        Ok(Self {
            inner: xdsa::PublicKey::from_bytes(&arr).map_err(|e| JsError::new(&e.to_string()))?,
        })
    }

    /// Parses a public key from PEM format.
    pub fn from_pem(pem: &str) -> Result<XdsaPublicKey, JsError> {
        Ok(Self {
            inner: xdsa::PublicKey::from_pem(pem).map_err(|e| JsError::new(&e.to_string()))?,
        })
    }

    /// Serializes the public key to a 1984-byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Serializes the public key to PEM format.
    pub fn to_pem(&self) -> String {
        self.inner.to_pem()
    }

    /// Returns a 32-byte fingerprint uniquely identifying this key.
    pub fn fingerprint(&self) -> XdsaFingerprint {
        XdsaFingerprint {
            inner: self.inner.fingerprint(),
        }
    }

    /// Verifies a signature on a message.
    pub fn verify(&self, message: &[u8], signature: &XdsaSignature) -> bool {
        self.inner.verify(message, &signature.inner).is_ok()
    }
}

/// Opaque xDSA signature.
#[wasm_bindgen]
pub struct XdsaSignature {
    inner: xdsa::Signature,
}

#[wasm_bindgen]
impl XdsaSignature {
    /// Creates a signature from a 3373-byte array.
    pub fn from_bytes(bytes: &[u8]) -> Result<XdsaSignature, JsError> {
        let arr: [u8; 3373] = bytes
            .try_into()
            .map_err(|_| JsError::new("signature must be 3373 bytes"))?;
        Ok(Self {
            inner: xdsa::Signature::from_bytes(&arr),
        })
    }

    /// Serializes the signature to a 3373-byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

/// Opaque xDSA fingerprint.
#[wasm_bindgen]
pub struct XdsaFingerprint {
    pub(crate) inner: xdsa::Fingerprint,
}

#[wasm_bindgen]
impl XdsaFingerprint {
    /// Creates a fingerprint from a 32-byte array.
    pub fn from_bytes(bytes: &[u8]) -> Result<XdsaFingerprint, JsError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| JsError::new("fingerprint must be 32 bytes"))?;
        Ok(Self {
            inner: xdsa::Fingerprint::from_bytes(&arr),
        })
    }

    /// Serializes the fingerprint to a 32-byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}
