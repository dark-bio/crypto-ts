// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Composite ML-DSA and Ed25519 signatures for JavaScript callers.
//!
//! https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs

use darkbio_crypto::xdsa;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

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
    /// Signing key owned by this handle.
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

    /// Creates a private key from a 64-byte seed, wiping the seed from WASM
    /// memory before return.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<XdsaSecretKey, JsError> {
        let bytes = Zeroizing::new(bytes);
        let seed: &[u8; xdsa::SECRET_KEY_SIZE] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| JsError::new("secret key must be 64 bytes"))?;
        Ok(Self {
            inner: xdsa::SecretKey::from_bytes(seed),
        })
    }

    /// Parses a secret key from PEM format, wiping the PEM from WASM memory
    /// before return.
    pub fn from_pem(pem: String) -> Result<XdsaSecretKey, JsError> {
        let pem = Zeroizing::new(pem);
        Ok(Self {
            inner: xdsa::SecretKey::from_pem(&pem).map_err(|e| JsError::new(&e.to_string()))?,
        })
    }

    /// Exports the 64-byte seed to a JavaScript byte array.
    pub fn to_bytes(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.inner.to_bytes()[..])
    }

    /// Exports the PEM-encoded secret key to a JavaScript string.
    pub fn to_pem(&self) -> js_sys::JsString {
        js_sys::JsString::from(self.inner.to_pem().as_str())
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

    /// Signs a message with fresh randomness for the ML-DSA component.
    pub fn sign(&self, message: Vec<u8>) -> XdsaSignature {
        let message = Zeroizing::new(message);
        XdsaSignature {
            inner: self.inner.sign(&message),
        }
    }
}

/// Opaque xDSA public key. Key material stays inside WASM memory.
#[wasm_bindgen]
pub struct XdsaPublicKey {
    /// Verification key owned by this handle.
    pub(crate) inner: xdsa::PublicKey,
}

#[wasm_bindgen]
impl XdsaPublicKey {
    /// Creates a public key from a 1984-byte array.
    pub fn from_bytes(bytes: &[u8]) -> Result<XdsaPublicKey, JsError> {
        let key: &[u8; xdsa::PUBLIC_KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| JsError::new("public key must be 1984 bytes"))?;
        Ok(Self {
            inner: xdsa::PublicKey::from_bytes(key).map_err(|e| JsError::new(&e.to_string()))?,
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
    pub fn verify(&self, message: Vec<u8>, signature: &XdsaSignature) -> bool {
        let message = Zeroizing::new(message);
        self.inner.verify(&message, &signature.inner).is_ok()
    }
}

/// Opaque xDSA signature.
#[wasm_bindgen]
pub struct XdsaSignature {
    /// Composite signature owned by this handle.
    inner: xdsa::Signature,
}

#[wasm_bindgen]
impl XdsaSignature {
    /// Creates a signature from a 3373-byte array.
    pub fn from_bytes(bytes: &[u8]) -> Result<XdsaSignature, JsError> {
        let signature: &[u8; xdsa::SIGNATURE_SIZE] = bytes
            .try_into()
            .map_err(|_| JsError::new("signature must be 3373 bytes"))?;
        Ok(Self {
            inner: xdsa::Signature::from_bytes(signature),
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
    /// Key fingerprint owned by this handle.
    pub(crate) inner: xdsa::Fingerprint,
}

#[wasm_bindgen]
impl XdsaFingerprint {
    /// Creates a fingerprint from a 32-byte array.
    pub fn from_bytes(bytes: &[u8]) -> Result<XdsaFingerprint, JsError> {
        let fingerprint: &[u8; xdsa::FINGERPRINT_SIZE] = bytes
            .try_into()
            .map_err(|_| JsError::new("fingerprint must be 32 bytes"))?;
        Ok(Self {
            inner: xdsa::Fingerprint::from_bytes(fingerprint),
        })
    }

    /// Serializes the fingerprint to a 32-byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}
