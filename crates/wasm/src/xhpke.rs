// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! HPKE cryptography wrappers and parametrization.
//!
//! https://datatracker.ietf.org/doc/html/rfc9180

use darkbio_crypto::xhpke;
use wasm_bindgen::prelude::*;

/// Size of the secret key seed in bytes.
#[wasm_bindgen]
pub fn xhpke_secret_key_size() -> usize {
    xhpke::SECRET_KEY_SIZE
}

/// Size of the public key in bytes.
#[wasm_bindgen]
pub fn xhpke_public_key_size() -> usize {
    xhpke::PUBLIC_KEY_SIZE
}

/// Size of the encapsulated key in bytes.
#[wasm_bindgen]
pub fn xhpke_encap_key_size() -> usize {
    xhpke::ENCAP_KEY_SIZE
}

/// Size of the fingerprint in bytes.
#[wasm_bindgen]
pub fn xhpke_fingerprint_size() -> usize {
    xhpke::FINGERPRINT_SIZE
}

/// Opaque xHPKE secret key. Key material stays inside WASM memory.
#[wasm_bindgen]
pub struct XhpkeSecretKey {
    pub(crate) inner: xhpke::SecretKey,
}

#[wasm_bindgen]
impl XhpkeSecretKey {
    /// Generates a new random private key.
    pub fn generate() -> Self {
        Self {
            inner: xhpke::SecretKey::generate(),
        }
    }

    /// Creates a private key from a 32-byte seed.
    pub fn from_bytes(bytes: &[u8]) -> Result<XhpkeSecretKey, JsError> {
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| JsError::new("secret key must be 32 bytes"))?;
        Ok(Self {
            inner: xhpke::SecretKey::from_bytes(&seed),
        })
    }

    /// Parses a secret key from PEM format.
    pub fn from_pem(pem: &str) -> Result<XhpkeSecretKey, JsError> {
        Ok(Self {
            inner: xhpke::SecretKey::from_pem(pem).map_err(|e| JsError::new(&e.to_string()))?,
        })
    }

    /// Serializes the secret key to a 32-byte seed.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Serializes the secret key to PEM format.
    pub fn to_pem(&self) -> String {
        self.inner.to_pem().to_string()
    }

    /// Returns the public key corresponding to this private key.
    pub fn public_key(&self) -> XhpkePublicKey {
        XhpkePublicKey {
            inner: self.inner.public_key(),
        }
    }

    /// Returns a 32-byte fingerprint uniquely identifying this key.
    pub fn fingerprint(&self) -> XhpkeFingerprint {
        XhpkeFingerprint {
            inner: self.inner.fingerprint(),
        }
    }

    /// Creates an HPKE receiver context for multi-message decryption.
    pub fn new_receiver(&self, encap_key: &[u8], domain: &[u8]) -> Result<XhpkeReceiver, JsError> {
        let encap_key_array: [u8; 1120] = encap_key
            .try_into()
            .map_err(|_| JsError::new("encapsulated key must be 1120 bytes"))?;

        let receiver = self
            .inner
            .new_receiver(&encap_key_array, domain)
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(XhpkeReceiver { inner: receiver })
    }

    /// Decrypts a single-shot sealed message.
    /// Input: encapsulated key (1120 bytes) || ciphertext
    pub fn open(
        &self,
        sealed: &[u8],
        msg_to_auth: &[u8],
        domain: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        if sealed.len() < xhpke::ENCAP_KEY_SIZE {
            return Err(JsError::new("sealed data too short"));
        }
        let session_key: [u8; 1120] = sealed[..xhpke::ENCAP_KEY_SIZE]
            .try_into()
            .map_err(|_| JsError::new("invalid encapsulated key"))?;
        let ciphertext = &sealed[xhpke::ENCAP_KEY_SIZE..];

        self.inner
            .open(&session_key, ciphertext, msg_to_auth, domain)
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

/// Opaque xHPKE public key. Key material stays inside WASM memory.
#[wasm_bindgen]
pub struct XhpkePublicKey {
    pub(crate) inner: xhpke::PublicKey,
}

#[wasm_bindgen]
impl XhpkePublicKey {
    /// Creates a public key from a 1216-byte array.
    pub fn from_bytes(bytes: &[u8]) -> Result<XhpkePublicKey, JsError> {
        let arr: [u8; 1216] = bytes
            .try_into()
            .map_err(|_| JsError::new("public key must be 1216 bytes"))?;
        Ok(Self {
            inner: xhpke::PublicKey::from_bytes(&arr).map_err(|e| JsError::new(&e.to_string()))?,
        })
    }

    /// Parses a public key from PEM format.
    pub fn from_pem(pem: &str) -> Result<XhpkePublicKey, JsError> {
        Ok(Self {
            inner: xhpke::PublicKey::from_pem(pem).map_err(|e| JsError::new(&e.to_string()))?,
        })
    }

    /// Serializes the public key to a 1216-byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Serializes the public key to PEM format.
    pub fn to_pem(&self) -> String {
        self.inner.to_pem()
    }

    /// Returns a 32-byte fingerprint uniquely identifying this key.
    pub fn fingerprint(&self) -> XhpkeFingerprint {
        XhpkeFingerprint {
            inner: self.inner.fingerprint(),
        }
    }

    /// Creates an HPKE sender context for multi-message encryption.
    pub fn new_sender(&self, domain: &[u8]) -> Result<XhpkeSender, JsError> {
        let (sender, encap_key) = self
            .inner
            .new_sender(domain)
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(XhpkeSender {
            inner: sender,
            encap_key: encap_key.to_vec(),
        })
    }

    /// Encrypts a single-shot message to this public key.
    /// Returns: encapsulated key (1120 bytes) || ciphertext
    pub fn seal(
        &self,
        msg_to_seal: &[u8],
        msg_to_auth: &[u8],
        domain: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let (encap_key, ciphertext) = self
            .inner
            .seal(msg_to_seal, msg_to_auth, domain)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let mut result = Vec::with_capacity(encap_key.len() + ciphertext.len());
        result.extend_from_slice(&encap_key);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }
}

/// Opaque xHPKE fingerprint.
#[wasm_bindgen]
pub struct XhpkeFingerprint {
    pub(crate) inner: xhpke::Fingerprint,
}

#[wasm_bindgen]
impl XhpkeFingerprint {
    /// Creates a fingerprint from a 32-byte array.
    pub fn from_bytes(bytes: &[u8]) -> Result<XhpkeFingerprint, JsError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| JsError::new("fingerprint must be 32 bytes"))?;
        Ok(Self {
            inner: xhpke::Fingerprint::from_bytes(&arr),
        })
    }

    /// Serializes the fingerprint to a 32-byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

/// Stateful HPKE sender for multi-message encryption.
#[wasm_bindgen]
pub struct XhpkeSender {
    inner: xhpke::Sender,
    encap_key: Vec<u8>,
}

#[wasm_bindgen]
impl XhpkeSender {
    /// Returns the 1120-byte encapsulated key.
    pub fn encap_key(&self) -> Vec<u8> {
        self.encap_key.clone()
    }

    /// Encrypts a message using the next nonce in the sequence.
    pub fn seal(&mut self, msg_to_seal: &[u8], msg_to_auth: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner
            .seal(msg_to_seal, msg_to_auth)
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

/// Stateful HPKE receiver for multi-message decryption.
#[wasm_bindgen]
pub struct XhpkeReceiver {
    inner: xhpke::Receiver,
}

#[wasm_bindgen]
impl XhpkeReceiver {
    /// Decrypts a message using the next nonce in the sequence.
    pub fn open(&mut self, msg_to_open: &[u8], msg_to_auth: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner
            .open(msg_to_open, msg_to_auth)
            .map_err(|e| JsError::new(&e.to_string()))
    }
}
