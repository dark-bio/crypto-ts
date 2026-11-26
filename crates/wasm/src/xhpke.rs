// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Hybrid public key encryption for JavaScript callers.
//!
//! https://datatracker.ietf.org/doc/html/rfc9180

use darkbio_crypto::xhpke;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

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
    /// Decryption key owned by this handle.
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

    /// Creates a private key from a 32-byte seed, wiping the seed from WASM
    /// memory before return.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<XhpkeSecretKey, JsError> {
        let bytes = Zeroizing::new(bytes);
        let seed: &[u8; xhpke::SECRET_KEY_SIZE] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| JsError::new("secret key must be 32 bytes"))?;
        Ok(Self {
            inner: xhpke::SecretKey::from_bytes(seed),
        })
    }

    /// Parses a secret key from PEM format, wiping the PEM from WASM memory
    /// before return.
    pub fn from_pem(pem: String) -> Result<XhpkeSecretKey, JsError> {
        let pem = Zeroizing::new(pem);
        Ok(Self {
            inner: xhpke::SecretKey::from_pem(&pem).map_err(|e| JsError::new(&e.to_string()))?,
        })
    }

    /// Exports the 32-byte seed to a JavaScript byte array.
    pub fn to_bytes(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.inner.to_bytes()[..])
    }

    /// Exports the PEM-encoded secret key to a JavaScript string.
    pub fn to_pem(&self) -> js_sys::JsString {
        js_sys::JsString::from(self.inner.to_pem().as_str())
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
        let encap_key: &[u8; xhpke::ENCAP_KEY_SIZE] = encap_key
            .try_into()
            .map_err(|_| JsError::new("encapsulated key must be 1120 bytes"))?;

        let receiver = self
            .inner
            .new_receiver(encap_key, domain)
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(XhpkeReceiver { inner: receiver })
    }

    /// Decrypts ciphertext prefixed with the 1120-byte encapsulated key.
    pub fn open(
        &self,
        sealed: &[u8],
        msg_to_auth: Vec<u8>,
        domain: &[u8],
    ) -> Result<js_sys::Uint8Array, JsError> {
        let auth = Zeroizing::new(msg_to_auth);
        // Split off the fixed-size encapsulated key
        let (encap_key, ciphertext) = sealed
            .split_first_chunk::<{ xhpke::ENCAP_KEY_SIZE }>()
            .ok_or_else(|| JsError::new("sealed data too short"))?;

        // Wipe the plaintext after copying it into JavaScript
        let plaintext = Zeroizing::new(
            self.inner
                .open(encap_key, ciphertext, &auth, domain)
                .map_err(|e| JsError::new(&e.to_string()))?,
        );
        Ok(js_sys::Uint8Array::from(&plaintext[..]))
    }
}

/// Opaque xHPKE public key. Key material stays inside WASM memory.
#[wasm_bindgen]
pub struct XhpkePublicKey {
    /// Encryption key owned by this handle.
    pub(crate) inner: xhpke::PublicKey,
}

#[wasm_bindgen]
impl XhpkePublicKey {
    /// Creates a public key from a 1216-byte array.
    pub fn from_bytes(bytes: &[u8]) -> Result<XhpkePublicKey, JsError> {
        let key: &[u8; xhpke::PUBLIC_KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| JsError::new("public key must be 1216 bytes"))?;
        Ok(Self {
            inner: xhpke::PublicKey::from_bytes(key).map_err(|e| JsError::new(&e.to_string()))?,
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

    /// Encrypts one message and prefixes it with the 1120-byte encapsulated key.
    pub fn seal(
        &self,
        msg_to_seal: Vec<u8>,
        msg_to_auth: Vec<u8>,
        domain: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let msg_to_seal = Zeroizing::new(msg_to_seal);
        let auth = Zeroizing::new(msg_to_auth);
        let (encap_key, ciphertext) = self
            .inner
            .seal(&msg_to_seal, &auth, domain)
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
    /// Key fingerprint owned by this handle.
    pub(crate) inner: xhpke::Fingerprint,
}

#[wasm_bindgen]
impl XhpkeFingerprint {
    /// Creates a fingerprint from a 32-byte array.
    pub fn from_bytes(bytes: &[u8]) -> Result<XhpkeFingerprint, JsError> {
        let fingerprint: &[u8; xhpke::FINGERPRINT_SIZE] = bytes
            .try_into()
            .map_err(|_| JsError::new("fingerprint must be 32 bytes"))?;
        Ok(Self {
            inner: xhpke::Fingerprint::from_bytes(fingerprint),
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
    /// Sender context with the next encryption nonce.
    inner: xhpke::Sender,
    /// Encapsulated key for initializing the peer's receiver.
    encap_key: Vec<u8>,
}

#[wasm_bindgen]
impl XhpkeSender {
    /// Returns the 1120-byte encapsulated key.
    pub fn encap_key(&self) -> Vec<u8> {
        self.encap_key.clone()
    }

    /// Encrypts a message using the next nonce in the sequence, wiping the
    /// plaintext from WASM memory before return.
    pub fn seal(&mut self, msg_to_seal: Vec<u8>, msg_to_auth: Vec<u8>) -> Result<Vec<u8>, JsError> {
        let msg_to_seal = Zeroizing::new(msg_to_seal);
        let auth = Zeroizing::new(msg_to_auth);
        self.inner
            .seal(&msg_to_seal, &auth)
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

/// Stateful HPKE receiver for multi-message decryption.
#[wasm_bindgen]
pub struct XhpkeReceiver {
    /// Receiver context with the next decryption nonce.
    inner: xhpke::Receiver,
}

#[wasm_bindgen]
impl XhpkeReceiver {
    /// Decrypts a message using the next nonce and wipes the WASM output buffer.
    pub fn open(
        &mut self,
        msg_to_open: &[u8],
        msg_to_auth: Vec<u8>,
    ) -> Result<js_sys::Uint8Array, JsError> {
        let auth = Zeroizing::new(msg_to_auth);
        let plaintext = Zeroizing::new(
            self.inner
                .open(msg_to_open, &auth)
                .map_err(|e| JsError::new(&e.to_string()))?,
        );
        Ok(js_sys::Uint8Array::from(&plaintext[..]))
    }
}
