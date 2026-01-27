// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import { encode as cborEncode, decode as cborDecodeRaw } from "cborg";
import {
  SecretKey as XdsaSecretKey,
  PublicKey as XdsaPublicKey,
  Fingerprint as XdsaFingerprint,
} from "./xdsa.js";
import {
  SecretKey as XhpkeSecretKey,
  PublicKey as XhpkePublicKey,
  Fingerprint as XhpkeFingerprint,
} from "./xhpke.js";

function cborDecode<T>(data: Uint8Array): T {
  return cborDecodeRaw(data, { useMaps: true }) as T;
}

import init, {
  cose_sign,
  cose_sign_detached,
  cose_verify,
  cose_verify_detached,
  cose_signer,
  cose_peek,
  cose_recipient,
  cose_seal,
  cose_open,
  cose_encrypt,
  cose_decrypt,
} from "./wasm/darkbio_crypto_wasm.js";

let initialized = false;

async function ensureInit(): Promise<void> {
  if (!initialized) {
    await init();
    initialized = true;
  }
}

/**
 * Create a COSE_Sign1 signature with an embedded payload.
 *
 * @param msgToEmbed - The payload to embed and sign (will be CBOR encoded)
 * @param msgToAuth - Additional authenticated data (will be CBOR encoded)
 * @param signer - The xDSA secret key
 * @param domain - Application-specific domain separator
 * @returns The serialized COSE_Sign1 structure
 */
export async function sign<E, A>(
  msgToEmbed: E,
  msgToAuth: A,
  signer: XdsaSecretKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  const embedBytes = cborEncode(msgToEmbed);
  const authBytes = cborEncode(msgToAuth);
  return new Uint8Array(
    cose_sign(embedBytes, authBytes, signer.toBytes(), domain),
  );
}

/**
 * Create a COSE_Sign1 signature without an embedded payload (detached mode).
 *
 * @param msgToAuth - The message to authenticate (will be CBOR encoded)
 * @param signer - The xDSA secret key
 * @param domain - Application-specific domain separator
 * @returns The serialized COSE_Sign1 structure (with null payload)
 */
export async function signDetached<A>(
  msgToAuth: A,
  signer: XdsaSecretKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  const authBytes = cborEncode(msgToAuth);
  return new Uint8Array(
    cose_sign_detached(authBytes, signer.toBytes(), domain),
  );
}

/**
 * Verify a COSE_Sign1 signature and return the embedded payload.
 *
 * @param msgToCheck - The COSE_Sign1 structure to verify
 * @param msgToAuth - Additional authenticated data (will be CBOR encoded)
 * @param verifier - The xDSA public key
 * @param domain - Application-specific domain separator
 * @param maxDriftSecs - Maximum allowed clock drift (undefined for no time check)
 * @returns The decoded embedded payload
 */
export async function verify<T, A>(
  msgToCheck: Uint8Array,
  msgToAuth: A,
  verifier: XdsaPublicKey,
  domain: Uint8Array,
  maxDriftSecs?: number,
): Promise<T> {
  await ensureInit();
  const authBytes = cborEncode(msgToAuth);
  const payloadBytes = cose_verify(
    msgToCheck,
    authBytes,
    verifier.toBytes(),
    domain,
    maxDriftSecs !== undefined ? BigInt(maxDriftSecs) : undefined,
  );
  return cborDecode(new Uint8Array(payloadBytes)) as T;
}

/**
 * Verify a COSE_Sign1 signature with a detached payload.
 *
 * @param msgToCheck - The COSE_Sign1 structure to verify
 * @param msgToAuth - The detached message to authenticate (will be CBOR encoded)
 * @param verifier - The xDSA public key
 * @param domain - Application-specific domain separator
 * @param maxDriftSecs - Maximum allowed clock drift (undefined for no time check)
 */
export async function verifyDetached<A>(
  msgToCheck: Uint8Array,
  msgToAuth: A,
  verifier: XdsaPublicKey,
  domain: Uint8Array,
  maxDriftSecs?: number,
): Promise<void> {
  await ensureInit();
  const authBytes = cborEncode(msgToAuth);
  cose_verify_detached(
    msgToCheck,
    authBytes,
    verifier.toBytes(),
    domain,
    maxDriftSecs !== undefined ? BigInt(maxDriftSecs) : undefined,
  );
}

/**
 * Extract the signer's fingerprint from a COSE_Sign1 without verifying.
 *
 * @param signature - The COSE_Sign1 structure
 * @returns The signer fingerprint
 */
export async function signer(signature: Uint8Array): Promise<XdsaFingerprint> {
  await ensureInit();
  const fp = new Uint8Array(cose_signer(signature));
  return XdsaFingerprint.fromBytes(fp);
}

/**
 * Extract the embedded payload from a COSE_Sign1 without verifying.
 *
 * Warning: The returned payload is unauthenticated and should not be
 * trusted until verified with `verify`.
 *
 * @param signature - The COSE_Sign1 structure
 * @returns The decoded (but unverified) payload
 */
export async function peek<T>(signature: Uint8Array): Promise<T> {
  await ensureInit();
  const payloadBytes = cose_peek(signature);
  return cborDecode(new Uint8Array(payloadBytes)) as T;
}

/**
 * Extract the recipient's fingerprint from a COSE_Encrypt0 without decrypting.
 *
 * @param ciphertext - The COSE_Encrypt0 structure
 * @returns The recipient fingerprint
 */
export async function recipient(
  ciphertext: Uint8Array,
): Promise<XhpkeFingerprint> {
  await ensureInit();
  const fp = new Uint8Array(cose_recipient(ciphertext));
  return XhpkeFingerprint.fromBytes(fp);
}

/**
 * Sign a message then encrypt it to a recipient (sign-then-encrypt).
 *
 * @param msgToSeal - The payload to sign and encrypt (will be CBOR encoded)
 * @param msgToAuth - Additional authenticated data (will be CBOR encoded)
 * @param signerKey - The xDSA secret key to sign with
 * @param recipientKey - The xHPKE public key to encrypt to
 * @param domain - Application-specific domain separator
 * @returns The sealed COSE structure
 */
export async function seal<S, A>(
  msgToSeal: S,
  msgToAuth: A,
  signerKey: XdsaSecretKey,
  recipientKey: XhpkePublicKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  const sealBytes = cborEncode(msgToSeal);
  const authBytes = cborEncode(msgToAuth);
  return new Uint8Array(
    cose_seal(
      sealBytes,
      authBytes,
      signerKey.toBytes(),
      recipientKey.toBytes(),
      domain,
    ),
  );
}

/**
 * Decrypt and verify a sealed message.
 *
 * @param msgToOpen - The sealed COSE structure
 * @param msgToAuth - Additional authenticated data (will be CBOR encoded)
 * @param recipientKey - The xHPKE secret key to decrypt with
 * @param senderKey - The xDSA public key to verify against
 * @param domain - Application-specific domain separator
 * @param maxDriftSecs - Maximum allowed clock drift (undefined for no time check)
 * @returns The decoded payload
 */
export async function open<T, A>(
  msgToOpen: Uint8Array,
  msgToAuth: A,
  recipientKey: XhpkeSecretKey,
  senderKey: XdsaPublicKey,
  domain: Uint8Array,
  maxDriftSecs?: number,
): Promise<T> {
  await ensureInit();
  const authBytes = cborEncode(msgToAuth);
  const payloadBytes = cose_open(
    msgToOpen,
    authBytes,
    recipientKey.toBytes(),
    senderKey.toBytes(),
    domain,
    maxDriftSecs !== undefined ? BigInt(maxDriftSecs) : undefined,
  );
  return cborDecode(new Uint8Array(payloadBytes)) as T;
}

/**
 * Encrypt an already-signed COSE_Sign1 to a recipient.
 *
 * For most use cases, prefer `seal` which signs and encrypts in one step.
 * Use this only when re-encrypting a message to a different recipient
 * without access to the original signer's key.
 *
 * @param sign1 - The COSE_Sign1 structure to encrypt
 * @param msgToAuth - Additional authenticated data (will be CBOR encoded)
 * @param recipientKey - The xHPKE public key to encrypt to
 * @param domain - Application-specific domain separator
 * @returns The COSE_Encrypt0 structure
 */
export async function encrypt<A>(
  sign1: Uint8Array,
  msgToAuth: A,
  recipientKey: XhpkePublicKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  const authBytes = cborEncode(msgToAuth);
  return new Uint8Array(
    cose_encrypt(sign1, authBytes, recipientKey.toBytes(), domain),
  );
}

/**
 * Decrypt a sealed message without verifying the signature.
 *
 * This allows inspecting the signer before verification. Use `signer` to
 * extract the signer's fingerprint, then verify with `verify`.
 *
 * @param msgToOpen - The COSE_Encrypt0 structure
 * @param msgToAuth - Additional authenticated data (will be CBOR encoded)
 * @param recipientKey - The xHPKE secret key to decrypt with
 * @param domain - Application-specific domain separator
 * @returns The decrypted COSE_Sign1 structure (not yet verified)
 */
export async function decrypt<A>(
  msgToOpen: Uint8Array,
  msgToAuth: A,
  recipientKey: XhpkeSecretKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  const authBytes = cborEncode(msgToAuth);
  return new Uint8Array(
    cose_decrypt(msgToOpen, authBytes, recipientKey.toBytes(), domain),
  );
}
