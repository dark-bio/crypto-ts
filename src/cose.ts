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

function driftToBigInt(maxDriftSecs?: number): bigint | undefined {
  if (maxDriftSecs === undefined) return undefined;
  if (!Number.isFinite(maxDriftSecs) || maxDriftSecs < 0) {
    throw new Error("maxDriftSecs must be a non-negative number");
  }
  return BigInt(Math.floor(maxDriftSecs));
}

import {
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
import { ensureInit } from "./init.js";

/**
 * Create a COSE_Sign1 signature with an embedded payload.
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
  return new Uint8Array(cose_sign(embedBytes, authBytes, signer._wasm, domain));
}

/**
 * Create a COSE_Sign1 signature without an embedded payload (detached mode).
 */
export async function signDetached<A>(
  msgToAuth: A,
  signer: XdsaSecretKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  const authBytes = cborEncode(msgToAuth);
  return new Uint8Array(cose_sign_detached(authBytes, signer._wasm, domain));
}

/**
 * Verify a COSE_Sign1 signature and return the embedded payload.
 *
 * CBOR maps in the payload decode as `Map` objects, not plain objects, so a
 * payload signed from a plain object comes back as a `Map`.
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
    verifier._wasm,
    domain,
    driftToBigInt(maxDriftSecs),
  );
  return cborDecode(new Uint8Array(payloadBytes)) as T;
}

/**
 * Verify a COSE_Sign1 signature with a detached payload.
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
    verifier._wasm,
    domain,
    driftToBigInt(maxDriftSecs),
  );
}

/**
 * Extract the signer's fingerprint from a COSE_Sign1 without verifying.
 */
export async function signer(signature: Uint8Array): Promise<XdsaFingerprint> {
  await ensureInit();
  return new XdsaFingerprint(cose_signer(signature));
}

/**
 * Extract the embedded payload from a COSE_Sign1 without verifying.
 *
 * Warning: The returned payload is unauthenticated and should not be
 * trusted until verified with `verify`.
 *
 * CBOR maps in the payload decode as `Map` objects, not plain objects.
 */
export async function peek<T>(signature: Uint8Array): Promise<T> {
  await ensureInit();
  const payloadBytes = cose_peek(signature);
  return cborDecode(new Uint8Array(payloadBytes)) as T;
}

/**
 * Extract the recipient's fingerprint from a COSE_Encrypt0 without decrypting.
 */
export async function recipient(
  ciphertext: Uint8Array,
): Promise<XhpkeFingerprint> {
  await ensureInit();
  return new XhpkeFingerprint(cose_recipient(ciphertext));
}

/**
 * Sign a message then encrypt it to a recipient (sign-then-encrypt).
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
      signerKey._wasm,
      recipientKey._wasm,
      domain,
    ),
  );
}

/**
 * Decrypt and verify a sealed message.
 *
 * CBOR maps in the payload decode as `Map` objects, not plain objects, so a
 * payload sealed from a plain object comes back as a `Map`.
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
    recipientKey._wasm,
    senderKey._wasm,
    domain,
    driftToBigInt(maxDriftSecs),
  );
  return cborDecode(new Uint8Array(payloadBytes)) as T;
}

/**
 * Encrypt an already-signed COSE_Sign1 to a recipient.
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
    cose_encrypt(sign1, authBytes, recipientKey._wasm, domain),
  );
}

/**
 * Decrypt a sealed message without verifying the signature.
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
    cose_decrypt(msgToOpen, authBytes, recipientKey._wasm, domain),
  );
}
