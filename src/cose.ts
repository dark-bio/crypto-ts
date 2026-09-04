// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import type { Decodable, Encodable } from "./cbor.js";
import { parse, serialize } from "./internal/cborg.js";
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
import { ensureInit } from "./internal/init.js";
import { U64_MAX } from "./internal/limits.js";
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

/**
 * Converts the drift bound of a verification for the WASM boundary.
 */
function driftToBigInt(maxDriftSecs?: number): bigint | undefined {
  if (maxDriftSecs === undefined) return undefined;
  if (!Number.isFinite(maxDriftSecs)) {
    throw new Error(
      "maxDriftSecs must be a non-negative number within 64 bits",
    );
  }
  const secs = BigInt(Math.floor(maxDriftSecs));
  if (secs < 0n || secs > U64_MAX) {
    throw new Error(
      "maxDriftSecs must be a non-negative number within 64 bits",
    );
  }
  return secs;
}

/**
 * Create a COSE_Sign1 signature with an embedded payload.
 */
export async function sign<E, A>(
  msgToEmbed: Encodable<E>,
  msgToAuth: Encodable<A>,
  signer: XdsaSecretKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  return new Uint8Array(
    cose_sign(
      serialize(msgToEmbed),
      serialize(msgToAuth),
      signer._wasm,
      domain,
    ),
  );
}

/**
 * Create a COSE_Sign1 signature without an embedded payload (detached mode).
 */
export async function signDetached<A>(
  msgToAuth: Encodable<A>,
  signer: XdsaSecretKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  return new Uint8Array(
    cose_sign_detached(serialize(msgToAuth), signer._wasm, domain),
  );
}

/**
 * Verify a COSE_Sign1 signature and return the embedded payload.
 */
export async function verify<T, A>(
  msgToCheck: Decodable<T>,
  msgToAuth: Encodable<A>,
  verifier: XdsaPublicKey,
  domain: Uint8Array,
  maxDriftSecs?: number,
): Promise<T> {
  await ensureInit();
  const payload = cose_verify(
    msgToCheck.bytes,
    serialize(msgToAuth),
    verifier._wasm,
    domain,
    driftToBigInt(maxDriftSecs),
  );
  return msgToCheck.codec.decode(parse(new Uint8Array(payload)));
}

/**
 * Verify a COSE_Sign1 signature with a detached payload.
 */
export async function verifyDetached<A>(
  msgToCheck: Uint8Array,
  msgToAuth: Encodable<A>,
  verifier: XdsaPublicKey,
  domain: Uint8Array,
  maxDriftSecs?: number,
): Promise<void> {
  await ensureInit();
  cose_verify_detached(
    msgToCheck,
    serialize(msgToAuth),
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
 */
export async function peek<T>(signature: Decodable<T>): Promise<T> {
  await ensureInit();
  return signature.codec.decode(
    parse(new Uint8Array(cose_peek(signature.bytes))),
  );
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
  msgToSeal: Encodable<S>,
  msgToAuth: Encodable<A>,
  signerKey: XdsaSecretKey,
  recipientKey: XhpkePublicKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  return new Uint8Array(
    cose_seal(
      serialize(msgToSeal),
      serialize(msgToAuth),
      signerKey._wasm,
      recipientKey._wasm,
      domain,
    ),
  );
}

/**
 * Decrypt and verify a sealed message.
 */
export async function open<T, A>(
  msgToOpen: Decodable<T>,
  msgToAuth: Encodable<A>,
  recipientKey: XhpkeSecretKey,
  senderKey: XdsaPublicKey,
  domain: Uint8Array,
  maxDriftSecs?: number,
): Promise<T> {
  await ensureInit();
  const payload = cose_open(
    msgToOpen.bytes,
    serialize(msgToAuth),
    recipientKey._wasm,
    senderKey._wasm,
    domain,
    driftToBigInt(maxDriftSecs),
  );
  return msgToOpen.codec.decode(parse(new Uint8Array(payload)));
}

/**
 * Encrypt an already-signed COSE_Sign1 to a recipient.
 */
export async function encrypt<A>(
  sign1: Uint8Array,
  msgToAuth: Encodable<A>,
  recipientKey: XhpkePublicKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  return new Uint8Array(
    cose_encrypt(sign1, serialize(msgToAuth), recipientKey._wasm, domain),
  );
}

/**
 * Decrypt a sealed message without verifying the signature.
 */
export async function decrypt<A>(
  msgToOpen: Uint8Array,
  msgToAuth: Encodable<A>,
  recipientKey: XhpkeSecretKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  return new Uint8Array(
    cose_decrypt(msgToOpen, serialize(msgToAuth), recipientKey._wasm, domain),
  );
}
