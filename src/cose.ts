// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/**
 * COSE signing and encryption with xDSA and xHPKE.
 *
 * https://datatracker.ietf.org/doc/html/rfc9052
 * https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke
 *
 * Signatures are COSE_Sign1 envelopes carrying the signer's fingerprint and a
 * timestamp in the protected header. Encryption is COSE_Encrypt0 around a
 * signed envelope, so every message created by {@link seal} is also signed.
 * Payloads and authenticated messages are values bound to a `cbor` codec.
 * Signing, verification, encryption and decryption use an application domain,
 * prefixed with `dark-bio-v1:`, which both sides must agree on.
 *
 * ## Domain separation and freshness
 *
 * Choose distinct domains for distinct application operations. Domains
 * prevent a message for one purpose from being accepted for another; they do
 * not stop repeated use within the same domain. Verification accepts a
 * signature whose timestamp is at most `maxDriftSecs` seconds in the past or
 * future. An undefined `maxDriftSecs` skips this timestamp check. Applications
 * that require one-time acceptance must also track a message identifier,
 * nonce or challenge to reject replays.
 *
 * ## Wire profile
 *
 * Interoperating implementations must match these Dark Bio conventions:
 *
 * - Envelopes are untagged COSE_Sign1 and COSE_Encrypt0 arrays. CBOR tags are
 *   not accepted. Headers are deterministic maps with integer keys.
 * - The private algorithm IDs are -70000 for xDSA and -70001 for xHPKE. The
 *   protected `kid` is the appropriate public key's fingerprint. Signatures
 *   require the private timestamp header -70002 and name it in `crit`.
 * - For signatures, the Sig_structure external_aad is the CBOR encoding of
 *   `[bstr("dark-bio-v1:" || domain), msgToAuth]`. An embedded payload is the
 *   CBOR encoding of the caller's value.
 * - For {@link signDetached}, the caller's message is authenticated in that
 *   external_aad, while the Sig_structure payload is an empty byte string and
 *   the envelope payload is null. A generic COSE detached-payload API that
 *   puts the caller's message in the Sig_structure payload must be adapted to
 *   this convention.
 * - For encryption, the Enc_structure external_aad is the CBOR encoding of
 *   `msgToAuth`, and the complete encoded Enc_structure is the HPKE AAD. HPKE
 *   key derivation uses `"dark-bio-v1:" || domain` as its info. The X-Wing
 *   encapsulated key is carried in unprotected header -4.
 *
 * Here bstr denotes a CBOR byte string and || denotes byte concatenation. The
 * domain and `msgToAuth` are not included in the returned envelope, so both
 * parties must know them or transmit them separately.
 *
 * @example
 * ```ts
 * import { cbor, cose, xdsa, xhpke } from "@darkbio/crypto";
 *
 * const signer = await xdsa.SecretKey.generate();
 * const domain = new TextEncoder().encode("example");
 * const context = cbor.text.value("context");
 *
 * // Sign a payload, binding a second message supplied separately
 * const envelope = await cose.sign(cbor.text.value("hello"), context, signer, domain);
 * const payload = await cose.verify(cbor.text.bytes(envelope), context, signer.publicKey(), domain, 60);
 * console.log(payload); // hello
 *
 * // Sign and encrypt to a recipient in one step, then open and verify it back
 * const recipient = await xhpke.SecretKey.generate();
 * const sealed = await cose.seal(cbor.text.value("secret"), context, signer, recipient.publicKey(), domain);
 * const opened = await cose.open(cbor.text.bytes(sealed), context, recipient, signer.publicKey(), domain, 60);
 * console.log(opened); // secret
 * ```
 *
 * @module
 */

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
 * Creates a COSE_Sign1 signature with an embedded payload.
 *
 * Uses the current system time as the signature timestamp.
 *
 * @param msgToEmbed - The message to sign, embedded in the envelope
 * @param msgToAuth - Additional authenticated data, signed but not embedded
 * @param signer - The xDSA secret key to sign with
 * @param domain - Application domain for separating protocol purposes
 * @returns The serialized COSE_Sign1 envelope
 * @throws CodecError if a message does not fit its codec
 * @throws If a message falls outside the restricted CBOR type system
 */
export async function sign<E, A>(
  msgToEmbed: Encodable<E>,
  msgToAuth: Encodable<A>,
  signer: XdsaSecretKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  return cose_sign(
    serialize(msgToEmbed),
    serialize(msgToAuth),
    signer._wasm,
    domain,
  );
}

/**
 * Creates a COSE_Sign1 signature without an embedded payload, the envelope
 * payload being null.
 *
 * The caller's message is authenticated in external_aad, and the payload in
 * the signature input is empty. See the module's wire profile for
 * interoperability. Uses the current system time as the signature timestamp.
 *
 * @param msgToAuth - The message to sign, not embedded in the envelope
 * @param signer - The xDSA secret key to sign with
 * @param domain - Application domain for separating protocol purposes
 * @returns The serialized COSE_Sign1 envelope
 * @throws CodecError if the message does not fit its codec
 * @throws If the message falls outside the restricted CBOR type system
 */
export async function signDetached<A>(
  msgToAuth: Encodable<A>,
  signer: XdsaSecretKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  return cose_sign_detached(serialize(msgToAuth), signer._wasm, domain);
}

/**
 * Verifies a COSE_Sign1 signature and returns the embedded payload.
 *
 * Uses the current system time for the drift check.
 *
 * @param msgToCheck - The serialized COSE_Sign1 envelope, bound to the codec
 *   of its payload
 * @param msgToAuth - The same additional authenticated data used during signing
 * @param verifier - The xDSA public key to verify against
 * @param domain - Application domain for separating protocol purposes
 * @param maxDriftSecs - Maximum allowed timestamp difference in seconds, past
 *   or future. A value of n accepts differences up to and including n, with
 *   fractions rounded down. Undefined skips the check.
 * @returns The decoded payload
 * @throws If the envelope is malformed, carries no payload or does not verify
 *   for this key, `msgToAuth` and `domain`, or its timestamp drifts too far
 * @throws If `maxDriftSecs` is negative or beyond 64 bits
 * @throws CodecError if the payload or `msgToAuth` does not fit its codec
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
  return msgToCheck.codec.decode(parse(payload));
}

/**
 * Verifies a COSE_Sign1 signature with a detached payload.
 *
 * Uses the current system time for the drift check.
 *
 * @param msgToCheck - The serialized COSE_Sign1 envelope, with a null payload
 * @param msgToAuth - The same message used during signing
 * @param verifier - The xDSA public key to verify against
 * @param domain - Application domain for separating protocol purposes
 * @param maxDriftSecs - Maximum allowed timestamp difference in seconds, past
 *   or future. A value of n accepts differences up to and including n, with
 *   fractions rounded down. Undefined skips the check.
 * @throws If the envelope is malformed, embeds a payload or does not verify
 *   for this key, `msgToAuth` and `domain`, or its timestamp drifts too far
 * @throws If `maxDriftSecs` is negative or beyond 64 bits
 * @throws CodecError if `msgToAuth` does not fit its codec
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
 * Extracts the signer's fingerprint from a COSE_Sign1 envelope without
 * verifying it.
 *
 * This allows looking up the appropriate verification key before attempting
 * full signature verification. The fingerprint is unauthenticated.
 *
 * @param signature - The serialized COSE_Sign1 envelope
 * @returns The signer's fingerprint from the protected header's `kid`
 * @throws If the envelope is malformed
 */
export async function signer(signature: Uint8Array): Promise<XdsaFingerprint> {
  await ensureInit();
  return XdsaFingerprint._fromWasm(cose_signer(signature));
}

/**
 * Extracts the embedded payload from a COSE_Sign1 envelope without verifying
 * it.
 *
 * The payload is unauthenticated and must not be trusted until verified with
 * {@link verify}. Use {@link signer} to extract the signer's fingerprint for
 * key lookup.
 *
 * @param signature - The serialized COSE_Sign1 envelope, bound to the codec of
 *   its payload
 * @returns The decoded, unverified payload
 * @throws If the envelope is malformed or carries no payload
 * @throws CodecError if the payload does not fit its codec
 */
export async function peek<T>(signature: Decodable<T>): Promise<T> {
  await ensureInit();
  return signature.codec.decode(parse(cose_peek(signature.bytes)));
}

/**
 * Extracts the recipient's fingerprint from a COSE_Encrypt0 envelope without
 * decrypting it.
 *
 * This allows looking up the appropriate decryption key before attempting
 * full decryption. The fingerprint is unauthenticated.
 *
 * @param ciphertext - The serialized COSE_Encrypt0 envelope
 * @returns The recipient's fingerprint from the protected header's `kid`
 * @throws If the envelope is malformed
 */
export async function recipient(
  ciphertext: Uint8Array,
): Promise<XhpkeFingerprint> {
  await ensureInit();
  return XhpkeFingerprint._fromWasm(cose_recipient(ciphertext));
}

/**
 * Signs a message then encrypts it to a recipient.
 *
 * Uses the current system time as the signature timestamp.
 *
 * @param msgToSeal - The message to sign and encrypt
 * @param msgToAuth - Additional authenticated data, signed and bound to the
 *   encryption but not embedded
 * @param signerKey - The xDSA secret key to sign with
 * @param recipientKey - The xHPKE public key to encrypt to
 * @param domain - Application domain for HPKE key derivation
 * @returns The serialized COSE_Encrypt0 envelope holding the encrypted
 *   COSE_Sign1
 * @throws CodecError if a message does not fit its codec
 * @throws If a message falls outside the restricted CBOR type system
 */
export async function seal<S, A>(
  msgToSeal: Encodable<S>,
  msgToAuth: Encodable<A>,
  signerKey: XdsaSecretKey,
  recipientKey: XhpkePublicKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  const plaintext = serialize(msgToSeal);
  try {
    return cose_seal(
      plaintext,
      serialize(msgToAuth),
      signerKey._wasm,
      recipientKey._wasm,
      domain,
    );
  } finally {
    plaintext.fill(0);
  }
}

/**
 * Decrypts and verifies a sealed message.
 *
 * Uses the current system time for the drift check.
 *
 * @param msgToOpen - The serialized COSE_Encrypt0 envelope, bound to the codec
 *   of its payload
 * @param msgToAuth - The same additional authenticated data used during sealing
 * @param recipientKey - The xHPKE secret key to decrypt with
 * @param senderKey - The xDSA public key to verify the signature against
 * @param domain - Application domain for HPKE key derivation
 * @param maxDriftSecs - Maximum allowed timestamp difference in seconds, past
 *   or future. A value of n accepts differences up to and including n, with
 *   fractions rounded down. Undefined skips the check.
 * @returns The decoded payload
 * @throws If the envelope is malformed, does not decrypt or verify for these
 *   keys, `msgToAuth` and `domain`, or its timestamp drifts too far
 * @throws If `maxDriftSecs` is negative or beyond 64 bits
 * @throws CodecError if the payload or `msgToAuth` does not fit its codec
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
  try {
    return msgToOpen.codec.decode(parse(payload));
  } finally {
    payload.fill(0);
  }
}

/**
 * Encrypts an already signed COSE_Sign1 envelope to a recipient.
 *
 * For most use cases, prefer {@link seal}, which signs and encrypts in one
 * step. Use this only when re-encrypting a message from {@link decrypt} to a
 * different recipient without access to the original signer's key. The
 * envelope is encrypted as given, without being checked.
 *
 * @param sign1 - The COSE_Sign1 envelope, such as one from {@link decrypt}
 * @param msgToAuth - The same additional authenticated data used during sealing
 * @param recipientKey - The xHPKE public key to encrypt to
 * @param domain - Application domain for HPKE key derivation
 * @returns The serialized COSE_Encrypt0 envelope
 * @throws CodecError if `msgToAuth` does not fit its codec
 */
export async function encrypt<A>(
  sign1: Uint8Array,
  msgToAuth: Encodable<A>,
  recipientKey: XhpkePublicKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  return cose_encrypt(sign1, serialize(msgToAuth), recipientKey._wasm, domain);
}

/**
 * Decrypts a sealed message without verifying the signature.
 *
 * This allows inspecting the signer before verification. Use {@link signer}
 * to extract the signer's fingerprint, then {@link verify} with the same
 * `msgToAuth` and `domain` to verify.
 *
 * @param msgToOpen - The serialized COSE_Encrypt0 envelope
 * @param msgToAuth - The same additional authenticated data used during sealing
 * @param recipientKey - The xHPKE secret key to decrypt with
 * @param domain - Application domain for HPKE key derivation
 * @returns The decrypted COSE_Sign1 envelope, not yet verified
 * @throws If the envelope is malformed or does not decrypt for this key,
 *   `msgToAuth` and `domain`
 * @throws CodecError if `msgToAuth` does not fit its codec
 */
export async function decrypt<A>(
  msgToOpen: Uint8Array,
  msgToAuth: Encodable<A>,
  recipientKey: XhpkeSecretKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  return cose_decrypt(
    msgToOpen,
    serialize(msgToAuth),
    recipientKey._wasm,
    domain,
  );
}
