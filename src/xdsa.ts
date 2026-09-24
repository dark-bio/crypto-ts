// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/**
 * Composite ML-DSA-65 + Ed25519 digital signatures.
 *
 * https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs
 *
 * A key signs a message with ML-DSA-65 and Ed25519 at once, and a signature
 * verifies only if both halves do. Keys and signatures round-trip through
 * fixed-size byte arrays. Keys also support PEM serialization.
 *
 * @example
 * ```ts
 * import { xdsa } from "@darkbio/crypto";
 *
 * const secret = await xdsa.SecretKey.generate();
 * const verifier = secret.publicKey();
 * const text = new TextEncoder();
 *
 * const signature = secret.sign(text.encode("hello"));
 * console.log(verifier.verify(text.encode("hello"), signature)); // true
 * console.log(verifier.verify(text.encode("tampered"), signature)); // false
 *
 * const restored = await xdsa.PublicKey.fromPem(verifier.toPem());
 * console.log(restored.fingerprint().equals(verifier.fingerprint())); // true
 * ```
 *
 * @module
 */

import {
  xdsa_secret_key_size,
  xdsa_public_key_size,
  xdsa_signature_size,
  xdsa_fingerprint_size,
  XdsaSecretKey as WasmSecretKey,
  XdsaPublicKey as WasmPublicKey,
  XdsaSignature as WasmSignature,
  XdsaFingerprint as WasmFingerprint,
} from "./wasm/darkbio_crypto_wasm.js";
import { ensureInit, requireInit } from "./internal/init.js";
import { codec, CodecError, type Codec } from "./cbor.js";
import { equal, toHex } from "./internal/bytes.js";

/**
 * Size of the secret key seed in bytes, the 32-byte ML-DSA-65 seed followed by
 * the 32-byte Ed25519 seed.
 */
export const SECRET_KEY_SIZE = 64;

/**
 * Size of the public key in bytes, the 1952-byte ML-DSA-65 key followed by the
 * 32-byte Ed25519 key.
 */
export const PUBLIC_KEY_SIZE = 1984;

/**
 * Size of a signature in bytes, the 3309-byte ML-DSA-65 signature followed by
 * the 64-byte Ed25519 signature.
 */
export const SIGNATURE_SIZE = 3373;

/** Size of a key fingerprint in bytes. */
export const FINGERPRINT_SIZE = 32;

/**
 * Returns the sizes in bytes as the Rust library defines them, the same values
 * as the constants of this module.
 */
export async function sizes(): Promise<{
  secretKey: number;
  publicKey: number;
  signature: number;
  fingerprint: number;
}> {
  await ensureInit();
  return {
    secretKey: xdsa_secret_key_size(),
    publicKey: xdsa_public_key_size(),
    signature: xdsa_signature_size(),
    fingerprint: xdsa_fingerprint_size(),
  };
}

/** A 256-bit unique identifier for an xDSA key. */
export class Fingerprint {
  /** @internal */
  readonly _wasm: WasmFingerprint;

  private constructor(inner: WasmFingerprint) {
    this._wasm = inner;
  }

  /** @internal */
  static _fromWasm(inner: WasmFingerprint): Fingerprint {
    return new Fingerprint(inner);
  }

  /**
   * Creates a fingerprint from a 32-byte array.
   *
   * @throws If `bytes` is not 32 bytes long
   */
  static async fromBytes(bytes: Uint8Array): Promise<Fingerprint> {
    await ensureInit();
    return new Fingerprint(WasmFingerprint.from_bytes(bytes));
  }

  /** Converts a fingerprint into a 32-byte array. */
  toBytes(): Uint8Array {
    return this._wasm.to_bytes();
  }

  /** Renders a fingerprint as lowercase hex. */
  toHex(): string {
    return toHex(this.toBytes());
  }

  /** Reports whether another fingerprint is the same. */
  equals(other: Fingerprint): boolean {
    return equal(this.toBytes(), other.toBytes());
  }
}

/** An xDSA signature, an ML-DSA-65 signature paired with an Ed25519 one. */
export class Signature {
  /** @internal */
  readonly _wasm: WasmSignature;

  private constructor(inner: WasmSignature) {
    this._wasm = inner;
  }

  /** @internal */
  static _fromWasm(inner: WasmSignature): Signature {
    return new Signature(inner);
  }

  /**
   * Creates a signature from a 3373-byte array. The halves are only checked
   * when the signature is verified.
   *
   * @throws If `bytes` is not 3373 bytes long
   */
  static async fromBytes(bytes: Uint8Array): Promise<Signature> {
    await ensureInit();
    return new Signature(WasmSignature.from_bytes(bytes));
  }

  /** Converts a signature into a 3373-byte array. */
  toBytes(): Uint8Array {
    return this._wasm.to_bytes();
  }
}

/**
 * An xDSA public key, an ML-DSA-65 key paired with an Ed25519 key, for
 * verifying quantum resistant digital signatures.
 */
export class PublicKey {
  /** @internal */
  readonly _wasm: WasmPublicKey;

  private constructor(inner: WasmPublicKey) {
    this._wasm = inner;
  }

  /** @internal */
  static _fromWasm(inner: WasmPublicKey): PublicKey {
    return new PublicKey(inner);
  }

  /**
   * Creates a public key from a 1984-byte array.
   *
   * @throws If `bytes` is not 1984 bytes long or not a valid composite key
   */
  static async fromBytes(bytes: Uint8Array): Promise<PublicKey> {
    await ensureInit();
    return new PublicKey(WasmPublicKey.from_bytes(bytes));
  }

  /**
   * Parses a PEM string into a public key. The input must be exactly one
   * `PUBLIC KEY` block, with no leading whitespace, strict base64 and LF or
   * CRLF line endings throughout.
   *
   * @throws If the PEM is malformed or holds another kind of key
   */
  static async fromPem(pem: string): Promise<PublicKey> {
    await ensureInit();
    return new PublicKey(WasmPublicKey.from_pem(pem));
  }

  /** Converts a public key into a 1984-byte array. */
  toBytes(): Uint8Array {
    return this._wasm.to_bytes();
  }

  /** Serializes a public key into a `PUBLIC KEY` PEM block with LF line endings. */
  toPem(): string {
    return this._wasm.to_pem();
  }

  /** Reports whether another public key is the same. */
  equals(other: PublicKey): boolean {
    return equal(this.toBytes(), other.toBytes());
  }

  /** Returns a 256-bit unique identifier for this key. */
  fingerprint(): Fingerprint {
    return Fingerprint._fromWasm(this._wasm.fingerprint());
  }

  /**
   * Verifies a digital signature of the message. Both the ML-DSA-65 and the
   * Ed25519 halves must verify.
   *
   * @param message - The signed message
   * @param signature - The signature to check
   * @returns True if the signature is valid for this key and message, false
   *   otherwise
   */
  verify(message: Uint8Array, signature: Signature): boolean {
    return this._wasm.verify(message, signature._wasm);
  }
}

/**
 * An xDSA secret key, an ML-DSA-65 key paired with an Ed25519 key, for
 * creating quantum resistant digital signatures. The key stays in WASM memory
 * unless {@link SecretKey.toBytes} or {@link SecretKey.toPem} copies it out.
 */
export class SecretKey {
  /** @internal */
  readonly _wasm: WasmSecretKey;

  private constructor(inner: WasmSecretKey) {
    this._wasm = inner;
  }

  /** Generates a new, random secret key. */
  static async generate(): Promise<SecretKey> {
    await ensureInit();
    return new SecretKey(WasmSecretKey.generate());
  }

  /**
   * Creates a secret key from a 64-byte seed.
   *
   * @throws If `bytes` is not 64 bytes long
   */
  static async fromBytes(bytes: Uint8Array): Promise<SecretKey> {
    await ensureInit();
    return new SecretKey(WasmSecretKey.from_bytes(bytes));
  }

  /**
   * Parses a PEM string into a secret key. The input must be exactly one
   * `PRIVATE KEY` block, with no leading whitespace, strict base64 and LF or
   * CRLF line endings throughout.
   *
   * @throws If the PEM is malformed or holds another kind of key
   */
  static async fromPem(pem: string): Promise<SecretKey> {
    await ensureInit();
    return new SecretKey(WasmSecretKey.from_pem(pem));
  }

  /** Converts a secret key into its 64-byte seed. */
  toBytes(): Uint8Array {
    return this._wasm.to_bytes();
  }

  /** Serializes a secret key into a `PRIVATE KEY` PEM block with LF line endings. */
  toPem(): string {
    return this._wasm.to_pem();
  }

  /** Retrieves the public counterpart of the secret key. */
  publicKey(): PublicKey {
    return PublicKey._fromWasm(this._wasm.public_key());
  }

  /** Returns a 256-bit unique identifier for this key, the same as its public key's. */
  fingerprint(): Fingerprint {
    return Fingerprint._fromWasm(this._wasm.fingerprint());
  }

  /**
   * Creates a digital signature of the message.
   *
   * @param message - The message to sign
   * @returns The signature
   */
  sign(message: Uint8Array): Signature {
    return Signature._fromWasm(this._wasm.sign(message));
  }
}

/** Private COSE algorithm identifier of composite ML-DSA-65 + Ed25519 signatures. */
export const ALGORITHM_ID = -70000;

/**
 * Codec of a public key as its 1984 bytes. Decoding throws a
 * {@link CodecError} unless the bytes are a valid key. Calling its decode
 * directly needs any async function of this package to have run first.
 */
export const publicKey: Codec<PublicKey> = codec(
  (key) => {
    if (!(key instanceof PublicKey)) {
      throw new CodecError("not a public key");
    }
    return key.toBytes();
  },
  (value) => {
    if (!(value instanceof Uint8Array)) {
      throw new CodecError("not a public key");
    }
    requireInit();
    try {
      return PublicKey._fromWasm(WasmPublicKey.from_bytes(value));
    } catch (err) {
      throw new CodecError(
        `not a public key: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  },
);

/**
 * Codec of a fingerprint as its 32 bytes. Decoding throws a {@link CodecError}
 * unless the value is 32 bytes. Calling its decode directly needs any async
 * function of this package to have run first.
 */
export const fingerprint: Codec<Fingerprint> = codec(
  (print) => {
    if (!(print instanceof Fingerprint)) {
      throw new CodecError("not a fingerprint");
    }
    return print.toBytes();
  },
  (value) => {
    if (!(value instanceof Uint8Array)) {
      throw new CodecError("not a fingerprint");
    }
    requireInit();
    try {
      return Fingerprint._fromWasm(WasmFingerprint.from_bytes(value));
    } catch (err) {
      throw new CodecError(
        `not a fingerprint: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  },
);
