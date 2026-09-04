// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
import { ensureInit, requireInit } from "./init.js";
import { codec, CodecError, type Codec } from "./cbor.js";
import { equal, toHex } from "./bytes.js";

/** Size of the secret key in bytes (64). */
export const SECRET_KEY_SIZE = 64;

/** Size of the public key in bytes (1984). */
export const PUBLIC_KEY_SIZE = 1984;

/** Size of a signature in bytes (3373). */
export const SIGNATURE_SIZE = 3373;

/** Size of a fingerprint in bytes (32). */
export const FINGERPRINT_SIZE = 32;

/**
 * Get the size constants (requires WASM initialization).
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

/**
 * Fingerprint is a 32-byte unique identifier for an xDSA key.
 * Backed by an opaque WASM handle.
 */
export class Fingerprint {
  /** @internal */
  readonly _wasm: WasmFingerprint;

  /** @internal */
  constructor(inner: WasmFingerprint) {
    this._wasm = inner;
  }

  /** Creates a fingerprint from a 32-byte array. */
  static async fromBytes(bytes: Uint8Array): Promise<Fingerprint> {
    await ensureInit();
    return new Fingerprint(WasmFingerprint.from_bytes(bytes));
  }

  /** Converts a fingerprint into a 32-byte array. */
  toBytes(): Uint8Array {
    return new Uint8Array(this._wasm.to_bytes());
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

/**
 * Signature is a 3373-byte xDSA signature.
 * Backed by an opaque WASM handle.
 */
export class Signature {
  /** @internal */
  readonly _wasm: WasmSignature;

  /** @internal */
  constructor(inner: WasmSignature) {
    this._wasm = inner;
  }

  /** Creates a signature from a 3373-byte array. */
  static async fromBytes(bytes: Uint8Array): Promise<Signature> {
    await ensureInit();
    return new Signature(WasmSignature.from_bytes(bytes));
  }

  /** Converts a signature into a 3373-byte array. */
  toBytes(): Uint8Array {
    return new Uint8Array(this._wasm.to_bytes());
  }
}

/**
 * PublicKey contains a composite ML-DSA-65 + Ed25519 public key for
 * verifying quantum resistant digital signatures.
 * Backed by an opaque WASM handle — key material stays in WASM memory.
 */
export class PublicKey {
  /** @internal */
  readonly _wasm: WasmPublicKey;

  /** @internal */
  constructor(inner: WasmPublicKey) {
    this._wasm = inner;
  }

  /** Creates a public key from a 1984-byte array. */
  static async fromBytes(bytes: Uint8Array): Promise<PublicKey> {
    await ensureInit();
    return new PublicKey(WasmPublicKey.from_bytes(bytes));
  }

  /** Parses a PEM string into a public key. */
  static async fromPem(pem: string): Promise<PublicKey> {
    await ensureInit();
    return new PublicKey(WasmPublicKey.from_pem(pem));
  }

  /** Converts a public key into a 1984-byte array. */
  toBytes(): Uint8Array {
    return new Uint8Array(this._wasm.to_bytes());
  }

  /** Serializes a public key into a PEM string. */
  toPem(): string {
    return this._wasm.to_pem();
  }

  /** Reports whether another public key is the same. */
  equals(other: PublicKey): boolean {
    return equal(this.toBytes(), other.toBytes());
  }

  /** Returns a 256-bit unique identifier for this key. */
  fingerprint(): Fingerprint {
    return new Fingerprint(this._wasm.fingerprint());
  }

  /**
   * Verifies a digital signature of the message.
   *
   * @returns true if the signature is valid, false otherwise (never throws)
   */
  verify(message: Uint8Array, signature: Signature): boolean {
    return this._wasm.verify(message, signature._wasm);
  }
}

/**
 * SecretKey contains a composite ML-DSA-65 + Ed25519 private key for
 * creating quantum resistant digital signatures.
 * Backed by an opaque WASM handle — key material stays in WASM memory.
 */
export class SecretKey {
  /** @internal */
  readonly _wasm: WasmSecretKey;

  /** @internal */
  constructor(inner: WasmSecretKey) {
    this._wasm = inner;
  }

  /** Creates a new, random private key. */
  static async generate(): Promise<SecretKey> {
    await ensureInit();
    return new SecretKey(WasmSecretKey.generate());
  }

  /** Creates a private key from a 64-byte seed. */
  static async fromBytes(bytes: Uint8Array): Promise<SecretKey> {
    await ensureInit();
    return new SecretKey(WasmSecretKey.from_bytes(bytes));
  }

  /** Parses a PEM string into a private key. */
  static async fromPem(pem: string): Promise<SecretKey> {
    await ensureInit();
    return new SecretKey(WasmSecretKey.from_pem(pem));
  }

  /** Converts a secret key into a 64-byte array. */
  toBytes(): Uint8Array {
    return new Uint8Array(this._wasm.to_bytes());
  }

  /** Serializes a private key into a PEM string. */
  toPem(): string {
    return this._wasm.to_pem();
  }

  /** Retrieves the public counterpart of the secret key. */
  publicKey(): PublicKey {
    return new PublicKey(this._wasm.public_key());
  }

  /** Returns a 256-bit unique identifier for this key. */
  fingerprint(): Fingerprint {
    return new Fingerprint(this._wasm.fingerprint());
  }

  /** Creates a digital signature of the message. */
  sign(message: Uint8Array): Signature {
    return new Signature(this._wasm.sign(message));
  }
}

/** The COSE algorithm identifier of the key type. */
export const ALGORITHM_ID = -70000;

/**
 * Codec of a public key as its bytes. Only the CBOR type is checked here, the
 * size and the key material are the Rust key's call.
 */
export const publicKey: Codec<PublicKey> = codec(
  (key) => key.toBytes(),
  (value) => {
    if (!(value instanceof Uint8Array)) {
      throw new CodecError("not a public key");
    }
    requireInit();
    try {
      return new PublicKey(WasmPublicKey.from_bytes(value));
    } catch (err) {
      throw new CodecError(
        `not a public key: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  },
);

/**
 * Codec of a fingerprint as its bytes. Only the CBOR type is checked here,
 * the size is the Rust fingerprint's call.
 */
export const fingerprint: Codec<Fingerprint> = codec(
  (print) => print.toBytes(),
  (value) => {
    if (!(value instanceof Uint8Array)) {
      throw new CodecError("not a fingerprint");
    }
    requireInit();
    try {
      return new Fingerprint(WasmFingerprint.from_bytes(value));
    } catch (err) {
      throw new CodecError(
        `not a fingerprint: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  },
);
