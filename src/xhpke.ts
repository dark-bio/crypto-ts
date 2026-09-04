// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import {
  xhpke_secret_key_size,
  xhpke_public_key_size,
  xhpke_encap_key_size,
  xhpke_fingerprint_size,
  XhpkeSecretKey as WasmSecretKey,
  XhpkePublicKey as WasmPublicKey,
  XhpkeFingerprint as WasmFingerprint,
  XhpkeSender as WasmSender,
  XhpkeReceiver as WasmReceiver,
} from "./wasm/darkbio_crypto_wasm.js";
import { ensureInit, requireInit } from "./init.js";
import { codec, CodecError, type Codec } from "./cbor.js";
import { equal, toHex } from "./bytes.js";

/** Size of the secret key seed in bytes (32). */
export const SECRET_KEY_SIZE = 32;

/** Size of the public key in bytes (1216). */
export const PUBLIC_KEY_SIZE = 1216;

/** Size of the encapsulated key in bytes (1120). */
export const ENCAP_KEY_SIZE = 1120;

/** Size of a fingerprint in bytes (32). */
export const FINGERPRINT_SIZE = 32;

/**
 * Get the size constants (requires WASM initialization).
 */
export async function sizes(): Promise<{
  secretKey: number;
  publicKey: number;
  encapKey: number;
  fingerprint: number;
}> {
  await ensureInit();
  return {
    secretKey: xhpke_secret_key_size(),
    publicKey: xhpke_public_key_size(),
    encapKey: xhpke_encap_key_size(),
    fingerprint: xhpke_fingerprint_size(),
  };
}

/**
 * Fingerprint is a 32-byte unique identifier for an xHPKE key.
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
 * PublicKey contains an X-Wing public key for hybrid post-quantum encryption.
 * Backed by an opaque WASM handle — key material stays in WASM memory.
 */
export class PublicKey {
  /** @internal */
  readonly _wasm: WasmPublicKey;

  /** @internal */
  constructor(inner: WasmPublicKey) {
    this._wasm = inner;
  }

  /** Creates a public key from a 1216-byte array. */
  static async fromBytes(bytes: Uint8Array): Promise<PublicKey> {
    await ensureInit();
    return new PublicKey(WasmPublicKey.from_bytes(bytes));
  }

  /** Parses a PEM string into a public key. */
  static async fromPem(pem: string): Promise<PublicKey> {
    await ensureInit();
    return new PublicKey(WasmPublicKey.from_pem(pem));
  }

  /** Converts a public key into a 1216-byte array. */
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

  /** Returns a 256-bit unique identifier for this key (SHA256 of raw public key). */
  fingerprint(): Fingerprint {
    return new Fingerprint(this._wasm.fingerprint());
  }

  /**
   * Creates an HPKE sender context for multi-message encryption to this
   * public key. Returns a stateful Sender and the 1120-byte encapsulated
   * key that must be transmitted to the recipient.
   */
  newSender(domain: Uint8Array): { sender: Sender; encapKey: Uint8Array } {
    const wasmSender = this._wasm.new_sender(domain);
    const encapKey = new Uint8Array(wasmSender.encap_key());
    return { sender: new Sender(wasmSender), encapKey };
  }

  /**
   * Seal (encrypt) a message to this public key.
   *
   * @param msgToSeal - The message to encrypt
   * @param msgToAuth - Additional data to authenticate (but not encrypt)
   * @param domain - Application domain for context separation
   * @returns Sealed data (encapsulated key + ciphertext)
   */
  seal(
    msgToSeal: Uint8Array,
    msgToAuth: Uint8Array,
    domain: Uint8Array,
  ): Uint8Array {
    return new Uint8Array(this._wasm.seal(msgToSeal, msgToAuth, domain));
  }
}

/**
 * SecretKey contains an X-Wing private key for hybrid post-quantum encryption.
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

  /** Creates a private key from a 32-byte seed. */
  static async fromBytes(bytes: Uint8Array): Promise<SecretKey> {
    await ensureInit();
    return new SecretKey(WasmSecretKey.from_bytes(bytes));
  }

  /** Parses a PEM string into a private key. */
  static async fromPem(pem: string): Promise<SecretKey> {
    await ensureInit();
    return new SecretKey(WasmSecretKey.from_pem(pem));
  }

  /** Converts a private key into a 32-byte seed. */
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

  /** Returns a 256-bit unique identifier for this key (SHA256 of raw public key). */
  fingerprint(): Fingerprint {
    return new Fingerprint(this._wasm.fingerprint());
  }

  /**
   * Creates an HPKE receiver context for multi-message decryption.
   */
  newReceiver(encapKey: Uint8Array, domain: Uint8Array): Receiver {
    return new Receiver(this._wasm.new_receiver(encapKey, domain));
  }

  /**
   * Open (decrypt) a sealed message with this secret key.
   *
   * @param sealed - The sealed data from `seal()`
   * @param msgToAuth - The same additional authenticated data used during sealing
   * @param domain - The same application domain used during sealing
   * @returns The decrypted message
   */
  open(
    sealed: Uint8Array,
    msgToAuth: Uint8Array,
    domain: Uint8Array,
  ): Uint8Array {
    return new Uint8Array(this._wasm.open(sealed, msgToAuth, domain));
  }
}

/**
 * Sender is a stateful HPKE encryption context for multi-message
 * communication. Created via `PublicKey.newSender()`.
 */
export class Sender {
  private readonly inner: WasmSender;

  /** @internal */
  constructor(inner: WasmSender) {
    this.inner = inner;
  }

  /** Encrypts a message using the next nonce in the sequence. */
  seal(msgToSeal: Uint8Array, msgToAuth: Uint8Array): Uint8Array {
    return new Uint8Array(this.inner.seal(msgToSeal, msgToAuth));
  }
}

/**
 * Receiver is a stateful HPKE decryption context for multi-message
 * communication. Created via `SecretKey.newReceiver()`.
 */
export class Receiver {
  private readonly inner: WasmReceiver;

  /** @internal */
  constructor(inner: WasmReceiver) {
    this.inner = inner;
  }

  /** Decrypts a message using the next nonce in the sequence. */
  open(msgToOpen: Uint8Array, msgToAuth: Uint8Array): Uint8Array {
    return new Uint8Array(this.inner.open(msgToOpen, msgToAuth));
  }
}

/** The COSE algorithm identifier of the key type. */
export const ALGORITHM_ID = -70001;

/**
 * Codec of a public key as its bytes. Only the CBOR type is checked here, the
 * size and the key material are the Rust key's call.
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
      return new Fingerprint(WasmFingerprint.from_bytes(value));
    } catch (err) {
      throw new CodecError(
        `not a fingerprint: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  },
);
