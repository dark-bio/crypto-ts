// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/**
 * X-Wing HPKE encryption.
 *
 * https://datatracker.ietf.org/doc/html/rfc9180
 * https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem
 *
 * Messages are encrypted to a public key with X-Wing, a hybrid of ML-KEM-768
 * and X25519, and sealed with ChaCha20-Poly1305. Encryption and decryption use
 * an application domain, prefixed with `dark-bio-v1:`, which both sides must
 * agree on. The ciphertext also authenticates a second message that must be
 * supplied separately.
 *
 * A {@link Sender} and {@link Receiver} pair shares one encapsulated key across
 * many messages, which must be opened in the order they were sealed. The
 * domain is fixed when the contexts are created.
 *
 * @example
 * ```ts
 * import { xhpke } from "@darkbio/crypto";
 *
 * const secret = await xhpke.SecretKey.generate();
 * const text = new TextEncoder();
 * const domain = text.encode("example");
 *
 * const sealed = secret.publicKey().seal(text.encode("secret"), text.encode("header"), domain);
 * const plaintext = secret.open(sealed, text.encode("header"), domain);
 * console.log(new TextDecoder().decode(plaintext)); // secret
 *
 * // A tampered header fails authentication
 * try {
 *   secret.open(sealed, text.encode("other"), domain);
 * } catch {
 *   console.log("rejected");
 * }
 * ```
 *
 * @example
 * ```ts
 * import { xhpke } from "@darkbio/crypto";
 *
 * const secret = await xhpke.SecretKey.generate();
 * const domain = new TextEncoder().encode("example");
 *
 * const { sender, encapKey } = secret.publicKey().newSender(domain);
 * const receiver = secret.newReceiver(encapKey, domain);
 *
 * for (const message of ["first", "second"]) {
 *   const ciphertext = sender.seal(new TextEncoder().encode(message), new Uint8Array());
 *   const plaintext = receiver.open(ciphertext, new Uint8Array());
 *   console.log(new TextDecoder().decode(plaintext)); // first, then second
 * }
 * ```
 *
 * @module
 */

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
import { ensureInit, requireInit } from "./internal/init.js";
import { codec, CodecError, type Codec } from "./cbor.js";
import { equal, toHex } from "./internal/bytes.js";

/** Size of the secret key seed in bytes. */
export const SECRET_KEY_SIZE = 32;

/** Size of the public key in bytes. */
export const PUBLIC_KEY_SIZE = 1216;

/**
 * Size of the encapsulated key in bytes, the prefix of every
 * {@link PublicKey.seal} output.
 */
export const ENCAP_KEY_SIZE = 1120;

/** Size of a key fingerprint in bytes. */
export const FINGERPRINT_SIZE = 32;

/**
 * Returns the sizes in bytes as the Rust library defines them, the same values
 * as the constants of this module.
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

/** A 256-bit unique identifier for an xHPKE key. */
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

/** An X-Wing public key for encrypting HPKE messages. */
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
   * Creates a public key from a 1216-byte array.
   *
   * @throws If `bytes` is not 1216 bytes long or not a valid X-Wing key
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

  /** Converts a public key into a 1216-byte array. */
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

  /**
   * Returns a 256-bit unique identifier for this key, the SHA-256 hash of the
   * public key bytes.
   */
  fingerprint(): Fingerprint {
    return Fingerprint._fromWasm(this._wasm.fingerprint());
  }

  /**
   * Creates an HPKE sender context for multi-message encryption to this
   * public key. Messages it seals must be opened in order by a
   * {@link Receiver} created from the returned encapsulated key.
   *
   * HPKE runs in base mode, which does not authenticate the sender. The
   * recipient cannot verify who created the context.
   *
   * @param domain - Application domain, fixed for every message of the context
   * @returns The stateful sender and the 1120-byte encapsulated key, which
   *   must be transmitted to the recipient
   */
  newSender(domain: Uint8Array): { sender: Sender; encapKey: Uint8Array } {
    const wasmSender = this._wasm.new_sender(domain);
    const encapKey = wasmSender.encap_key();
    return { sender: Sender._fromWasm(wasmSender), encapKey };
  }

  /**
   * Encrypts a message to this public key, also authenticating a second
   * message that is not included in the output. Opening it with
   * {@link SecretKey.open} needs the same second message and domain.
   *
   * HPKE runs in base mode, which does not authenticate the sender. The
   * recipient cannot verify who sealed the message.
   *
   * @param msgToSeal - The message to encrypt
   * @param msgToAuth - The message to authenticate but not include
   * @param domain - Application domain, which both sides must agree on
   * @returns The 1120-byte encapsulated key followed by the ciphertext
   */
  seal(
    msgToSeal: Uint8Array,
    msgToAuth: Uint8Array,
    domain: Uint8Array,
  ): Uint8Array {
    return this._wasm.seal(msgToSeal, msgToAuth, domain);
  }
}

/**
 * An X-Wing secret key for decrypting HPKE messages. The key stays in WASM
 * memory unless {@link SecretKey.toBytes} or {@link SecretKey.toPem} copies it
 * out.
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
   * Creates a secret key from a 32-byte seed.
   *
   * @throws If `bytes` is not 32 bytes long
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

  /** Converts a secret key into its 32-byte seed. */
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

  /**
   * Returns a 256-bit unique identifier for this key, the SHA-256 hash of the
   * public key bytes.
   */
  fingerprint(): Fingerprint {
    return Fingerprint._fromWasm(this._wasm.fingerprint());
  }

  /**
   * Creates an HPKE receiver context for multi-message decryption. Messages
   * must be opened in the order the {@link Sender} sealed them.
   *
   * HPKE runs in base mode, which does not authenticate the sender. The
   * recipient cannot verify who created the context.
   *
   * @param encapKey - The 1120-byte encapsulated key from {@link PublicKey.newSender}
   * @param domain - The same application domain the sender uses
   * @returns The stateful receiver
   * @throws If `encapKey` is not 1120 bytes long or is malformed
   */
  newReceiver(encapKey: Uint8Array, domain: Uint8Array): Receiver {
    return Receiver._fromWasm(this._wasm.new_receiver(encapKey, domain));
  }

  /**
   * Decrypts a message sealed to this key and checks the second message it
   * authenticates.
   *
   * HPKE runs in base mode, which does not authenticate the sender. The
   * recipient cannot verify who sealed the message.
   *
   * @param sealed - The 1120-byte encapsulated key followed by the
   *   ciphertext, as {@link PublicKey.seal} returns them
   * @param msgToAuth - The same second message used during sealing
   * @param domain - The same application domain used during sealing
   * @returns The decrypted message
   * @throws If the data is malformed, sealed to another key or tampered with,
   *   or `msgToAuth` or `domain` differ
   */
  open(
    sealed: Uint8Array,
    msgToAuth: Uint8Array,
    domain: Uint8Array,
  ): Uint8Array {
    return this._wasm.open(sealed, msgToAuth, domain);
  }
}

/**
 * A stateful HPKE encryption context for multi-message communication, created
 * by {@link PublicKey.newSender}. Each seal uses the next nonce in the
 * sequence, so identical messages encrypt differently. The matching
 * {@link Receiver} must open messages in the order they were sealed.
 */
export class Sender {
  private readonly inner: WasmSender;

  private constructor(inner: WasmSender) {
    this.inner = inner;
  }

  /** @internal */
  static _fromWasm(inner: WasmSender): Sender {
    return new Sender(inner);
  }

  /**
   * Encrypts a message using the next nonce in the sequence.
   *
   * @param msgToSeal - The message to encrypt
   * @param msgToAuth - The message to authenticate but not include
   * @returns The ciphertext
   */
  seal(msgToSeal: Uint8Array, msgToAuth: Uint8Array): Uint8Array {
    return this.inner.seal(msgToSeal, msgToAuth);
  }
}

/**
 * A stateful HPKE decryption context for multi-message communication, created
 * by {@link SecretKey.newReceiver}. Messages must be opened in the order the
 * {@link Sender} sealed them.
 */
export class Receiver {
  private readonly inner: WasmReceiver;

  private constructor(inner: WasmReceiver) {
    this.inner = inner;
  }

  /** @internal */
  static _fromWasm(inner: WasmReceiver): Receiver {
    return new Receiver(inner);
  }

  /**
   * Decrypts a message using the next nonce in the sequence.
   *
   * @param msgToOpen - The ciphertext from {@link Sender.seal}
   * @param msgToAuth - The same second message used during sealing
   * @returns The decrypted message
   * @throws If the message is out of order or was tampered with, or
   *   `msgToAuth` differs
   */
  open(msgToOpen: Uint8Array, msgToAuth: Uint8Array): Uint8Array {
    return this.inner.open(msgToOpen, msgToAuth);
  }
}

/** Private COSE algorithm identifier of X-Wing (ML-KEM-768 + X25519). */
export const ALGORITHM_ID = -70001;

/**
 * Codec of a public key as its 1216 bytes. Decoding throws a
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
