// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import init, {
  xhpke_secret_key_size,
  xhpke_public_key_size,
  xhpke_encap_key_size,
  xhpke_fingerprint_size,
  xhpke_generate,
  xhpke_public_key,
  xhpke_fingerprint,
  xhpke_seal,
  xhpke_open,
  xhpke_secret_key_from_pem,
  xhpke_secret_key_to_pem,
  xhpke_public_key_from_pem,
  xhpke_public_key_to_pem,
} from "./wasm/darkbio_crypto_wasm.js";

let initialized = false;

async function ensureInit(): Promise<void> {
  if (!initialized) {
    await init();
    initialized = true;
  }
}

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
 * It is the SHA256 hash of the raw public key.
 */
export class Fingerprint {
  private readonly bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  /** Converts a 32-byte array into a fingerprint. */
  static fromBytes(bytes: Uint8Array): Fingerprint {
    if (bytes.length !== FINGERPRINT_SIZE) {
      throw new Error(`Fingerprint must be ${FINGERPRINT_SIZE} bytes`);
    }
    return new Fingerprint(new Uint8Array(bytes));
  }

  /** Converts a fingerprint into a 32-byte array. */
  toBytes(): Uint8Array {
    return new Uint8Array(this.bytes);
  }
}

/**
 * PublicKey contains an X-Wing public key for hybrid post-quantum encryption.
 * Uses X-Wing KEM (ML-KEM-768 + X25519) with HPKE Base mode.
 */
export class PublicKey {
  private readonly bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  /**
   * Converts a 1216-byte array into a public key.
   *
   * This validates the ML-KEM-768 component by checking that all polynomial
   * coefficients are in the valid range [0, 3329).
   */
  static fromBytes(bytes: Uint8Array): PublicKey {
    if (bytes.length !== PUBLIC_KEY_SIZE) {
      throw new Error(`PublicKey must be ${PUBLIC_KEY_SIZE} bytes`);
    }
    return new PublicKey(new Uint8Array(bytes));
  }

  /** Parses a PEM string into a public key. */
  static async fromPem(pem: string): Promise<PublicKey> {
    await ensureInit();
    const bytes = new Uint8Array(xhpke_public_key_from_pem(pem));
    return new PublicKey(bytes);
  }

  /** Converts a public key into a 1216-byte array. */
  toBytes(): Uint8Array {
    return new Uint8Array(this.bytes);
  }

  /** Serializes a public key into a PEM string. */
  async toPem(): Promise<string> {
    await ensureInit();
    return xhpke_public_key_to_pem(this.bytes);
  }

  /** Returns a 256-bit unique identifier for this key (SHA256 of raw public key). */
  async fingerprint(): Promise<Fingerprint> {
    await ensureInit();
    const fp = new Uint8Array(xhpke_fingerprint(this.bytes));
    return Fingerprint.fromBytes(fp);
  }

  /**
   * Seal (encrypt) a message to this public key.
   *
   * Uses X-Wing KEM (ML-KEM-768 + X25519) with HPKE Base mode.
   *
   * @param msgToSeal - The message to encrypt
   * @param msgToAuth - Additional data to authenticate (but not encrypt)
   * @param domain - Application domain for context separation
   * @returns Sealed data (encapsulated key + ciphertext)
   */
  async seal(
    msgToSeal: Uint8Array,
    msgToAuth: Uint8Array,
    domain: Uint8Array,
  ): Promise<Uint8Array> {
    await ensureInit();
    return new Uint8Array(xhpke_seal(this.bytes, msgToSeal, msgToAuth, domain));
  }
}

/**
 * SecretKey contains an X-Wing private key for hybrid post-quantum encryption.
 * Uses X-Wing KEM (ML-KEM-768 + X25519) with HPKE Base mode.
 */
export class SecretKey {
  private readonly bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  /** Creates a new, random private key. */
  static async generate(): Promise<SecretKey> {
    await ensureInit();
    const bytes = new Uint8Array(xhpke_generate());
    return new SecretKey(bytes);
  }

  /** Converts a 32-byte seed into a private key. */
  static fromBytes(bytes: Uint8Array): SecretKey {
    if (bytes.length !== SECRET_KEY_SIZE) {
      throw new Error(`SecretKey must be ${SECRET_KEY_SIZE} bytes`);
    }
    return new SecretKey(new Uint8Array(bytes));
  }

  /** Parses a PEM string into a private key. */
  static async fromPem(pem: string): Promise<SecretKey> {
    await ensureInit();
    const bytes = new Uint8Array(xhpke_secret_key_from_pem(pem));
    return new SecretKey(bytes);
  }

  /** Converts a private key into a 32-byte seed. */
  toBytes(): Uint8Array {
    return new Uint8Array(this.bytes);
  }

  /** Serializes a private key into a PEM string. */
  async toPem(): Promise<string> {
    await ensureInit();
    return xhpke_secret_key_to_pem(this.bytes);
  }

  /** Retrieves the public counterpart of the secret key. */
  async publicKey(): Promise<PublicKey> {
    await ensureInit();
    const pk = new Uint8Array(xhpke_public_key(this.bytes));
    return PublicKey.fromBytes(pk);
  }

  /** Returns a 256-bit unique identifier for this key (SHA256 of raw public key). */
  async fingerprint(): Promise<Fingerprint> {
    const pk = await this.publicKey();
    return pk.fingerprint();
  }

  /**
   * Open (decrypt) a sealed message with this secret key.
   *
   * Deconstructs the encapsulated key and ciphertext, verifying the
   * authenticity of the (unencrypted) message-to-auth.
   *
   * Note: X-Wing uses Base mode (no sender authentication). The sender's
   * identity cannot be verified from the ciphertext alone.
   *
   * @param sealed - The sealed data from `seal()`
   * @param msgToAuth - The same additional authenticated data used during sealing
   * @param domain - The same application domain used during sealing
   * @returns The decrypted message
   * @throws If decryption fails (wrong key, tampered data, or wrong AAD/domain)
   */
  async open(
    sealed: Uint8Array,
    msgToAuth: Uint8Array,
    domain: Uint8Array,
  ): Promise<Uint8Array> {
    await ensureInit();
    return new Uint8Array(xhpke_open(this.bytes, sealed, msgToAuth, domain));
  }
}
