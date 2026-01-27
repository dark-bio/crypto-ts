// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import init, {
  xdsa_secret_key_size,
  xdsa_public_key_size,
  xdsa_signature_size,
  xdsa_fingerprint_size,
  xdsa_generate,
  xdsa_public_key,
  xdsa_fingerprint,
  xdsa_sign,
  xdsa_verify,
  xdsa_secret_key_from_pem,
  xdsa_secret_key_to_pem,
  xdsa_public_key_from_pem,
  xdsa_public_key_to_pem,
  xdsa_public_key_from_cert_pem,
  xdsa_public_key_from_cert_der,
  xdsa_public_key_to_cert_pem,
  xdsa_public_key_to_cert_der,
} from "./wasm/darkbio_crypto_wasm.js";

import type { Params } from "./x509.js";

let initialized = false;

async function ensureInit(): Promise<void> {
  if (!initialized) {
    await init();
    initialized = true;
  }
}

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
 * Signature is a 3373-byte xDSA signature.
 * Format: ML-DSA (3309 bytes) || Ed25519 (64 bytes)
 */
export class Signature {
  private readonly bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  /** Converts a 3373-byte array into a signature. */
  static fromBytes(bytes: Uint8Array): Signature {
    if (bytes.length !== SIGNATURE_SIZE) {
      throw new Error(`Signature must be ${SIGNATURE_SIZE} bytes`);
    }
    return new Signature(new Uint8Array(bytes));
  }

  /** Converts a signature into a 3373-byte array. */
  toBytes(): Uint8Array {
    return new Uint8Array(this.bytes);
  }
}

/**
 * PublicKey is an ML-DSA-65 public key paired with an Ed25519 public key for
 * verifying quantum resistant digital signatures.
 * Format: ML-DSA (1952 bytes) || Ed25519 (32 bytes)
 */
export class PublicKey {
  private readonly bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  /** Converts a 1984-byte array into a public key. */
  static fromBytes(bytes: Uint8Array): PublicKey {
    if (bytes.length !== PUBLIC_KEY_SIZE) {
      throw new Error(`PublicKey must be ${PUBLIC_KEY_SIZE} bytes`);
    }
    return new PublicKey(new Uint8Array(bytes));
  }

  /** Parses a PEM string into a public key. */
  static async fromPem(pem: string): Promise<PublicKey> {
    await ensureInit();
    const bytes = new Uint8Array(xdsa_public_key_from_pem(pem));
    return new PublicKey(bytes);
  }

  /**
   * Parses a public key from a PEM-encoded X.509 certificate.
   * Verifies the certificate signature against the provided signer.
   *
   * @param pem - PEM-encoded X.509 certificate
   * @param signer - The xDSA public key that signed this certificate
   * @returns The parsed public key and validity period (notBefore, notAfter as Unix timestamps)
   */
  static async fromCertPem(
    pem: string,
    signer: PublicKey,
  ): Promise<{ key: PublicKey; notBefore: bigint; notAfter: bigint }> {
    await ensureInit();
    const result = new Uint8Array(
      xdsa_public_key_from_cert_pem(pem, signer.toBytes()),
    );
    const key = new PublicKey(result.slice(0, PUBLIC_KEY_SIZE));
    const view = new DataView(result.buffer, result.byteOffset + PUBLIC_KEY_SIZE);
    const notBefore = view.getBigUint64(0, false);
    const notAfter = view.getBigUint64(8, false);
    return { key, notBefore, notAfter };
  }

  /**
   * Parses a public key from a DER-encoded X.509 certificate.
   * Verifies the certificate signature against the provided signer.
   *
   * @param der - DER-encoded X.509 certificate
   * @param signer - The xDSA public key that signed this certificate
   * @returns The parsed public key and validity period (notBefore, notAfter as Unix timestamps)
   */
  static async fromCertDer(
    der: Uint8Array,
    signer: PublicKey,
  ): Promise<{ key: PublicKey; notBefore: bigint; notAfter: bigint }> {
    await ensureInit();
    const result = new Uint8Array(
      xdsa_public_key_from_cert_der(der, signer.toBytes()),
    );
    const key = new PublicKey(result.slice(0, PUBLIC_KEY_SIZE));
    const view = new DataView(result.buffer, result.byteOffset + PUBLIC_KEY_SIZE);
    const notBefore = view.getBigUint64(0, false);
    const notAfter = view.getBigUint64(8, false);
    return { key, notBefore, notAfter };
  }

  /** Converts a public key into a 1984-byte array. */
  toBytes(): Uint8Array {
    return new Uint8Array(this.bytes);
  }

  /** Serializes a public key into a PEM string. */
  async toPem(): Promise<string> {
    await ensureInit();
    return xdsa_public_key_to_pem(this.bytes);
  }

  /** Returns a 256-bit unique identifier for this key. */
  async fingerprint(): Promise<Fingerprint> {
    await ensureInit();
    const fp = new Uint8Array(xdsa_fingerprint(this.bytes));
    return Fingerprint.fromBytes(fp);
  }

  /** Verifies a digital signature of the message. */
  async verify(message: Uint8Array, signature: Signature): Promise<boolean> {
    await ensureInit();
    return xdsa_verify(this.bytes, message, signature.toBytes());
  }

  /**
   * Generates a PEM-encoded X.509 certificate for this public key.
   *
   * @param signer - The xDSA secret key to sign the certificate
   * @param params - Certificate parameters (subject, issuer, validity, etc.)
   * @returns PEM-encoded X.509 certificate
   */
  async toCertPem(signer: SecretKey, params: Params): Promise<string> {
    await ensureInit();
    return xdsa_public_key_to_cert_pem(
      this.bytes,
      signer.toBytes(),
      params.subjectName,
      params.issuerName,
      params.notBefore,
      params.notAfter,
      params.isCa ?? false,
      params.pathLen,
    );
  }

  /**
   * Generates a DER-encoded X.509 certificate for this public key.
   *
   * @param signer - The xDSA secret key to sign the certificate
   * @param params - Certificate parameters (subject, issuer, validity, etc.)
   * @returns DER-encoded X.509 certificate
   */
  async toCertDer(signer: SecretKey, params: Params): Promise<Uint8Array> {
    await ensureInit();
    return new Uint8Array(
      xdsa_public_key_to_cert_der(
        this.bytes,
        signer.toBytes(),
        params.subjectName,
        params.issuerName,
        params.notBefore,
        params.notAfter,
        params.isCa ?? false,
        params.pathLen,
      ),
    );
  }
}

/**
 * SecretKey is an ML-DSA-65 private key paired with an Ed25519 private key for
 * creating quantum resistant digital signatures.
 * Format: ML-DSA seed (32 bytes) || Ed25519 seed (32 bytes)
 */
export class SecretKey {
  private readonly bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  /** Creates a new, random private key. */
  static async generate(): Promise<SecretKey> {
    await ensureInit();
    const bytes = new Uint8Array(xdsa_generate());
    return new SecretKey(bytes);
  }

  /** Creates a private key from a 64-byte seed. */
  static fromBytes(bytes: Uint8Array): SecretKey {
    if (bytes.length !== SECRET_KEY_SIZE) {
      throw new Error(`SecretKey must be ${SECRET_KEY_SIZE} bytes`);
    }
    return new SecretKey(new Uint8Array(bytes));
  }

  /** Parses a PEM string into a private key. */
  static async fromPem(pem: string): Promise<SecretKey> {
    await ensureInit();
    const bytes = new Uint8Array(xdsa_secret_key_from_pem(pem));
    return new SecretKey(bytes);
  }

  /** Converts a secret key into a 64-byte array. */
  toBytes(): Uint8Array {
    return new Uint8Array(this.bytes);
  }

  /** Serializes a private key into a PEM string. */
  async toPem(): Promise<string> {
    await ensureInit();
    return xdsa_secret_key_to_pem(this.bytes);
  }

  /** Retrieves the public counterpart of the secret key. */
  async publicKey(): Promise<PublicKey> {
    await ensureInit();
    const pk = new Uint8Array(xdsa_public_key(this.bytes));
    return PublicKey.fromBytes(pk);
  }

  /** Returns a 256-bit unique identifier for this key. */
  async fingerprint(): Promise<Fingerprint> {
    const pk = await this.publicKey();
    return pk.fingerprint();
  }

  /** Creates a digital signature of the message. */
  async sign(message: Uint8Array): Promise<Signature> {
    await ensureInit();
    const sig = new Uint8Array(xdsa_sign(this.bytes, message));
    return Signature.fromBytes(sig);
  }
}
