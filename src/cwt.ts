// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/**
 * CBOR Web Tokens (CWT) on top of COSE Sign1.
 *
 * https://datatracker.ietf.org/doc/html/rfc8392
 *
 * Tokens carry a set of {@link Claims} encoded as a CBOR map. Standard CWT and
 * EAT claims have typed accessors; custom claims use integer keys via
 * `get()` / `set()`.
 *
 * @example
 * ```ts
 * import { cwt, xdsa } from "@darkbio/crypto";
 *
 * const issuerKey = await xdsa.SecretKey.generate();
 * const deviceKey = await xdsa.SecretKey.generate();
 *
 * // Issue a token
 * const claims = new cwt.Claims();
 * claims.subject = "device-abc";
 * claims.notBefore = 1000000;
 * claims.expiration = 2000000;
 * claims.setConfirmXdsa(deviceKey.publicKey());
 *
 * const domain = new TextEncoder().encode("device-cert");
 * const token = await cwt.issue(claims, issuerKey, domain);
 *
 * // Verify a token
 * const verified = await cwt.verify(token, issuerKey.publicKey(), domain, 1500000);
 * console.log(verified.subject); // "device-abc"
 * ```
 *
 * @module
 */

import { encode as cborEncode, decode as cborDecodeRaw } from "cborg";
import {
  cwt_issue,
  cwt_verify,
  cwt_signer,
  cwt_peek,
} from "./wasm/darkbio_crypto_wasm.js";
import { ensureInit } from "./init.js";
import {
  SecretKey as XdsaSecretKey,
  PublicKey as XdsaPublicKey,
  Fingerprint as XdsaFingerprint,
} from "./xdsa.js";
import { PublicKey as XhpkePublicKey } from "./xhpke.js";

// COSE algorithm identifiers used in Confirm claim encoding.
const ALGORITHM_ID_XDSA = -70000;
const ALGORITHM_ID_XHPKE = -70001;

/**
 * Debug port state per RFC 9711 Section 4.2.9.
 */
export enum DebugState {
  /** Debug is currently enabled. */
  Enabled = 0,
  /** Debug is currently disabled. */
  Disabled = 1,
  /** Debug was disabled at boot and has not been enabled since. */
  DisabledSinceBoot = 2,
  /** Debug is disabled and cannot be re-enabled. */
  DisabledPermanently = 3,
  /** All debug, including DMA-based, is permanently disabled. */
  DisabledFullyPermanently = 4,
}

/**
 * Token intended purpose per RFC 9711 Section 4.3.3.
 */
export enum IntendedUse {
  /** General-purpose attestation. */
  Generic = 1,
  /** Attestation for service registration. */
  Registration = 2,
  /** Attestation prior to key/config provisioning. */
  Provisioning = 3,
  /** Attestation for certificate signing requests. */
  CertIssuance = 4,
  /** Attestation accompanying a proof-of-possession. */
  ProofOfPossession = 5,
}

/**
 * A CWT claims set with typed accessors for standard CWT (RFC 8392) and
 * EAT (RFC 9711) claims.
 *
 * Standard claims are exposed as typed properties. Custom or application-
 * specific claims can be accessed via `get()` / `set()` using their integer key.
 */
export class Claims {
  private readonly map: Map<number, unknown>;

  /** Creates an empty claims set. */
  constructor() {
    this.map = new Map();
  }

  private static fromMap(map: Map<number, unknown>): Claims {
    const c = new Claims();
    for (const [k, v] of map) {
      c.map.set(k, v);
    }
    return c;
  }

  /** Issuer: identifies the principal that issued the token (key 1). */
  get issuer(): string | undefined {
    return this.map.get(1) as string | undefined;
  }
  set issuer(value: string | undefined) {
    this.setOrDelete(1, value);
  }

  /** Subject: identifies the principal that is the subject of the token (key 2). */
  get subject(): string | undefined {
    return this.map.get(2) as string | undefined;
  }
  set subject(value: string | undefined) {
    this.setOrDelete(2, value);
  }

  /** Audience: identifies the recipients the token is intended for (key 3). */
  get audience(): string | undefined {
    return this.map.get(3) as string | undefined;
  }
  set audience(value: string | undefined) {
    this.setOrDelete(3, value);
  }

  /**
   * Expiration: the time on or after which the token must not be accepted
   * (key 4, Unix timestamp in seconds).
   */
  get expiration(): number | undefined {
    return this.map.get(4) as number | undefined;
  }
  set expiration(value: number | undefined) {
    this.setOrDelete(4, value);
  }

  /**
   * NotBefore: the time before which the token must not be accepted
   * (key 5, Unix timestamp in seconds).
   */
  get notBefore(): number | undefined {
    return this.map.get(5) as number | undefined;
  }
  set notBefore(value: number | undefined) {
    this.setOrDelete(5, value);
  }

  /**
   * IssuedAt: the time at which the token was issued
   * (key 6, Unix timestamp in seconds).
   */
  get issuedAt(): number | undefined {
    return this.map.get(6) as number | undefined;
  }
  set issuedAt(value: number | undefined) {
    this.setOrDelete(6, value);
  }

  /** TokenID: a unique identifier for the token (key 7). */
  get tokenId(): Uint8Array | undefined {
    return this.map.get(7) as Uint8Array | undefined;
  }
  set tokenId(value: Uint8Array | undefined) {
    this.setOrDelete(7, value);
  }

  /**
   * Sets the Confirm claim to bind an xDSA public key to this token.
   * Encoded as: `{8: {1: {1: -70000, -2: <key_bytes>}}}`
   */
  setConfirmXdsa(key: XdsaPublicKey): void {
    this.map.set(
      8,
      new Map<number, unknown>([
        [
          1,
          new Map<number, unknown>([
            [1, ALGORITHM_ID_XDSA],
            [-2, key.toBytes()],
          ]),
        ],
      ]),
    );
  }

  /**
   * Sets the Confirm claim to bind an xHPKE public key to this token.
   * Encoded as: `{8: {1: {1: -70001, -2: <key_bytes>}}}`
   */
  setConfirmXhpke(key: XhpkePublicKey): void {
    this.map.set(
      8,
      new Map<number, unknown>([
        [
          1,
          new Map<number, unknown>([
            [1, ALGORITHM_ID_XHPKE],
            [-2, key.toBytes()],
          ]),
        ],
      ]),
    );
  }

  /**
   * Extracts the bound xDSA public key from the Confirm claim, or undefined
   * if absent or a different key type.
   */
  async getConfirmXdsa(): Promise<XdsaPublicKey | undefined> {
    const { kty, keyBytes } = this.readConfirm();
    if (kty !== ALGORITHM_ID_XDSA || !keyBytes) return undefined;
    return XdsaPublicKey.fromBytes(keyBytes);
  }

  /**
   * Extracts the bound xHPKE public key from the Confirm claim, or undefined
   * if absent or a different key type.
   */
  async getConfirmXhpke(): Promise<XhpkePublicKey | undefined> {
    const { kty, keyBytes } = this.readConfirm();
    if (kty !== ALGORITHM_ID_XHPKE || !keyBytes) return undefined;
    return XhpkePublicKey.fromBytes(keyBytes);
  }

  private readConfirm(): {
    kty: number | undefined;
    keyBytes: Uint8Array | undefined;
  } {
    const cnf = this.map.get(8);
    if (!(cnf instanceof Map)) return { kty: undefined, keyBytes: undefined };
    const coseKey = cnf.get(1);
    if (!(coseKey instanceof Map))
      return { kty: undefined, keyBytes: undefined };
    const kty = coseKey.get(1) as number | undefined;
    const keyBytes = coseKey.get(-2) as Uint8Array | undefined;
    if (typeof kty !== "number" || !(keyBytes instanceof Uint8Array)) {
      return { kty: undefined, keyBytes: undefined };
    }
    return { kty, keyBytes };
  }

  /** UEID: a globally unique device identifier (key 256). */
  get ueid(): Uint8Array | undefined {
    return this.map.get(256) as Uint8Array | undefined;
  }
  set ueid(value: Uint8Array | undefined) {
    this.setOrDelete(256, value);
  }

  /**
   * OEMID: hardware manufacturer identifier (key 258).
   *
   * Use {@link setOemidRandom}, {@link setOemidIeee}, or {@link setOemidPen} to set.
   * The getter returns the raw CBOR value (Uint8Array or number).
   */
  get oemid(): Uint8Array | number | undefined {
    return this.map.get(258) as Uint8Array | number | undefined;
  }

  /** Sets OEMID to a 16-byte random manufacturer identifier. */
  setOemidRandom(id: Uint8Array): void {
    if (id.length !== 16) {
      throw new Error(`OEMID random must be 16 bytes, got ${id.length}`);
    }
    this.map.set(258, new Uint8Array(id));
  }

  /** Sets OEMID to a 3-byte IEEE OUI/MA-L. */
  setOemidIeee(id: Uint8Array): void {
    if (id.length !== 3) {
      throw new Error(`OEMID IEEE must be 3 bytes, got ${id.length}`);
    }
    this.map.set(258, new Uint8Array(id));
  }

  /** Sets OEMID to an IANA Private Enterprise Number. */
  setOemidPen(pen: number): void {
    this.map.set(258, pen);
  }

  /** HwModel: product or board model identifier (key 259). */
  get hwModel(): Uint8Array | undefined {
    return this.map.get(259) as Uint8Array | undefined;
  }
  set hwModel(value: Uint8Array | undefined) {
    this.setOrDelete(259, value);
  }

  /**
   * HwVersion: hardware revision identifier (key 260).
   * Stored as a 1-element CBOR array per RFC 9711 Section 4.2.5.
   */
  get hwVersion(): string | undefined {
    const v = this.map.get(260);
    if (Array.isArray(v) && v.length > 0) return v[0] as string;
    return undefined;
  }
  set hwVersion(value: string | undefined) {
    this.setOrDelete(260, value !== undefined ? [value] : undefined);
  }

  /** Uptime: seconds since last boot (key 261). */
  get uptime(): number | undefined {
    return this.map.get(261) as number | undefined;
  }
  set uptime(value: number | undefined) {
    this.setOrDelete(261, value);
  }

  /** OemBoot: whether the boot chain is OEM-authorized (key 262). */
  get oemBoot(): boolean | undefined {
    return this.map.get(262) as boolean | undefined;
  }
  set oemBoot(value: boolean | undefined) {
    this.setOrDelete(262, value);
  }

  /** DebugStatus: debug port state (key 263). */
  get debugStatus(): DebugState | undefined {
    const v = this.map.get(263);
    if (typeof v !== "number" || v < 0 || v > 4) return undefined;
    return v as DebugState;
  }
  set debugStatus(value: DebugState | undefined) {
    this.setOrDelete(263, value);
  }

  /** BootCount: number of times the device has booted (key 267). */
  get bootCount(): number | undefined {
    return this.map.get(267) as number | undefined;
  }
  set bootCount(value: number | undefined) {
    this.setOrDelete(267, value);
  }

  /** BootSeed: random value unique to the current boot cycle (key 268). */
  get bootSeed(): Uint8Array | undefined {
    return this.map.get(268) as Uint8Array | undefined;
  }
  set bootSeed(value: Uint8Array | undefined) {
    this.setOrDelete(268, value);
  }

  /** SwName: name of the firmware or software (key 270). */
  get swName(): string | undefined {
    return this.map.get(270) as string | undefined;
  }
  set swName(value: string | undefined) {
    this.setOrDelete(270, value);
  }

  /**
   * SwVersion: software version identifier (key 271).
   * Stored as a 1-element CBOR array per RFC 9711 Section 4.2.7.
   */
  get swVersion(): string | undefined {
    const v = this.map.get(271);
    if (Array.isArray(v) && v.length > 0) return v[0] as string;
    return undefined;
  }
  set swVersion(value: string | undefined) {
    this.setOrDelete(271, value !== undefined ? [value] : undefined);
  }

  /** IntendedUse: the token's purpose (key 275). */
  get intendedUse(): IntendedUse | undefined {
    const v = this.map.get(275);
    if (typeof v !== "number" || v < 1 || v > 5) return undefined;
    return v as IntendedUse;
  }
  set intendedUse(value: IntendedUse | undefined) {
    this.setOrDelete(275, value);
  }

  /** Gets a custom claim by its integer key. */
  get(key: number): unknown {
    return this.map.get(key);
  }

  /** Sets a custom claim by its integer key. */
  set(key: number, value: unknown): void {
    this.setOrDelete(key, value);
  }

  private setOrDelete(key: number, value: unknown): void {
    if (value !== undefined && value !== null) {
      this.map.set(key, value);
    } else {
      this.map.delete(key);
    }
  }

  /** Encodes the claims to CBOR bytes. @internal */
  encode(): Uint8Array {
    return Uint8Array.from(cborEncode(this.map));
  }

  /** Decodes claims from CBOR bytes. @internal */
  static decode(bytes: Uint8Array): Claims {
    const decoded = cborDecodeRaw(bytes, { useMaps: true });
    if (!(decoded instanceof Map)) {
      throw new Error("CWT claims must be a CBOR map");
    }
    const map = new Map<number, unknown>();
    for (const [k, v] of decoded) {
      if (typeof k !== "number") {
        throw new Error(`CWT claim key must be an integer, got ${typeof k}`);
      }
      map.set(k, v);
    }
    return Claims.fromMap(map);
  }
}

/**
 * Issues a CWT by signing the claims with COSE Sign1.
 *
 * Uses the current system time as the COSE signature timestamp.
 *
 * @param claims - The claims to include in the token
 * @param signer - The xDSA secret key to sign with
 * @param domain - Application-specific domain separator
 * @returns The serialized CWT
 */
export async function issue(
  claims: Claims,
  signer: XdsaSecretKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  const claimsCbor = claims.encode();
  return new Uint8Array(cwt_issue(claimsCbor, signer._wasm, domain));
}

/**
 * Verifies a CWT's COSE signature and temporal validity, then returns the
 * decoded claims.
 *
 * When `now` is provided (Unix timestamp in seconds), temporal claims are
 * validated: nbf must be present and `nbf <= now`, and if exp is present
 * then `now < exp`. When `now` is undefined, temporal validation is skipped.
 *
 * @param token - The serialized CWT
 * @param verifier - The xDSA public key to verify against
 * @param domain - Application-specific domain separator
 * @param now - Current Unix timestamp for temporal validation (undefined to skip)
 * @returns The decoded claims
 */
export async function verify(
  token: Uint8Array,
  verifier: XdsaPublicKey,
  domain: Uint8Array,
  now?: number,
): Promise<Claims> {
  await ensureInit();
  if (now !== undefined && (!Number.isFinite(now) || now < 0)) {
    throw new Error("now must be a non-negative Unix timestamp");
  }
  const claimsCbor = cwt_verify(
    token,
    verifier._wasm,
    domain,
    now !== undefined ? BigInt(Math.floor(now)) : undefined,
  );
  return Claims.decode(new Uint8Array(claimsCbor));
}

/**
 * Extracts the signer's fingerprint from a CWT without verifying.
 *
 * The returned data is unauthenticated. Use this to look up the appropriate
 * verification key before calling {@link verify}.
 *
 * @param token - The serialized CWT
 * @returns The signer fingerprint
 */
export async function signer(token: Uint8Array): Promise<XdsaFingerprint> {
  await ensureInit();
  return new XdsaFingerprint(cwt_signer(token));
}

/**
 * Extracts claims from a CWT without verifying the signature.
 *
 * **Warning**: The returned payload is unauthenticated and should not be
 * trusted until verified with {@link verify}. Use {@link signer} to extract
 * the signer's fingerprint for key lookup.
 *
 * @param token - The serialized CWT
 * @returns The decoded (but unverified) claims
 */
export async function peek(token: Uint8Array): Promise<Claims> {
  await ensureInit();
  const claimsCbor = cwt_peek(token);
  return Claims.decode(new Uint8Array(claimsCbor));
}
