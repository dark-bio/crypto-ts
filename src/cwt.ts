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
 * Tokens carry a set of claims encoded as a CBOR map. Standard CWT and EAT
 * claims are declared as fields under {@link claims}; a token's claim set is a
 * `cbor.map` of them, custom claims being fields at integer keys.
 *
 * @example
 * ```ts
 * import { cbor, cwt, xdsa } from "@darkbio/crypto";
 *
 * const issuerKey = await xdsa.SecretKey.generate();
 * const deviceKey = await xdsa.SecretKey.generate();
 *
 * // Declare the claim set
 * const Claims = cbor.map({
 *   sub: cwt.claims.subject,
 *   nbf: cwt.claims.notBefore,
 *   exp: cwt.claims.expiration,
 *   cnf: cwt.claims.confirmXdsa,
 * });
 *
 * // Issue a token
 * const domain = new TextEncoder().encode("device-cert");
 * const token = await cwt.issue(
 *   Claims.value({ sub: "device-abc", nbf: 1000000n, exp: 2000000n, cnf: deviceKey.publicKey() }),
 *   issuerKey,
 *   domain,
 * );
 *
 * // Verify a token
 * const verified = await cwt.verify(Claims.bytes(token), issuerKey.publicKey(), domain, 1500000);
 * console.log(verified.sub); // "device-abc"
 * ```
 *
 * @module
 */

import {
  bool,
  bytes,
  codec,
  CodecError,
  enumeration,
  field,
  map,
  parse,
  serialize,
  text,
  uint,
  type Codec,
  type Decodable,
  type Encodable,
} from "./cbor.js";
import {
  cwt_issue,
  cwt_verify,
  cwt_signer,
  cwt_peek,
} from "./wasm/darkbio_crypto_wasm.js";
import { ensureInit } from "./init.js";
import { U64_MAX } from "./limits.js";
import * as xdsa from "./xdsa.js";
import * as xhpke from "./xhpke.js";

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
 * An OEM identifier in one of the three forms RFC 9711 allows, an IANA
 * private enterprise number, a 3 byte IEEE organisationally unique identifier
 * or a 16 byte random identifier.
 */
export type Oemid =
  { pen: bigint } | { ieee: Uint8Array } | { random: Uint8Array };

/** Codec of an OEM identifier, an unsigned integer or 3 or 16 bytes. */
export const oemid: Codec<Oemid> = codec(
  (value) => {
    if (typeof value !== "object" || value === null) {
      throw new CodecError("not an OEM identifier");
    }
    const forms = Object.keys(value);
    if (forms.length !== 1) {
      throw new CodecError("not an OEM identifier of exactly one form");
    }
    const data = (value as Record<string, unknown>)[forms[0]];
    switch (forms[0]) {
      case "pen":
        return uint.encode(data as bigint);
      case "ieee":
        if (!(data instanceof Uint8Array) || data.length !== 3) {
          throw new CodecError("IEEE OEM identifier is not 3 bytes");
        }
        return data;
      case "random":
        if (!(data instanceof Uint8Array) || data.length !== 16) {
          throw new CodecError("random OEM identifier is not 16 bytes");
        }
        return data;
      default:
        throw new CodecError("not an OEM identifier");
    }
  },
  (value) => {
    if (value instanceof Uint8Array) {
      if (value.length === 3) {
        return { ieee: value };
      }
      if (value.length === 16) {
        return { random: value };
      }
      throw new CodecError("OEM identifier is not 3 or 16 bytes");
    }
    try {
      return { pen: uint.decode(value) };
    } catch {
      throw new CodecError("not an OEM identifier");
    }
  },
);

/**
 * Codec of a version, the text wrapped in a one element array as RFC 9711
 * has it. The optional scheme element is not supported.
 */
export const version: Codec<string> = codec(
  (value) => [text.encode(value)],
  (value) => {
    if (
      !Array.isArray(value) ||
      value.length !== 1 ||
      typeof value[0] !== "string"
    ) {
      throw new CodecError("not a version");
    }
    return value[0];
  },
);

/**
 * Codec of a confirmation, a public key the token's subject holds, wrapped in
 * a COSE_Key of exactly the key type and the key bytes (RFC 8747).
 *
 * @param algorithm - The COSE algorithm identifier of the key type
 * @param key - The codec of the key
 */
export function confirmation<K>(algorithm: number, key: Codec<K>): Codec<K> {
  const coseKey = map({
    type: field(1, enumeration([algorithm])),
    key: field(-2, key),
  });
  const claim = map({ key: field(1, coseKey) });
  return codec(
    (value: K) => claim.encode({ key: { type: algorithm, key: value } }),
    (value) => claim.decode(value).key.key,
  );
}

/** The numeric members of an enum object. */
function members<E extends number>(values: Record<string, E | string>): E[] {
  return Object.values(values).filter(
    (value): value is E => typeof value === "number",
  );
}

/**
 * The registered claims, RFC 8392 for the token ones and RFC 9711 for the
 * attestation ones under `eat`. A claim set is a `cbor.map` of these.
 */
export const claims = {
  /** The issuer, the principal that issued the token (key 1). */
  issuer: field(1, text),
  /** The subject, the principal the token is about (key 2). */
  subject: field(2, text),
  /** The audience, the recipients the token is meant for (key 3). */
  audience: field(3, text),
  /** The expiration, Unix seconds the token is valid until, exclusive (key 4). */
  expiration: field(4, uint),
  /** The not before time, Unix seconds the token is valid from (key 5). */
  notBefore: field(5, uint),
  /** The issue time, Unix seconds the token was issued (key 6). */
  issuedAt: field(6, uint),
  /** The token identifier, unique to the token (key 7). */
  tokenId: field(7, bytes),
  /** The confirmation, an xDSA public key the subject holds (key 8). */
  confirmXdsa: field(8, confirmation(xdsa.ALGORITHM_ID, xdsa.publicKey)),
  /** The confirmation, an xHPKE public key the subject holds (key 8). */
  confirmXhpke: field(8, confirmation(xhpke.ALGORITHM_ID, xhpke.publicKey)),
  /** The Entity Attestation Token claims of RFC 9711. */
  eat: {
    /** Universal entity identifier (key 256). */
    ueid: field(256, bytes),
    /** OEM identifier (key 258). */
    oemid: field(258, oemid),
    /** Hardware model (key 259). */
    hwModel: field(259, bytes),
    /** Hardware version (key 260). */
    hwVersion: field(260, version),
    /** Seconds since boot (key 261). */
    uptime: field(261, uint),
    /** Whether the entity booted OEM authorised software (key 262). */
    oemBoot: field(262, bool),
    /** Debug state of the entity (key 263). */
    debugStatus: field(263, enumeration(members(DebugState))),
    /** Number of boots (key 267). */
    bootCount: field(267, uint),
    /** Random seed of the boot (key 268). */
    bootSeed: field(268, bytes),
    /** Software name (key 270). */
    swName: field(270, text),
    /** Software version (key 271). */
    swVersion: field(271, version),
    /** Intended use of the token (key 275). */
    intendedUse: field(275, enumeration(members(IntendedUse))),
  },
};

/** Converts the clock of a verification for the WASM boundary. */
function nowToBigInt(now?: number | bigint): bigint | undefined {
  if (now === undefined) return undefined;
  if (
    typeof now !== "bigint" &&
    (typeof now !== "number" || !Number.isFinite(now))
  ) {
    throw new Error("now must be a non-negative Unix timestamp within 64 bits");
  }
  const secs = typeof now === "bigint" ? now : BigInt(Math.floor(now));
  if (secs < 0n || secs > U64_MAX) {
    throw new Error("now must be a non-negative Unix timestamp within 64 bits");
  }
  return secs;
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
export async function issue<C>(
  claims: Encodable<C>,
  signer: xdsa.SecretKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  return new Uint8Array(cwt_issue(serialize(claims), signer._wasm, domain));
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
export async function verify<C>(
  token: Decodable<C>,
  verifier: xdsa.PublicKey,
  domain: Uint8Array,
  now?: number | bigint,
): Promise<C> {
  await ensureInit();
  const payload = cwt_verify(
    token.bytes,
    verifier._wasm,
    domain,
    nowToBigInt(now),
  );
  return token.codec.decode(parse(new Uint8Array(payload)));
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
export async function signer(token: Uint8Array): Promise<xdsa.Fingerprint> {
  await ensureInit();
  return new xdsa.Fingerprint(cwt_signer(token));
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
export async function peek<C>(token: Decodable<C>): Promise<C> {
  await ensureInit();
  return token.codec.decode(parse(new Uint8Array(cwt_peek(token.bytes))));
}
