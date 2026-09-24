// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/**
 * CBOR Web Tokens on top of COSE Sign1.
 *
 * https://datatracker.ietf.org/doc/html/rfc8392
 *
 * Tokens carry a set of claims encoded as a CBOR map. Standard CWT and EAT
 * claims are declared as fields under {@link claims}. A token's claim set is a
 * `cbor.map` of them, with custom claims as fields at other integer keys.
 *
 * {@link verify} checks the signature against the supplied key and, when
 * requested, the `nbf` and `exp` time bounds. Applications must establish
 * trust in that key, check issuer and audience claims, and apply their own
 * attestation policy. EAT claim relationships and proof of possession of a
 * `cnf` key are not automatically checked.
 *
 * @example
 * ```ts
 * import { cbor, cwt, xdsa } from "@darkbio/crypto";
 *
 * const DeviceCert = cbor.map({
 *   sub: cwt.claims.subject,
 *   exp: cwt.claims.expiration,
 *   nbf: cwt.claims.notBefore,
 *   cnf: cwt.claims.confirmXdsa,
 *   ueid: cwt.claims.eat.ueid,
 * });
 * const issuer = await xdsa.SecretKey.generate();
 * const device = await xdsa.SecretKey.generate();
 * const domain = new TextEncoder().encode("device-cert");
 * const now = 1_700_000_000n;
 *
 * // Example RAND UEID from the generated identity, type 0x01 and 16 identifier bytes.
 * // Provision it once and retain it for the device's lifetime, even if keys change.
 * const ueid = new Uint8Array([0x01, ...device.fingerprint().toBytes().slice(0, 16)]);
 *
 * const cert = { sub: "ark-0001", exp: now + 3600n, nbf: now, cnf: device.publicKey(), ueid };
 * const token = await cwt.issue(DeviceCert.value(cert), issuer, domain);
 *
 * const verified = await cwt.verify(DeviceCert.bytes(token), issuer.publicKey(), domain, now + 60n);
 * console.log(verified.sub, verified.cnf.equals(device.publicKey())); // ark-0001 true
 *
 * // Outside the validity window the token is rejected
 * await cwt.verify(DeviceCert.bytes(token), issuer.publicKey(), domain, now + 7200n).catch(() => {
 *   console.log("expired");
 * });
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
  text,
  uint,
  type Codec,
  type Decodable,
  type Encodable,
} from "./cbor.js";
import { parse, serialize } from "./internal/cborg.js";
import {
  cwt_issue,
  cwt_verify,
  cwt_signer,
  cwt_peek,
} from "./wasm/darkbio_crypto_wasm.js";
import { ensureInit } from "./internal/init.js";
import { U64_MAX } from "./internal/limits.js";
import * as xdsa from "./xdsa.js";
import * as xhpke from "./xhpke.js";

/** The debug port state, per RFC 9711 Section 4.2.9. */
export enum DebugState {
  /** Debug is currently enabled. */
  Enabled = 0,
  /** Debug is currently disabled. */
  Disabled = 1,
  /** Debug was disabled at boot and has not been enabled since. */
  DisabledSinceBoot = 2,
  /**
   * All debug has been disabled since boot. End users and developers cannot
   * re-enable it, but the manufacturer identified by `oemid` may do so. The
   * `oemid` claim must be present, and the application must enforce this.
   */
  DisabledPermanently = 3,
  /**
   * All debug facilities are permanently disabled, including manufacturer
   * facilities, and none can be re-enabled.
   */
  DisabledFullyPermanently = 4,
}

/** The token's intended purpose, per RFC 9711 Section 4.3.3. */
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
 * An OEM identifier in one of the three forms RFC 9711 allows:
 *
 * - `pen`, an IANA private enterprise number
 * - `ieee`, a 3-byte IEEE organizationally unique identifier
 * - `random`, a 16-byte random identifier
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
 * Codec of a version, the text wrapped in a one-element array as RFC 9711
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
 * Codec of a confirmation, a public key the token's subject holds (RFC 8747).
 * The key is wrapped in a COSE_Key of exactly the key type and the key bytes.
 *
 * A verified token authenticates this key binding, but does not prove that
 * the presenter holds the matching secret key. Applications must check that
 * separately using their protocol's proof-of-possession mechanism.
 *
 * @param algorithm - The COSE algorithm identifier of the key type
 * @param key - The codec of the key
 * @returns The codec
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
  /**
   * The expiration time in seconds since the Unix epoch. The token is
   * rejected at or after it (key 4).
   */
  expiration: field(4, uint),
  /**
   * The not-before time in seconds since the Unix epoch. The token is
   * rejected before it (key 5).
   */
  notBefore: field(5, uint),
  /** The issue time in seconds since the Unix epoch (key 6). */
  issuedAt: field(6, uint),
  /** The token identifier, opaque bytes unique to the token (key 7). */
  tokenId: field(7, bytes),
  /**
   * The confirmation, an xDSA public key the subject holds (key 8). A
   * verified token does not prove that the presenter holds the secret key.
   */
  confirmXdsa: field(8, confirmation(xdsa.ALGORITHM_ID, xdsa.publicKey)),
  /**
   * The confirmation, an xHPKE public key the subject holds (key 8). A
   * verified token does not prove that the presenter holds the secret key.
   */
  confirmXhpke: field(8, confirmation(xhpke.ALGORITHM_ID, xhpke.publicKey)),
  /**
   * The Entity Attestation Token claims of RFC 9711.
   *
   * These declare the claims and check their wire representations.
   * Applications must evaluate the claims against their attestation policy and
   * enforce RFC 9711's relationships between claims. For example, `hwModel`
   * and `oemBoot` require `oemid`, `hwVersion` requires `hwModel`, and
   * `swVersion` requires `swName`. {@link DebugState.DisabledPermanently} also
   * requires `oemid`. {@link verify} does not check these relationships.
   */
  eat: {
    /**
     * The universal entity identifier, a globally unique device identifier
     * such as a serial number or IMEI (key 256). Its first byte is the type
     * prefix of RFC 9711 Section 4.2.1.
     *
     * A RAND UEID uses prefix 0x01 followed by 16, 24 or 32 bytes of random
     * identifier data, provisioned once for the device. The bytes are carried
     * as supplied, so callers must check the prefix, length and identifier
     * policy.
     */
    ueid: field(256, bytes),
    /** The hardware manufacturer, in one of the {@link Oemid} forms (key 258). */
    oemid: field(258, oemid),
    /** The product or board model identifier, as the manufacturer defines it (key 259). */
    hwModel: field(259, bytes),
    /** The hardware revision identifier (key 260). */
    hwVersion: field(260, version),
    /** The number of seconds since the last boot (key 261). */
    uptime: field(261, uint),
    /** Whether every boot stage was OEM authorized, so secure boot passed (key 262). */
    oemBoot: field(262, bool),
    /** The state of the device's debug facilities at attestation time (key 263). */
    debugStatus: field(263, enumeration(members(DebugState))),
    /** The number of times the device has booted, never decreasing (key 267). */
    bootCount: field(267, uint),
    /** Random bytes drawn at boot, the same in every token of one boot cycle (key 268). */
    bootSeed: field(268, bytes),
    /** The name of the firmware or software running on the device (key 270). */
    swName: field(270, text),
    /** The software version identifier (key 271). */
    swVersion: field(271, version),
    /** The purpose the token was issued for (key 275). */
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
 * The claims must encode as a CBOR map, such as a `cbor.map` of the
 * {@link claims} fields. Uses the current system time as the COSE signature
 * timestamp.
 *
 * @param claims - The claims to include in the token
 * @param signer - The xDSA secret key to sign with
 * @param domain - Application domain for separating protocol purposes
 * @returns The serialized CWT
 * @throws CodecError if the claims do not fit their codec
 * @throws If the claims do not encode as a CBOR map
 */
export async function issue<C>(
  claims: Encodable<C>,
  signer: xdsa.SecretKey,
  domain: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  return cwt_issue(serialize(claims), signer._wasm, domain);
}

/**
 * Verifies a CWT's COSE signature and temporal validity, then returns the
 * decoded claims.
 *
 * When `now` is given, the `nbf` claim (key 5) must be present and
 * `nbf <= now`. If the `exp` claim (key 4) is present too, `now < exp` must
 * also hold. When `now` is undefined, temporal validation is skipped entirely.
 *
 * The COSE signature timestamp is not checked, since temporal validity comes
 * from the CWT claims. The codec determines the accepted claim schema.
 * Successful verification does not establish issuer trust, enforce an
 * audience, evaluate attestation policy or EAT claim relationships, or prove
 * possession of a confirmation key. The application must perform those checks.
 *
 * @param token - The serialized CWT, bound to the codec of its claims
 * @param verifier - The xDSA public key to verify against
 * @param domain - Application domain for separating protocol purposes
 * @param now - Time of the check in seconds since the Unix epoch, with
 *   fractions rounded down, or undefined to skip the time checks
 * @returns The decoded claims
 * @throws If the token is malformed, does not verify for this key and
 *   `domain`, or fails a time check
 * @throws If `now` is negative or beyond 64 bits
 * @throws CodecError if the claims do not fit their codec
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
  return token.codec.decode(parse(payload));
}

/**
 * Extracts the signer's fingerprint from a CWT without verifying the
 * signature.
 *
 * The fingerprint is unauthenticated. Use it to look up the appropriate
 * verification key before calling {@link verify}.
 *
 * @param token - The serialized CWT
 * @returns The signer's fingerprint
 * @throws If the token is malformed
 */
export async function signer(token: Uint8Array): Promise<xdsa.Fingerprint> {
  await ensureInit();
  return xdsa.Fingerprint._fromWasm(cwt_signer(token));
}

/**
 * Extracts and decodes the claims from a CWT without verifying the signature.
 *
 * The claims are unauthenticated and must not be trusted until verified with
 * {@link verify}. Use {@link signer} to extract the signer's fingerprint for
 * key lookup. The one intended use of this function is self-signed key
 * discovery.
 *
 * @param token - The serialized CWT, bound to the codec of its claims
 * @returns The decoded, unverified claims
 * @throws If the token is malformed
 * @throws CodecError if the claims do not fit their codec
 */
export async function peek<C>(token: Decodable<C>): Promise<C> {
  await ensureInit();
  return token.codec.decode(parse(cwt_peek(token.bytes)));
}
