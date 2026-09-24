// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/**
 * HKDF-SHA256 key derivation.
 *
 * https://datatracker.ietf.org/doc/html/rfc5869
 *
 * Stretches a secret that is already high entropy, a shared secret or a file
 * key, into one or more keys bound to a context string. It is not a password
 * hash; the `argon2` module is the one for that.
 *
 * @example
 * ```ts
 * import { hkdf } from "@darkbio/crypto";
 *
 * const secret = new Uint8Array(32).fill(42);
 * const salt = new Uint8Array();
 * const text = new TextEncoder();
 *
 * // Distinct contexts derive independent keys from the same secret
 * const encryption = await hkdf.key(secret, salt, text.encode("example encryption key"), 32);
 * const authentication = await hkdf.key(secret, salt, text.encode("example authentication key"), 32);
 * ```
 *
 * @module
 */

import {
  hkdf_key,
  hkdf_extract,
  hkdf_expand,
} from "./wasm/darkbio_crypto_wasm.js";
import { ensureInit } from "./internal/init.js";
import { u32 } from "./internal/limits.js";

/**
 * Derives a key from the secret, salt and info using HKDF-SHA256.
 *
 * @param secret - The input keying material, already high entropy
 * @param salt - Optional salt, empty for none
 * @param info - Context the key is bound to, empty for none
 * @param outLen - Length of the key in bytes, at most 8160
 * @returns The derived key
 * @throws If `outLen` is not a whole number between 0 and 8160
 */
export async function key(
  secret: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  outLen: number,
): Promise<Uint8Array> {
  await ensureInit();
  return new Uint8Array(hkdf_key(secret, salt, info, u32(outLen, "outLen")));
}

/**
 * Extracts a 32-byte pseudorandom key from the secret and salt, for use with
 * {@link expand}.
 *
 * Only use this to reuse the extracted key with multiple {@link expand} calls
 * and different contexts. Most scenarios, including the derivation of multiple
 * keys, should use {@link key} instead.
 *
 * @param secret - The input keying material, already high entropy
 * @param salt - Optional salt, empty for none
 * @returns A 32-byte pseudorandom key
 */
export async function extract(
  secret: Uint8Array,
  salt: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  return new Uint8Array(hkdf_extract(secret, salt));
}

/**
 * Derives a key from a pseudorandom key and context info, skipping the
 * extraction step.
 *
 * The pseudorandom key should come from {@link extract}, or be a uniformly
 * random or pseudorandom cryptographically strong key. See RFC 5869 Section
 * 3.3. Most scenarios should use {@link key} instead.
 *
 * @param prk - A 32-byte pseudorandom key
 * @param info - Context the key is bound to, empty for none
 * @param outLen - Length of the key in bytes, at most 8160
 * @returns The derived key
 * @throws If `prk` is not 32 bytes, or `outLen` is not a whole number between
 *   0 and 8160
 */
export async function expand(
  prk: Uint8Array,
  info: Uint8Array,
  outLen: number,
): Promise<Uint8Array> {
  await ensureInit();
  return new Uint8Array(hkdf_expand(prk, info, u32(outLen, "outLen")));
}
