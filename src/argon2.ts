// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/**
 * Argon2id key derivation.
 *
 * https://datatracker.ietf.org/doc/html/rfc9106
 *
 * Turns a password and a salt into key material, made deliberately slow and
 * memory hungry so guessing passwords is expensive. For stretching a secret
 * that is already random, see the `hkdf` module instead.
 *
 * @module
 */

import { argon2_key } from "./wasm/darkbio_crypto_wasm.js";
import { ensureInit } from "./internal/init.js";
import { u32 } from "./internal/limits.js";

/**
 * Derives a key from the password, salt and cost parameters using Argon2id.
 *
 * RFC 9106 Section 4 recommends `time = 1`, `memory = 2 * 1024 * 1024`
 * (2 GiB) and `threads = 4`. Its second recommendation uses `time = 3`,
 * `memory = 64 * 1024` (64 MiB) and `threads = 4`. Both use a random 16-byte
 * salt and a 32-byte output. A single WASM allocation stays below 2 GiB, so
 * only the second profile fits within the memory limit below.
 *
 * `time` is the number of passes and `memory` is the total working memory in
 * KiB. `threads` is Argon2's lane count, an algorithm parameter that changes
 * the derived key. It does not select how many threads compute the key. Store
 * the salt and all cost parameters so the same key can be reproduced on other
 * devices.
 *
 * The parameters must stay within these limits:
 *
 * - `time` must be at least 1.
 * - `threads` must be at least 1.
 * - `memory` must be at least `8 * threads` KiB and at most 2097151 KiB, one
 *   KiB short of 2 GiB.
 * - `salt` must be at least 8 bytes.
 * - `outLen` must be at least 4 bytes and at most 2147483647 bytes.
 *
 * @example
 * ```ts
 * import { argon2 } from "@darkbio/crypto";
 *
 * // Example salt only; generate and store a fresh random 16-byte salt in real code
 * const salt = new TextEncoder().encode("example salt1234");
 * const password = new TextEncoder().encode("password");
 *
 * // RFC 9106's recommended profile for memory-constrained environments
 * const key = await argon2.key(password, salt, 3, 64 * 1024, 4, 32);
 * console.log(key.length); // 32
 * ```
 *
 * @param password - The password to derive from
 * @param salt - A random salt, at least 8 bytes and 16 bytes recommended
 * @param time - Number of passes over the memory
 * @param memory - Size of the working memory in KiB
 * @param threads - Argon2's lane count
 * @param outLen - Length of the key in bytes
 * @returns The derived key
 * @throws If a parameter is outside the limits above, or the working memory
 *   cannot be allocated
 */
export async function key(
  password: Uint8Array,
  salt: Uint8Array,
  time: number,
  memory: number,
  threads: number,
  outLen: number,
): Promise<Uint8Array> {
  await ensureInit();
  return argon2_key(
    password,
    salt,
    u32(time, "time"),
    u32(memory, "memory"),
    u32(threads, "threads"),
    u32(outLen, "outLen"),
  );
}
