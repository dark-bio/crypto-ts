// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/**
 * Random bytes from the runtime's secure random source.
 *
 * @example
 * ```ts
 * import { rand } from "@darkbio/crypto";
 *
 * const nonce = await rand.generate(32);
 * console.log(nonce.length); // 32
 * ```
 *
 * @module
 */

import { rand_generate } from "./wasm/darkbio_crypto_wasm.js";
import { ensureInit } from "./internal/init.js";
import { u32 } from "./internal/limits.js";

/**
 * Generates cryptographically secure random bytes.
 *
 * @param bytes - Number of random bytes to generate, at most 64 MiB
 * @returns A new array filled with random bytes
 * @throws If `bytes` is not a whole number between 0 and 64 MiB
 */
export async function generate(bytes: number): Promise<Uint8Array> {
  await ensureInit();
  return new Uint8Array(rand_generate(u32(bytes, "bytes")));
}
