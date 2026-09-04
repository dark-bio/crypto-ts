// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import { rand_generate } from "./wasm/darkbio_crypto_wasm.js";
import { ensureInit } from "./init.js";
import { u32 } from "./limits.js";

/**
 * Generate cryptographically secure random bytes.
 *
 * @param bytes - Number of random bytes to generate (max 64 MiB)
 * @returns A Uint8Array containing the random bytes
 */
export async function generate(bytes: number): Promise<Uint8Array> {
  await ensureInit();
  return new Uint8Array(rand_generate(u32(bytes, "bytes")));
}
