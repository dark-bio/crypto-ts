// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import init, { argon2_key } from "./wasm/darkbio_crypto_wasm.js";

let initialized = false;

async function ensureInit(): Promise<void> {
  if (!initialized) {
    await init();
    initialized = true;
  }
}

/**
 * Derive a key from password, salt, and cost parameters using Argon2id.
 *
 * RFC 9106 Section 7.4 recommends time=1, memory=2048*1024 (2GB) as sensible
 * defaults. If that much memory isn't available, increase time to compensate.
 *
 * @param password - The password to derive from
 * @param salt - A random salt (should be at least 16 bytes)
 * @param time - Number of passes over memory (iterations)
 * @param memory - Memory size in KiB
 * @param threads - Degree of parallelism
 * @param outLen - Desired output length in bytes
 * @returns The derived key
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
  return new Uint8Array(
    argon2_key(password, salt, time, memory, threads, outLen),
  );
}
