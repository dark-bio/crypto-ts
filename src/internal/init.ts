// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import init from "../wasm/darkbio_crypto_wasm.js";

let initPromise: Promise<unknown> | undefined;
let initComplete = false;

/**
 * Ensures the WASM module is instantiated exactly once. Concurrent callers
 * share the single in-flight initialization; a failed attempt is cleared so
 * the next call can retry.
 *
 * @internal
 */
export function ensureInit(): Promise<unknown> {
  if (initPromise === undefined) {
    initPromise = init()
      .then((module) => {
        initComplete = true;
        return module;
      })
      .catch((err: unknown) => {
        initPromise = undefined;
        throw err;
      });
  }
  return initPromise;
}

/**
 * Fails unless the WASM module is instantiated, for the synchronous paths a
 * codec takes when it constructs a key. Every async entry point of the
 * package initialises the module, so a codec run after any of them is fine.
 *
 * @internal
 */
export function requireInit(): void {
  if (!initComplete) {
    throw new Error(
      "crypto module not initialised, await any entry point first",
    );
  }
}
