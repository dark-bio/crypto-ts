// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/** Shared initialization of the WASM module. */

import init from "../wasm/darkbio_crypto_wasm.js";

/** Initialization shared by concurrent callers. */
let initPromise: Promise<unknown> | undefined;
/** Whether synchronous codecs can use WASM handles. */
let initComplete = false;

/**
 * Initializes the WASM module. Concurrent callers share the same promise.
 * A failed attempt allows the next caller to retry.
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
 * Requires an initialized WASM module before a synchronous codec imports a key.
 *
 * @internal
 */
export function requireInit(): void {
  if (!initComplete) {
    throw new Error(
      "crypto module not initialized, await any entry point first",
    );
  }
}
