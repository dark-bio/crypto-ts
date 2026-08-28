// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import { cbor_verify } from "./wasm/darkbio_crypto_wasm.js";
import { ensureInit } from "./init.js";

/**
 * Verify that data is valid CBOR under the restricted deterministic type
 * system used across the darkbio ecosystem (booleans, null, 64-bit integers,
 * text strings, byte strings, arrays, and integer-keyed maps).
 *
 * The COSE and CWT functions run this check internally on every payload they
 * sign or embed; use it directly to pre-check hand-rolled encodings such as
 * custom claim values.
 *
 * @param data - The CBOR bytes to validate
 * @throws If the data is not valid restricted CBOR
 */
export async function verify(data: Uint8Array): Promise<void> {
  await ensureInit();
  cbor_verify(data);
}
