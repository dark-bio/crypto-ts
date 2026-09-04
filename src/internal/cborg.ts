// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import { encode as cborgEncode, decode as cborgDecode } from "cborg";
import type { Encodable } from "../cbor.js";

/**
 * Decodes bytes the Rust validator already checked into what cborg makes of
 * them, maps as `Map`.
 *
 * @internal
 */
export function parse(data: Uint8Array): unknown {
  return cborgDecode(data, {
    useMaps: true,
    rejectDuplicateMapKeys: true,
  }) as unknown;
}

/**
 * Serializes a value bound to its codec into the bytes the WASM boundary
 * takes, canonical by cborg's ordering and verified again on the Rust side.
 *
 * @internal
 */
export function serialize<T>(item: Encodable<T>): Uint8Array {
  return cborgEncode(item.codec.encode(item.value));
}
