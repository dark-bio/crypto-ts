// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/** Padded sizes, computed before an envelope enters WASM, where a panic would trap the shared instance. */

import type { Padding } from "../cose.js";
import { U32_MAX, u32 } from "./limits.js";

/**
 * Returns the padded plaintext size, rejecting policies that panic on wasm32.
 *
 * @internal
 */
export function paddedSize(length: number, padding: Padding): number {
  // Check the input size and policy before calculating any buckets
  u32(length, "signed envelope length");
  if (padding?.name === "none") return length;
  if (padding?.name !== "buckets") {
    throw new Error("padding name must be none or buckets");
  }
  const { floor, step } = padding;
  for (const [name, value] of [
    ["floor", floor],
    ["step", step],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 1 || value > U32_MAX) {
      throw new Error(`padding ${name} must be a positive 32 bit integer`);
    }
  }

  // Skip consecutive buckets with the same growth to bound the work even
  // when a large step makes billions of buckets grow by one byte each.
  // All intermediate integers fit within 33 bits and stay exact in JS.
  let size = floor;
  while (size < length) {
    const growth = Math.ceil(size / step);
    const count = Math.min(
      Math.ceil((length - size) / growth),
      Math.floor((growth * step - size) / growth) + 1,
    );
    size += count * growth;
    if (size > U32_MAX) {
      throw new Error("padding bucket size exceeds 32 bits");
    }
  }
  return size;
}
