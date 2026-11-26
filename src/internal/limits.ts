// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/** Integer bounds and conversions for the WASM interface. */

/** Largest unsigned 32-bit integer, the WASM size limit. */
export const U32_MAX = 0xffffffff;

/** Largest unsigned 64-bit integer. */
export const U64_MAX = (1n << 64n) - 1n;

/** Smallest signed 64-bit integer. */
export const I64_MIN = -(1n << 63n);

/** Largest signed 64-bit integer. */
export const I64_MAX = (1n << 63n) - 1n;

/**
 * Converts a safe integer or signed 64-bit bigint for a WASM call.
 *
 * @internal
 */
export function i64(value: number | bigint, name: string): bigint {
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    return BigInt(value);
  }
  if (typeof value === "bigint" && value >= I64_MIN && value <= I64_MAX) {
    return value;
  }
  throw new RangeError(
    `${name} must be a safe integer or a signed 64-bit bigint`,
  );
}

/**
 * Checks that a count or size fits an unsigned 32-bit integer.
 *
 * @internal
 */
export function u32(value: number, name: string): number {
  if (!Number.isInteger(value) || value < 0 || value > U32_MAX) {
    throw new Error(`${name} must be a non-negative 32 bit integer`);
  }
  return value;
}
