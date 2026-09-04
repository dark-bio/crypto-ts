// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/** Largest 32 bit unsigned integer, the size type of the WASM module. */
export const U32_MAX = 0xffffffff;

/** Largest 64 bit unsigned integer. */
export const U64_MAX = (1n << 64n) - 1n;

/**
 * Checks a count or size fits the 32 bit unsigned integers of the WASM
 * module, which would otherwise wrap it.
 *
 * @internal
 */
export function u32(value: number, name: string): number {
  if (!Number.isInteger(value) || value < 0 || value > U32_MAX) {
    throw new Error(`${name} must be a non-negative 32 bit integer`);
  }
  return value;
}
