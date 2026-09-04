// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import { describe, it, expect } from "vitest";
import { generate } from "../src/rand.js";

describe("rand", () => {
  it("generates empty buffer for zero bytes", async () => {
    const result = await generate(0);
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(0);
  });

  it("generates buffer of requested size", async () => {
    const result = await generate(32);
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(32);
  });

  it("generates different values each time", async () => {
    const a = await generate(32);
    const b = await generate(32);
    expect(a).not.toEqual(b);
  });

  it("handles large buffers", async () => {
    const result = await generate(1024);
    expect(result.length).toBe(1024);
  });

  it("rejects oversized requests", async () => {
    await expect(generate(64 * 1024 * 1024 + 1)).rejects.toThrow();
    await expect(generate(-1)).rejects.toThrow();
  });
});
