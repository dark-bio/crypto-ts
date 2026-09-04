// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import { describe, it, expect } from "vitest";
import { SecretKey as XdsaSecretKey, publicKey } from "../src/xdsa.js";
import { SecretKey as XhpkeSecretKey } from "../src/xhpke.js";
import { generate } from "../src/rand.js";

describe("init", () => {
  // Codecs run synchronously and construct keys through WASM, so before any
  // entry point has initialised the module they must fail clearly.
  it("refuses synchronous key decoding before initialization", () => {
    expect(() => publicKey.decode(new Uint8Array(32))).toThrow(
      "not initialised",
    );
  });

  // The first WASM calls race across modules on purpose: concurrent callers
  // must share a single module instantiation, and handles created by either
  // must stay usable afterwards.
  it("handles concurrent first-time initialization", async () => {
    const [signer, receiver, noise] = await Promise.all([
      XdsaSecretKey.generate(),
      XhpkeSecretKey.generate(),
      generate(32),
    ]);

    const message = new TextEncoder().encode("hello");
    const signature = signer.sign(message);
    expect(signer.publicKey().verify(message, signature)).toBe(true);

    const sealed = receiver.publicKey().seal(message, noise, noise);
    expect(receiver.open(sealed, noise, noise)).toEqual(message);
  });
});
