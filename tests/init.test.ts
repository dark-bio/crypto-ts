import { describe, it, expect } from "vitest";
import { SecretKey as XdsaSecretKey } from "../src/xdsa.js";
import { SecretKey as XhpkeSecretKey } from "../src/xhpke.js";
import { generate } from "../src/rand.js";

describe("init", () => {
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
