import { describe, it, expect } from "vitest";
import { encode } from "cborg";
import { verify } from "../src/cbor.js";

describe("cbor", () => {
  it("accepts restricted deterministic CBOR", async () => {
    const data = encode(
      new Map<number, unknown>([
        [1, "hello"],
        [2, new Uint8Array([1, 2, 3])],
      ]),
    );
    await expect(verify(data)).resolves.toBeUndefined();
  });

  it("rejects types outside the restricted system", async () => {
    await expect(verify(encode(1.5))).rejects.toThrow();
  });
});
