import { describe, it, expect } from "vitest";
import { key, extract, expand } from "../src/hkdf.js";

// Test vectors from RFC 5869 Appendix A (SHA-256)
describe("hkdf", () => {
  // Helper to convert hex string to Uint8Array
  function fromHex(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  // Helper to convert Uint8Array to hex string
  function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  // RFC 5869 A.1: Basic test case with SHA-256
  it("derives key correctly (RFC 5869 A.1)", async () => {
    const secret = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = fromHex("000102030405060708090a0b0c");
    const info = fromHex("f0f1f2f3f4f5f6f7f8f9");
    const expected =
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

    const result = await key(secret, salt, info, 42);
    expect(toHex(result)).toBe(expected);
  });

  // RFC 5869 A.3: Test with zero-length salt/info
  it("handles empty salt and info (RFC 5869 A.3)", async () => {
    const secret = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = new Uint8Array(0);
    const info = new Uint8Array(0);
    const expected =
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8";

    const result = await key(secret, salt, info, 42);
    expect(toHex(result)).toBe(expected);
  });

  // Test extract function
  it("extracts PRK correctly (RFC 5869 A.1)", async () => {
    const secret = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = fromHex("000102030405060708090a0b0c");
    const expected =
      "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";

    const result = await extract(secret, salt);
    expect(toHex(result)).toBe(expected);
    expect(result.length).toBe(32);
  });

  // Test expand function
  it("expands PRK correctly (RFC 5869 A.1)", async () => {
    const prk = fromHex(
      "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
    );
    const info = fromHex("f0f1f2f3f4f5f6f7f8f9");
    const expected =
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

    const result = await expand(prk, info, 42);
    expect(toHex(result)).toBe(expected);
  });

  // Test extract/expand roundtrip matches key
  it("extract + expand equals key", async () => {
    const secret = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = fromHex("000102030405060708090a0b0c");
    const info = fromHex("f0f1f2f3f4f5f6f7f8f9");

    const direct = await key(secret, salt, info, 42);
    const prk = await extract(secret, salt);
    const expanded = await expand(prk, info, 42);

    expect(toHex(expanded)).toBe(toHex(direct));
  });
});
