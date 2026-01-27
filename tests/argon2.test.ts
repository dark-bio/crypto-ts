import { describe, it, expect } from "vitest";
import { key } from "../src/argon2.js";

// Test vectors from Go's x/crypto/argon2 package
describe("argon2", () => {
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

  const password = new TextEncoder().encode("password");
  const salt = new TextEncoder().encode("somesalt");

  it("derives key correctly (time=1, memory=64, threads=1)", async () => {
    const result = await key(password, salt, 1, 64, 1, 24);
    expect(toHex(result)).toBe(
      "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb",
    );
  });

  it("derives key correctly (time=2, memory=64, threads=1)", async () => {
    const result = await key(password, salt, 2, 64, 1, 24);
    expect(toHex(result)).toBe(
      "068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7",
    );
  });

  it("derives key correctly (time=2, memory=64, threads=2)", async () => {
    const result = await key(password, salt, 2, 64, 2, 24);
    expect(toHex(result)).toBe(
      "350ac37222f436ccb5c0972f1ebd3bf6b958bf2071841362",
    );
  });

  it("derives key correctly (time=3, memory=256, threads=2)", async () => {
    const result = await key(password, salt, 3, 256, 2, 24);
    expect(toHex(result)).toBe(
      "4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b",
    );
  });

  it("produces different outputs for different passwords", async () => {
    const pass1 = new TextEncoder().encode("password1");
    const pass2 = new TextEncoder().encode("password2");

    const result1 = await key(pass1, salt, 1, 64, 1, 32);
    const result2 = await key(pass2, salt, 1, 64, 1, 32);

    expect(toHex(result1)).not.toBe(toHex(result2));
  });

  it("produces different outputs for different salts", async () => {
    const salt1 = new TextEncoder().encode("saltsalt1");
    const salt2 = new TextEncoder().encode("saltsalt2");

    const result1 = await key(password, salt1, 1, 64, 1, 32);
    const result2 = await key(password, salt2, 1, 64, 1, 32);

    expect(toHex(result1)).not.toBe(toHex(result2));
  });
});
