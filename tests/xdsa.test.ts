import { describe, it, expect } from "vitest";
import {
  SecretKey,
  PublicKey,
  Fingerprint,
  Signature,
  sizes,
  SECRET_KEY_SIZE,
  PUBLIC_KEY_SIZE,
  SIGNATURE_SIZE,
  FINGERPRINT_SIZE,
} from "../src/xdsa.js";
import type { Params } from "../src/x509.js";

describe("xdsa", () => {
  function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  it("has correct size constants", async () => {
    const s = await sizes();
    expect(s.secretKey).toBe(SECRET_KEY_SIZE);
    expect(s.publicKey).toBe(PUBLIC_KEY_SIZE);
    expect(s.signature).toBe(SIGNATURE_SIZE);
    expect(s.fingerprint).toBe(FINGERPRINT_SIZE);
    expect(SECRET_KEY_SIZE).toBe(64);
    expect(PUBLIC_KEY_SIZE).toBe(1984);
    expect(SIGNATURE_SIZE).toBe(3373);
    expect(FINGERPRINT_SIZE).toBe(32);
  });

  it("generates secret key of correct size", async () => {
    const sk = await SecretKey.generate();
    expect(sk.toBytes().length).toBe(SECRET_KEY_SIZE);
  });

  it("derives public key of correct size", async () => {
    const sk = await SecretKey.generate();
    const pk = await sk.publicKey();
    expect(pk.toBytes().length).toBe(PUBLIC_KEY_SIZE);
  });

  it("computes fingerprint of correct size", async () => {
    const sk = await SecretKey.generate();
    const pk = await sk.publicKey();
    const fp = await pk.fingerprint();
    expect(fp.toBytes().length).toBe(FINGERPRINT_SIZE);
  });

  it("generates different keys each time", async () => {
    const sk1 = await SecretKey.generate();
    const sk2 = await SecretKey.generate();
    expect(toHex(sk1.toBytes())).not.toBe(toHex(sk2.toBytes()));
  });

  it("derives same public key from same secret key", async () => {
    const sk = await SecretKey.generate();
    const pk1 = await sk.publicKey();
    const pk2 = await sk.publicKey();
    expect(toHex(pk1.toBytes())).toBe(toHex(pk2.toBytes()));
  });

  it("signs and verifies correctly", async () => {
    const sk = await SecretKey.generate();
    const pk = await sk.publicKey();
    const message = new TextEncoder().encode("hello world");

    const sig = await sk.sign(message);
    expect(sig.toBytes().length).toBe(SIGNATURE_SIZE);

    const valid = await pk.verify(message, sig);
    expect(valid).toBe(true);
  });

  it("rejects invalid signature", async () => {
    const sk = await SecretKey.generate();
    const pk = await sk.publicKey();
    const message = new TextEncoder().encode("hello world");
    const wrongMessage = new TextEncoder().encode("goodbye world");

    const sig = await sk.sign(message);
    const valid = await pk.verify(wrongMessage, sig);
    expect(valid).toBe(false);
  });

  it("rejects signature with wrong key", async () => {
    const sk1 = await SecretKey.generate();
    const sk2 = await SecretKey.generate();
    const pk2 = await sk2.publicKey();
    const message = new TextEncoder().encode("hello world");

    const sig = await sk1.sign(message);
    const valid = await pk2.verify(message, sig);
    expect(valid).toBe(false);
  });

  it("roundtrips secret key through PEM", async () => {
    const sk = await SecretKey.generate();
    const pem = await sk.toPem();
    expect(pem).toContain("-----BEGIN PRIVATE KEY-----");
    expect(pem).toContain("-----END PRIVATE KEY-----");

    const sk2 = await SecretKey.fromPem(pem);
    expect(toHex(sk2.toBytes())).toBe(toHex(sk.toBytes()));
  });

  it("roundtrips public key through PEM", async () => {
    const sk = await SecretKey.generate();
    const pk = await sk.publicKey();
    const pem = await pk.toPem();
    expect(pem).toContain("-----BEGIN PUBLIC KEY-----");
    expect(pem).toContain("-----END PUBLIC KEY-----");

    const pk2 = await PublicKey.fromPem(pem);
    expect(toHex(pk2.toBytes())).toBe(toHex(pk.toBytes()));
  });

  it("signs empty message", async () => {
    const sk = await SecretKey.generate();
    const pk = await sk.publicKey();
    const message = new Uint8Array(0);

    const sig = await sk.sign(message);
    const valid = await pk.verify(message, sig);
    expect(valid).toBe(true);
  });

  it("signs large message", async () => {
    const sk = await SecretKey.generate();
    const pk = await sk.publicKey();
    const message = new Uint8Array(1024 * 1024); // 1MB
    message.fill(0x42);

    const sig = await sk.sign(message);
    const valid = await pk.verify(message, sig);
    expect(valid).toBe(true);
  });

  it("roundtrips SecretKey through bytes", async () => {
    const sk = await SecretKey.generate();
    const bytes = sk.toBytes();
    const sk2 = SecretKey.fromBytes(bytes);
    expect(toHex(sk2.toBytes())).toBe(toHex(sk.toBytes()));
  });

  it("roundtrips PublicKey through bytes", async () => {
    const sk = await SecretKey.generate();
    const pk = await sk.publicKey();
    const bytes = pk.toBytes();
    const pk2 = PublicKey.fromBytes(bytes);
    expect(toHex(pk2.toBytes())).toBe(toHex(pk.toBytes()));
  });

  it("roundtrips Signature through bytes", async () => {
    const sk = await SecretKey.generate();
    const message = new TextEncoder().encode("test");
    const sig = await sk.sign(message);
    const bytes = sig.toBytes();
    const sig2 = Signature.fromBytes(bytes);
    expect(toHex(sig2.toBytes())).toBe(toHex(sig.toBytes()));
  });

  it("roundtrips Fingerprint through bytes", async () => {
    const sk = await SecretKey.generate();
    const fp = await sk.fingerprint();
    const bytes = fp.toBytes();
    const fp2 = Fingerprint.fromBytes(bytes);
    expect(toHex(fp2.toBytes())).toBe(toHex(fp.toBytes()));
  });

  it("generates and parses PEM certificate", async () => {
    const alice = await SecretKey.generate();
    const bobby = await SecretKey.generate();
    const alicePub = await alice.publicKey();
    const bobbyPub = await bobby.publicKey();

    const now = BigInt(Math.floor(Date.now() / 1000));
    const params: Params = {
      subjectName: "Alice",
      issuerName: "Bobby",
      notBefore: now,
      notAfter: now + 3600n,
    };

    const pem = await alicePub.toCertPem(bobby, params);
    expect(pem).toContain("-----BEGIN CERTIFICATE-----");
    expect(pem).toContain("-----END CERTIFICATE-----");

    const { key, notBefore, notAfter } = await PublicKey.fromCertPem(
      pem,
      bobbyPub,
    );
    expect(toHex(key.toBytes())).toBe(toHex(alicePub.toBytes()));
    expect(notBefore).toBe(now);
    expect(notAfter).toBe(now + 3600n);
  });

  it("generates and parses DER certificate", async () => {
    const alice = await SecretKey.generate();
    const bobby = await SecretKey.generate();
    const alicePub = await alice.publicKey();
    const bobbyPub = await bobby.publicKey();

    const now = BigInt(Math.floor(Date.now() / 1000));
    const params: Params = {
      subjectName: "Alice",
      issuerName: "Bobby",
      notBefore: now,
      notAfter: now + 3600n,
    };

    const der = await alicePub.toCertDer(bobby, params);
    expect(der.length).toBeGreaterThan(0);

    const { key, notBefore, notAfter } = await PublicKey.fromCertDer(
      der,
      bobbyPub,
    );
    expect(toHex(key.toBytes())).toBe(toHex(alicePub.toBytes()));
    expect(notBefore).toBe(now);
    expect(notAfter).toBe(now + 3600n);
  });

  it("rejects certificate with wrong signer", async () => {
    const alice = await SecretKey.generate();
    const bobby = await SecretKey.generate();
    const wrong = await SecretKey.generate();
    const alicePub = await alice.publicKey();
    const wrongPub = await wrong.publicKey();

    const now = BigInt(Math.floor(Date.now() / 1000));
    const params: Params = {
      subjectName: "Alice",
      issuerName: "Bobby",
      notBefore: now,
      notAfter: now + 3600n,
    };

    const pem = await alicePub.toCertPem(bobby, params);
    await expect(PublicKey.fromCertPem(pem, wrongPub)).rejects.toThrow();
  });

  it("generates CA certificate with pathLen", async () => {
    const ca = await SecretKey.generate();
    const caPub = await ca.publicKey();

    const now = BigInt(Math.floor(Date.now() / 1000));
    const params: Params = {
      subjectName: "CA",
      issuerName: "CA",
      notBefore: now,
      notAfter: now + 86400n,
      isCa: true,
      pathLen: 0,
    };

    const pem = await caPub.toCertPem(ca, params);
    expect(pem).toContain("-----BEGIN CERTIFICATE-----");

    const { key } = await PublicKey.fromCertPem(pem, caPub);
    expect(toHex(key.toBytes())).toBe(toHex(caPub.toBytes()));
  });
});
