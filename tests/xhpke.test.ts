import { describe, it, expect } from "vitest";
import {
  SecretKey,
  PublicKey,
  Fingerprint,
  sizes,
  SECRET_KEY_SIZE,
  PUBLIC_KEY_SIZE,
  ENCAP_KEY_SIZE,
  FINGERPRINT_SIZE,
} from "../src/xhpke.js";
import { SecretKey as XdsaSecretKey } from "../src/xdsa.js";
import type { Params } from "../src/x509.js";

describe("xhpke", () => {
  function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  it("has correct size constants", async () => {
    const s = await sizes();
    expect(s.secretKey).toBe(SECRET_KEY_SIZE);
    expect(s.publicKey).toBe(PUBLIC_KEY_SIZE);
    expect(s.encapKey).toBe(ENCAP_KEY_SIZE);
    expect(s.fingerprint).toBe(FINGERPRINT_SIZE);
    expect(SECRET_KEY_SIZE).toBe(32);
    expect(PUBLIC_KEY_SIZE).toBe(1216);
    expect(ENCAP_KEY_SIZE).toBe(1120);
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

  it("seals and opens correctly", async () => {
    const sk = await SecretKey.generate();
    const pk = await sk.publicKey();
    const message = new TextEncoder().encode("hello world");
    const aad = new TextEncoder().encode("additional data");
    const domain = new TextEncoder().encode("test-domain");

    const sealed = await pk.seal(message, aad, domain);
    expect(sealed.length).toBeGreaterThan(ENCAP_KEY_SIZE);

    const opened = await sk.open(sealed, aad, domain);
    expect(new TextDecoder().decode(opened)).toBe("hello world");
  });

  it("fails to open with wrong secret key", async () => {
    const sk1 = await SecretKey.generate();
    const sk2 = await SecretKey.generate();
    const pk1 = await sk1.publicKey();
    const message = new TextEncoder().encode("hello world");
    const aad = new Uint8Array(0);
    const domain = new TextEncoder().encode("test");

    const sealed = await pk1.seal(message, aad, domain);

    await expect(sk2.open(sealed, aad, domain)).rejects.toThrow();
  });

  it("fails to open with wrong AAD", async () => {
    const sk = await SecretKey.generate();
    const pk = await sk.publicKey();
    const message = new TextEncoder().encode("hello world");
    const aad1 = new TextEncoder().encode("aad1");
    const aad2 = new TextEncoder().encode("aad2");
    const domain = new TextEncoder().encode("test");

    const sealed = await pk.seal(message, aad1, domain);

    await expect(sk.open(sealed, aad2, domain)).rejects.toThrow();
  });

  it("fails to open with wrong domain", async () => {
    const sk = await SecretKey.generate();
    const pk = await sk.publicKey();
    const message = new TextEncoder().encode("hello world");
    const aad = new Uint8Array(0);
    const domain1 = new TextEncoder().encode("domain1");
    const domain2 = new TextEncoder().encode("domain2");

    const sealed = await pk.seal(message, aad, domain1);

    await expect(sk.open(sealed, aad, domain2)).rejects.toThrow();
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

  it("seals and opens empty message", async () => {
    const sk = await SecretKey.generate();
    const pk = await sk.publicKey();
    const message = new Uint8Array(0);
    const aad = new Uint8Array(0);
    const domain = new TextEncoder().encode("test");

    const sealed = await pk.seal(message, aad, domain);
    const opened = await sk.open(sealed, aad, domain);
    expect(opened.length).toBe(0);
  });

  it("seals and opens with only AAD (no encrypted content)", async () => {
    const sk = await SecretKey.generate();
    const pk = await sk.publicKey();
    const message = new Uint8Array(0);
    const aad = new TextEncoder().encode("authenticate this");
    const domain = new TextEncoder().encode("test");

    const sealed = await pk.seal(message, aad, domain);
    const opened = await sk.open(sealed, aad, domain);
    expect(opened.length).toBe(0);
  });

  it("produces different ciphertext for same message", async () => {
    const sk = await SecretKey.generate();
    const pk = await sk.publicKey();
    const message = new TextEncoder().encode("hello");
    const aad = new Uint8Array(0);
    const domain = new TextEncoder().encode("test");

    const sealed1 = await pk.seal(message, aad, domain);
    const sealed2 = await pk.seal(message, aad, domain);

    expect(toHex(sealed1)).not.toBe(toHex(sealed2));

    const opened1 = await sk.open(sealed1, aad, domain);
    const opened2 = await sk.open(sealed2, aad, domain);
    expect(toHex(opened1)).toBe(toHex(opened2));
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

  it("roundtrips Fingerprint through bytes", async () => {
    const sk = await SecretKey.generate();
    const fp = await sk.fingerprint();
    const bytes = fp.toBytes();
    const fp2 = Fingerprint.fromBytes(bytes);
    expect(toHex(fp2.toBytes())).toBe(toHex(fp.toBytes()));
  });

  it("generates and parses PEM certificate", async () => {
    const alice = await SecretKey.generate();
    const signer = await XdsaSecretKey.generate();
    const alicePub = await alice.publicKey();
    const signerPub = await signer.publicKey();

    const now = BigInt(Math.floor(Date.now() / 1000));
    const params: Params = {
      subjectName: "Alice",
      issuerName: "Signer",
      notBefore: now,
      notAfter: now + 3600n,
    };

    const pem = await alicePub.toCertPem(signer, params);
    expect(pem).toContain("-----BEGIN CERTIFICATE-----");
    expect(pem).toContain("-----END CERTIFICATE-----");

    const { key, notBefore, notAfter } = await PublicKey.fromCertPem(
      pem,
      signerPub,
    );
    expect(toHex(key.toBytes())).toBe(toHex(alicePub.toBytes()));
    expect(notBefore).toBe(now);
    expect(notAfter).toBe(now + 3600n);
  });

  it("generates and parses DER certificate", async () => {
    const alice = await SecretKey.generate();
    const signer = await XdsaSecretKey.generate();
    const alicePub = await alice.publicKey();
    const signerPub = await signer.publicKey();

    const now = BigInt(Math.floor(Date.now() / 1000));
    const params: Params = {
      subjectName: "Alice",
      issuerName: "Signer",
      notBefore: now,
      notAfter: now + 3600n,
    };

    const der = await alicePub.toCertDer(signer, params);
    expect(der.length).toBeGreaterThan(0);

    const { key, notBefore, notAfter } = await PublicKey.fromCertDer(
      der,
      signerPub,
    );
    expect(toHex(key.toBytes())).toBe(toHex(alicePub.toBytes()));
    expect(notBefore).toBe(now);
    expect(notAfter).toBe(now + 3600n);
  });

  it("rejects certificate with wrong signer", async () => {
    const alice = await SecretKey.generate();
    const signer = await XdsaSecretKey.generate();
    const wrong = await XdsaSecretKey.generate();
    const alicePub = await alice.publicKey();
    const wrongPub = await wrong.publicKey();

    const now = BigInt(Math.floor(Date.now() / 1000));
    const params: Params = {
      subjectName: "Alice",
      issuerName: "Signer",
      notBefore: now,
      notAfter: now + 3600n,
    };

    const pem = await alicePub.toCertPem(signer, params);
    await expect(PublicKey.fromCertPem(pem, wrongPub)).rejects.toThrow();
  });
});
