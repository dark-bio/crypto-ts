import { describe, it, expect } from "vitest";
import {
  SecretKey,
  PublicKey,
  Fingerprint,
  Sender,
  Receiver,
  sizes,
  SECRET_KEY_SIZE,
  PUBLIC_KEY_SIZE,
  ENCAP_KEY_SIZE,
  FINGERPRINT_SIZE,
} from "../src/xhpke.js";

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
    const sk2 = await SecretKey.fromBytes(bytes);
    expect(toHex(sk2.toBytes())).toBe(toHex(sk.toBytes()));
  });

  it("roundtrips PublicKey through bytes", async () => {
    const sk = await SecretKey.generate();
    const pk = await sk.publicKey();
    const bytes = pk.toBytes();
    const pk2 = await PublicKey.fromBytes(bytes);
    expect(toHex(pk2.toBytes())).toBe(toHex(pk.toBytes()));
  });

  it("roundtrips Fingerprint through bytes", async () => {
    const sk = await SecretKey.generate();
    const fp = await sk.fingerprint();
    const bytes = fp.toBytes();
    const fp2 = await Fingerprint.fromBytes(bytes);
    expect(toHex(fp2.toBytes())).toBe(toHex(fp.toBytes()));
  });

  describe("multi-message sender/receiver", () => {
    it("encrypts and decrypts multiple messages in order", async () => {
      const sk = await SecretKey.generate();
      const pk = await sk.publicKey();
      const domain = new TextEncoder().encode("multi-msg-test");

      const { sender, encapKey } = await pk.newSender(domain);
      expect(encapKey.length).toBe(ENCAP_KEY_SIZE);

      const receiver = await sk.newReceiver(encapKey, domain);

      const msg1 = new TextEncoder().encode("first message");
      const msg2 = new TextEncoder().encode("second message");
      const msg3 = new TextEncoder().encode("third message");
      const aad = new TextEncoder().encode("context");

      const ct1 = await sender.seal(msg1, aad);
      const ct2 = await sender.seal(msg2, aad);
      const ct3 = await sender.seal(msg3, aad);

      const pt1 = await receiver.open(ct1, aad);
      const pt2 = await receiver.open(ct2, aad);
      const pt3 = await receiver.open(ct3, aad);

      expect(new TextDecoder().decode(pt1)).toBe("first message");
      expect(new TextDecoder().decode(pt2)).toBe("second message");
      expect(new TextDecoder().decode(pt3)).toBe("third message");
    });

    it("produces different ciphertexts for identical messages", async () => {
      const sk = await SecretKey.generate();
      const pk = await sk.publicKey();
      const domain = new TextEncoder().encode("test");

      const { sender, encapKey } = await pk.newSender(domain);
      const receiver = await sk.newReceiver(encapKey, domain);

      const msg = new TextEncoder().encode("same message");
      const aad = new Uint8Array(0);

      const ct1 = await sender.seal(msg, aad);
      const ct2 = await sender.seal(msg, aad);

      expect(toHex(ct1)).not.toBe(toHex(ct2));

      const pt1 = await receiver.open(ct1, aad);
      const pt2 = await receiver.open(ct2, aad);
      expect(toHex(pt1)).toBe(toHex(pt2));
    });

    it("fails to decrypt with wrong secret key", async () => {
      const sk1 = await SecretKey.generate();
      const sk2 = await SecretKey.generate();
      const pk1 = await sk1.publicKey();
      const domain = new TextEncoder().encode("test");
      const aad = new Uint8Array(0);

      const { sender, encapKey } = await pk1.newSender(domain);
      const ct = await sender.seal(new TextEncoder().encode("hello"), aad);

      // Wrong key: receiver creation may succeed (KEM decap produces a
      // different shared secret), but open will fail.
      const receiver = await sk2.newReceiver(encapKey, domain);
      await expect(receiver.open(ct, aad)).rejects.toThrow();
    });

    it("fails to decrypt with wrong AAD", async () => {
      const sk = await SecretKey.generate();
      const pk = await sk.publicKey();
      const domain = new TextEncoder().encode("test");

      const { sender, encapKey } = await pk.newSender(domain);
      const receiver = await sk.newReceiver(encapKey, domain);

      const ct = await sender.seal(
        new TextEncoder().encode("hello"),
        new TextEncoder().encode("aad1"),
      );

      await expect(
        receiver.open(ct, new TextEncoder().encode("aad2")),
      ).rejects.toThrow();
    });

    it("fails to decrypt with wrong domain", async () => {
      const sk = await SecretKey.generate();
      const pk = await sk.publicKey();
      const aad = new Uint8Array(0);

      const { sender, encapKey } = await pk.newSender(
        new TextEncoder().encode("domain1"),
      );
      const ct = await sender.seal(new TextEncoder().encode("hello"), aad);

      // Wrong domain: receiver creation may succeed, but open will fail
      // because the derived key material differs.
      const receiver = await sk.newReceiver(
        encapKey,
        new TextEncoder().encode("domain2"),
      );
      await expect(receiver.open(ct, aad)).rejects.toThrow();
    });

    it("handles empty messages", async () => {
      const sk = await SecretKey.generate();
      const pk = await sk.publicKey();
      const domain = new TextEncoder().encode("test");

      const { sender, encapKey } = await pk.newSender(domain);
      const receiver = await sk.newReceiver(encapKey, domain);

      const ct = await sender.seal(new Uint8Array(0), new Uint8Array(0));
      const pt = await receiver.open(ct, new Uint8Array(0));
      expect(pt.length).toBe(0);
    });

    it("handles many sequential messages", async () => {
      const sk = await SecretKey.generate();
      const pk = await sk.publicKey();
      const domain = new TextEncoder().encode("test");

      const { sender, encapKey } = await pk.newSender(domain);
      const receiver = await sk.newReceiver(encapKey, domain);

      const aad = new Uint8Array(0);
      for (let i = 0; i < 20; i++) {
        const msg = new TextEncoder().encode(`message-${i}`);
        const ct = await sender.seal(msg, aad);
        const pt = await receiver.open(ct, aad);
        expect(new TextDecoder().decode(pt)).toBe(`message-${i}`);
      }
    });
  });
});
