import { describe, it, expect } from "vitest";
import {
  sign,
  signDetached,
  verify,
  verifyDetached,
  signer,
  peek,
  recipient,
  seal,
  open,
  encrypt,
  decrypt,
} from "../src/cose.js";
import { SecretKey as XdsaSecretKey } from "../src/xdsa.js";
import { SecretKey as XhpkeSecretKey } from "../src/xhpke.js";

describe("cose", () => {
  function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  describe("sign/verify", () => {
    it("signs and verifies with embedded payload", async () => {
      const sk = await XdsaSecretKey.generate();
      const pk = await sk.publicKey();
      const domain = new TextEncoder().encode("test-domain");

      const payload = ["login", 123];
      const aad = [1234567890];

      const signed = await sign(payload, aad, sk, domain);
      const recovered = await verify<typeof payload, typeof aad>(
        signed,
        aad,
        pk,
        domain,
      );

      expect(recovered).toEqual(payload);
    });

    it("fails verification with wrong key", async () => {
      const sk1 = await XdsaSecretKey.generate();
      const sk2 = await XdsaSecretKey.generate();
      const pk2 = await sk2.publicKey();
      const domain = new TextEncoder().encode("test");

      const signed = await sign(["hello"], null, sk1, domain);

      await expect(verify(signed, null, pk2, domain)).rejects.toThrow();
    });

    it("fails verification with wrong AAD", async () => {
      const sk = await XdsaSecretKey.generate();
      const pk = await sk.publicKey();
      const domain = new TextEncoder().encode("test");

      const signed = await sign("payload", "aad1", sk, domain);

      await expect(verify(signed, "aad2", pk, domain)).rejects.toThrow();
    });

    it("fails verification with wrong domain", async () => {
      const sk = await XdsaSecretKey.generate();
      const pk = await sk.publicKey();

      const signed = await sign(
        "payload",
        null,
        sk,
        new TextEncoder().encode("domain1"),
      );

      await expect(
        verify(signed, null, pk, new TextEncoder().encode("domain2")),
      ).rejects.toThrow();
    });
  });

  describe("signDetached/verifyDetached", () => {
    it("signs and verifies detached", async () => {
      const sk = await XdsaSecretKey.generate();
      const pk = await sk.publicKey();
      const domain = new TextEncoder().encode("test");

      const msg = ["external payload"];
      const signed = await signDetached(msg, sk, domain);

      await expect(
        verifyDetached(signed, msg, pk, domain),
      ).resolves.toBeUndefined();
    });

    it("fails with modified message", async () => {
      const sk = await XdsaSecretKey.generate();
      const pk = await sk.publicKey();
      const domain = new TextEncoder().encode("test");

      const signed = await signDetached(["original"], sk, domain);

      await expect(
        verifyDetached(signed, ["modified"], pk, domain),
      ).rejects.toThrow();
    });
  });

  describe("signer/peek", () => {
    it("extracts signer fingerprint", async () => {
      const sk = await XdsaSecretKey.generate();
      const domain = new TextEncoder().encode("test");

      const signed = await sign("payload", null, sk, domain);
      const fp = await signer(signed);

      expect(fp.toBytes().length).toBe(32);
    });

    it("peeks at unverified payload", async () => {
      const sk = await XdsaSecretKey.generate();
      const domain = new TextEncoder().encode("test");

      const payload = ["secret", "data"];
      const signed = await sign(payload, null, sk, domain);

      const peeked = await peek<typeof payload>(signed);
      expect(peeked).toEqual(payload);
    });
  });

  describe("seal/open", () => {
    it("seals and opens correctly", async () => {
      const signerSk = await XdsaSecretKey.generate();
      const signerPk = await signerSk.publicKey();
      const recipientSk = await XhpkeSecretKey.generate();
      const recipientPk = await recipientSk.publicKey();
      const domain = new TextEncoder().encode("test");

      const payload = ["encrypted and signed"];
      const aad = ["test-context"];

      const sealed = await seal(payload, aad, signerSk, recipientPk, domain);
      const opened = await open<typeof payload, typeof aad>(
        sealed,
        aad,
        recipientSk,
        signerPk,
        domain,
      );

      expect(opened).toEqual(payload);
    });

    it("fails with wrong recipient key", async () => {
      const signerSk = await XdsaSecretKey.generate();
      const signerPk = await signerSk.publicKey();
      const recipientSk1 = await XhpkeSecretKey.generate();
      const recipientPk1 = await recipientSk1.publicKey();
      const recipientSk2 = await XhpkeSecretKey.generate();
      const domain = new TextEncoder().encode("test");

      const sealed = await seal(
        "payload",
        null,
        signerSk,
        recipientPk1,
        domain,
      );

      await expect(
        open(sealed, null, recipientSk2, signerPk, domain),
      ).rejects.toThrow();
    });

    it("fails with wrong sender key", async () => {
      const signerSk1 = await XdsaSecretKey.generate();
      const signerSk2 = await XdsaSecretKey.generate();
      const signerPk2 = await signerSk2.publicKey();
      const recipientSk = await XhpkeSecretKey.generate();
      const recipientPk = await recipientSk.publicKey();
      const domain = new TextEncoder().encode("test");

      const sealed = await seal(
        "payload",
        null,
        signerSk1,
        recipientPk,
        domain,
      );

      await expect(
        open(sealed, null, recipientSk, signerPk2, domain),
      ).rejects.toThrow();
    });
  });

  describe("encrypt/decrypt", () => {
    it("encrypts and decrypts a signed message", async () => {
      const signerSk = await XdsaSecretKey.generate();
      const signerPk = await signerSk.publicKey();
      const recipientSk = await XhpkeSecretKey.generate();
      const recipientPk = await recipientSk.publicKey();
      const domain = new TextEncoder().encode("test");

      const payload = "hello world";
      const aad = null;

      const signed = await sign(payload, aad, signerSk, domain);
      const encrypted = await encrypt(signed, aad, recipientPk, domain);
      const decrypted = await decrypt(encrypted, aad, recipientSk, domain);
      const recovered = await verify<string, null>(
        decrypted,
        aad,
        signerPk,
        domain,
      );

      expect(recovered).toBe(payload);
    });

    it("extracts recipient before decryption", async () => {
      const signerSk = await XdsaSecretKey.generate();
      const recipientSk = await XhpkeSecretKey.generate();
      const recipientPk = await recipientSk.publicKey();
      const domain = new TextEncoder().encode("test");

      const signed = await sign("payload", null, signerSk, domain);
      const encrypted = await encrypt(signed, null, recipientPk, domain);

      const fp = await recipient(encrypted);
      expect(fp.toBytes().length).toBe(32);
    });
  });

  describe("complex types", () => {
    it("handles binary payloads", async () => {
      const sk = await XdsaSecretKey.generate();
      const pk = await sk.publicKey();
      const domain = new TextEncoder().encode("test");

      const payload = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
      const signed = await sign(payload, null, sk, domain);
      const recovered = await verify<Uint8Array, null>(
        signed,
        null,
        pk,
        domain,
      );

      expect(toHex(recovered)).toBe(toHex(payload));
    });

    it("handles nested array payloads", async () => {
      const sk = await XdsaSecretKey.generate();
      const pk = await sk.publicKey();
      const domain = new TextEncoder().encode("test");

      const payload = [[1, "document"], ["hello", [1234567890, "alice"]], null];

      const signed = await sign(payload, null, sk, domain);
      const recovered = await verify<typeof payload, null>(
        signed,
        null,
        pk,
        domain,
      );

      expect(recovered).toEqual(payload);
    });

    it("handles Map with integer keys", async () => {
      const sk = await XdsaSecretKey.generate();
      const pk = await sk.publicKey();
      const domain = new TextEncoder().encode("test");

      const payload = new Map<number, unknown>([
        [1, 123],
        [2, "Alice"],
        [3, null],
      ]);

      const signed = await sign(payload, null, sk, domain);
      const recovered = await verify<Map<number, unknown>, null>(
        signed,
        null,
        pk,
        domain,
      );

      expect(recovered).toBeInstanceOf(Map);
      expect(recovered.get(1)).toBe(123);
      expect(recovered.get(2)).toBe("Alice");
      expect(recovered.get(3)).toBe(null);
    });

    it("handles nested Maps", async () => {
      const sk = await XdsaSecretKey.generate();
      const pk = await sk.publicKey();
      const domain = new TextEncoder().encode("test");

      const inner = new Map<number, unknown>([
        [1, "nested"],
        [2, 42],
      ]);
      const payload = new Map<number, unknown>([
        [1, "outer"],
        [2, inner],
      ]);

      const signed = await sign(payload, null, sk, domain);
      const recovered = await verify<Map<number, unknown>, null>(
        signed,
        null,
        pk,
        domain,
      );

      expect(recovered.get(1)).toBe("outer");
      const recoveredInner = recovered.get(2) as Map<number, unknown>;
      expect(recoveredInner.get(1)).toBe("nested");
      expect(recoveredInner.get(2)).toBe(42);
    });
  });
});
