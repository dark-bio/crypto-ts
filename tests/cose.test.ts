// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import { describe, it, expect } from "vitest";
import { decode as cborgDecode, encode as cborgEncode } from "cborg";
import * as cbor from "../src/cbor.js";
import { CodecError } from "../src/cbor.js";
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

const Message = cbor.tuple(cbor.text, cbor.uint);
const Auth = cbor.tuple(cbor.uint);
const Nothing = cbor.nil;

describe("cose", () => {
  function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  describe("sign/verify", () => {
    it("signs and verifies with embedded payload", async () => {
      const sk = await XdsaSecretKey.generate();
      const domain = new TextEncoder().encode("test-domain");
      const signed = await sign(
        Message.value(["login", 123n]),
        Auth.value([1234567890n]),
        sk,
        domain,
      );
      const recovered = await verify(
        Message.bytes(signed),
        Auth.value([1234567890n]),
        sk.publicKey(),
        domain,
      );
      expect(recovered).toEqual(["login", 123n]);
    });

    it("fails verification with wrong key", async () => {
      const sk1 = await XdsaSecretKey.generate();
      const sk2 = await XdsaSecretKey.generate();
      const domain = new TextEncoder().encode("test");
      const signed = await sign(
        cbor.text.value("hello"),
        Nothing.value(null),
        sk1,
        domain,
      );
      await expect(
        verify(
          cbor.text.bytes(signed),
          Nothing.value(null),
          sk2.publicKey(),
          domain,
        ),
      ).rejects.toThrow();
    });

    it("fails verification with wrong AAD", async () => {
      const sk = await XdsaSecretKey.generate();
      const domain = new TextEncoder().encode("test");
      const signed = await sign(
        cbor.text.value("payload"),
        cbor.text.value("aad1"),
        sk,
        domain,
      );
      await expect(
        verify(
          cbor.text.bytes(signed),
          cbor.text.value("aad2"),
          sk.publicKey(),
          domain,
        ),
      ).rejects.toThrow();
    });

    it("fails verification with wrong domain", async () => {
      const sk = await XdsaSecretKey.generate();
      const signed = await sign(
        cbor.text.value("payload"),
        Nothing.value(null),
        sk,
        new TextEncoder().encode("domain1"),
      );
      await expect(
        verify(
          cbor.text.bytes(signed),
          Nothing.value(null),
          sk.publicKey(),
          new TextEncoder().encode("domain2"),
        ),
      ).rejects.toThrow();
    });

    it("bounds the signature drift", async () => {
      const sk = await XdsaSecretKey.generate();
      const domain = new TextEncoder().encode("test");
      const signed = await sign(
        cbor.text.value("payload"),
        Nothing.value(null),
        sk,
        domain,
      );
      expect(
        await verify(
          cbor.text.bytes(signed),
          Nothing.value(null),
          sk.publicKey(),
          domain,
          60,
        ),
      ).toBe("payload");
      await expect(
        verify(
          cbor.text.bytes(signed),
          Nothing.value(null),
          sk.publicKey(),
          domain,
          -1,
        ),
      ).rejects.toThrow();
      await expect(
        verify(
          cbor.text.bytes(signed),
          Nothing.value(null),
          sk.publicKey(),
          domain,
          2 ** 64,
        ),
      ).rejects.toThrow();
    });

    it("fails verification with a payload of another shape", async () => {
      const sk = await XdsaSecretKey.generate();
      const domain = new TextEncoder().encode("test");
      const signed = await sign(
        Message.value(["login", 123n]),
        Nothing.value(null),
        sk,
        domain,
      );
      await expect(
        verify(
          cbor.tuple(cbor.text).bytes(signed),
          Nothing.value(null),
          sk.publicKey(),
          domain,
        ),
      ).rejects.toThrow(CodecError);
    });
  });

  describe("signDetached/verifyDetached", () => {
    it("signs and verifies detached", async () => {
      const sk = await XdsaSecretKey.generate();
      const domain = new TextEncoder().encode("test");
      const signed = await signDetached(
        Message.value(["external", 1n]),
        sk,
        domain,
      );
      await expect(
        verifyDetached(
          signed,
          Message.value(["external", 1n]),
          sk.publicKey(),
          domain,
        ),
      ).resolves.toBeUndefined();
    });

    it("fails with modified message", async () => {
      const sk = await XdsaSecretKey.generate();
      const domain = new TextEncoder().encode("test");
      const signed = await signDetached(
        cbor.text.value("original"),
        sk,
        domain,
      );
      await expect(
        verifyDetached(
          signed,
          cbor.text.value("modified"),
          sk.publicKey(),
          domain,
        ),
      ).rejects.toThrow();
    });
  });

  describe("signer/peek", () => {
    it("extracts signer fingerprint", async () => {
      const sk = await XdsaSecretKey.generate();
      const domain = new TextEncoder().encode("test");
      const signed = await sign(
        cbor.text.value("payload"),
        Nothing.value(null),
        sk,
        domain,
      );
      const fp = await signer(signed);
      expect(fp.toBytes().length).toBe(32);
      expect(fp.equals(sk.fingerprint())).toBe(true);
    });

    it("peeks at unverified payload", async () => {
      const sk = await XdsaSecretKey.generate();
      const domain = new TextEncoder().encode("test");
      const signed = await sign(
        Message.value(["secret", 2n]),
        Nothing.value(null),
        sk,
        domain,
      );
      expect(await peek(Message.bytes(signed))).toEqual(["secret", 2n]);
    });

    it("refuses a non-canonical payload", async () => {
      const sk = await XdsaSecretKey.generate();
      const domain = new TextEncoder().encode("test");
      const signed = await sign(
        cbor.text.value("payload"),
        Nothing.value(null),
        sk,
        domain,
      );
      // Swap the payload of the envelope for a map with a duplicate key
      const envelope = cborgDecode(signed, { useMaps: true }) as unknown[];
      envelope[2] = new Uint8Array([0xa2, 0x01, 0x01, 0x01, 0x02]);
      const bogus = cborgEncode(envelope);
      await expect(peek(cbor.raw.bytes(bogus))).rejects.toThrow(
        /invalid payload CBOR/,
      );
    });
  });

  describe("seal/open", () => {
    it("seals and opens correctly", async () => {
      const signerSk = await XdsaSecretKey.generate();
      const recipientSk = await XhpkeSecretKey.generate();
      const domain = new TextEncoder().encode("test");
      const sealed = await seal(
        Message.value(["encrypted and signed", 7n]),
        cbor.text.value("test-context"),
        signerSk,
        recipientSk.publicKey(),
        domain,
      );
      const opened = await open(
        Message.bytes(sealed),
        cbor.text.value("test-context"),
        recipientSk,
        signerSk.publicKey(),
        domain,
      );
      expect(opened).toEqual(["encrypted and signed", 7n]);
    });

    it("fails with wrong recipient key", async () => {
      const signerSk = await XdsaSecretKey.generate();
      const recipientSk1 = await XhpkeSecretKey.generate();
      const recipientSk2 = await XhpkeSecretKey.generate();
      const domain = new TextEncoder().encode("test");
      const sealed = await seal(
        cbor.text.value("payload"),
        Nothing.value(null),
        signerSk,
        recipientSk1.publicKey(),
        domain,
      );
      await expect(
        open(
          cbor.text.bytes(sealed),
          Nothing.value(null),
          recipientSk2,
          signerSk.publicKey(),
          domain,
        ),
      ).rejects.toThrow();
    });

    it("fails with wrong sender key", async () => {
      const signerSk1 = await XdsaSecretKey.generate();
      const signerSk2 = await XdsaSecretKey.generate();
      const recipientSk = await XhpkeSecretKey.generate();
      const domain = new TextEncoder().encode("test");
      const sealed = await seal(
        cbor.text.value("payload"),
        Nothing.value(null),
        signerSk1,
        recipientSk.publicKey(),
        domain,
      );
      await expect(
        open(
          cbor.text.bytes(sealed),
          Nothing.value(null),
          recipientSk,
          signerSk2.publicKey(),
          domain,
        ),
      ).rejects.toThrow();
    });
  });

  describe("encrypt/decrypt", () => {
    it("encrypts and decrypts a signed message", async () => {
      const signerSk = await XdsaSecretKey.generate();
      const recipientSk = await XhpkeSecretKey.generate();
      const domain = new TextEncoder().encode("test");
      const signed = await sign(
        cbor.text.value("hello world"),
        Nothing.value(null),
        signerSk,
        domain,
      );
      const encrypted = await encrypt(
        signed,
        Nothing.value(null),
        recipientSk.publicKey(),
        domain,
      );
      const decrypted = await decrypt(
        encrypted,
        Nothing.value(null),
        recipientSk,
        domain,
      );
      const recovered = await verify(
        cbor.text.bytes(decrypted),
        Nothing.value(null),
        signerSk.publicKey(),
        domain,
      );
      expect(recovered).toBe("hello world");
    });

    it("extracts recipient before decryption", async () => {
      const signerSk = await XdsaSecretKey.generate();
      const recipientSk = await XhpkeSecretKey.generate();
      const domain = new TextEncoder().encode("test");
      const signed = await sign(
        cbor.text.value("payload"),
        Nothing.value(null),
        signerSk,
        domain,
      );
      const encrypted = await encrypt(
        signed,
        Nothing.value(null),
        recipientSk.publicKey(),
        domain,
      );
      const fp = await recipient(encrypted);
      expect(fp.toBytes().length).toBe(32);
      expect(fp.equals(recipientSk.fingerprint())).toBe(true);
    });
  });

  describe("complex types", () => {
    it("handles binary payloads", async () => {
      const sk = await XdsaSecretKey.generate();
      const domain = new TextEncoder().encode("test");
      const payload = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
      const signed = await sign(
        cbor.bytes.value(payload),
        Nothing.value(null),
        sk,
        domain,
      );
      const recovered = await verify(
        cbor.bytes.bytes(signed),
        Nothing.value(null),
        sk.publicKey(),
        domain,
      );
      expect(toHex(recovered)).toBe(toHex(payload));
    });

    it("handles nested array payloads", async () => {
      const sk = await XdsaSecretKey.generate();
      const domain = new TextEncoder().encode("test");
      const Nested = cbor.tuple(
        cbor.tuple(cbor.uint, cbor.text),
        cbor.tuple(cbor.text, cbor.tuple(cbor.uint, cbor.text)),
        cbor.nil,
      );
      const payload: [[bigint, string], [string, [bigint, string]], null] = [
        [1n, "document"],
        ["hello", [1234567890n, "alice"]],
        null,
      ];
      const signed = await sign(
        Nested.value(payload),
        Nothing.value(null),
        sk,
        domain,
      );
      const recovered = await verify(
        Nested.bytes(signed),
        Nothing.value(null),
        sk.publicKey(),
        domain,
      );
      expect(recovered).toEqual(payload);
    });

    it("handles maps with integer keys", async () => {
      const sk = await XdsaSecretKey.generate();
      const domain = new TextEncoder().encode("test");
      const Record = cbor.map({
        id: cbor.field(1, cbor.uint),
        name: cbor.field(2, cbor.text),
        note: cbor.field(3, cbor.nullable(cbor.text)),
      });
      const payload = { id: 123n, name: "Alice", note: null };
      const signed = await sign(
        Record.value(payload),
        Nothing.value(null),
        sk,
        domain,
      );
      const recovered = await verify(
        Record.bytes(signed),
        Nothing.value(null),
        sk.publicKey(),
        domain,
      );
      expect(recovered).toEqual(payload);
    });

    it("handles nested maps", async () => {
      const sk = await XdsaSecretKey.generate();
      const domain = new TextEncoder().encode("test");
      const Inner = cbor.map({
        label: cbor.field(1, cbor.text),
        answer: cbor.field(2, cbor.uint),
      });
      const Outer = cbor.map({
        label: cbor.field(1, cbor.text),
        inner: cbor.field(2, Inner),
      });
      const payload = {
        label: "outer",
        inner: { label: "nested", answer: 42n },
      };
      const signed = await sign(
        Outer.value(payload),
        Nothing.value(null),
        sk,
        domain,
      );
      const recovered = await verify(
        Outer.bytes(signed),
        Nothing.value(null),
        sk.publicKey(),
        domain,
      );
      expect(recovered).toEqual(payload);
    });
  });
});
