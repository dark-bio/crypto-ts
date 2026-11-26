// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/** Composite signing, key encodings and fingerprint comparisons. */

import { describe, it, expect } from "vitest";
import * as cbor from "../src/cbor.js";
import { CodecError } from "../src/cbor.js";
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
import { publicKey, fingerprint } from "../src/xdsa.js";
import * as cose from "../src/cose.js";
import * as cwt from "../src/cwt.js";

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

  it("produces distinct valid hedged signatures for the same message", async () => {
    const sk = await SecretKey.generate();
    const pk = sk.publicKey();
    const message = new TextEncoder().encode("hello world");

    // Both signatures authenticate the same input
    const first = sk.sign(message);
    const second = sk.sign(message);
    expect(first.toBytes().length).toBe(SIGNATURE_SIZE);
    expect(first.toBytes()).not.toEqual(second.toBytes());
    expect(pk.verify(message, first)).toBe(true);
    expect(pk.verify(message, second)).toBe(true);
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
    const message = new Uint8Array(1024 * 1024); // 1 MiB
    message.fill(0x42);

    const sig = await sk.sign(message);
    const valid = await pk.verify(message, sig);
    expect(valid).toBe(true);
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

  it("roundtrips Signature through bytes", async () => {
    const sk = await SecretKey.generate();
    const message = new TextEncoder().encode("test");
    const sig = await sk.sign(message);
    const bytes = sig.toBytes();
    const sig2 = await Signature.fromBytes(bytes);
    expect(toHex(sig2.toBytes())).toBe(toHex(sig.toBytes()));
  });

  it("rejects a tampered signature half", async () => {
    const sk = await SecretKey.generate();
    const message = new TextEncoder().encode("halves");
    const bytes = sk.sign(message).toBytes();

    // Flip one bit in the ML-DSA component, then one in the Ed25519 component
    for (const index of [0, SIGNATURE_SIZE - 64]) {
      const tampered = bytes.slice();
      tampered[index] ^= 1;
      const sig = await Signature.fromBytes(tampered);
      expect(sk.publicKey().verify(message, sig), `${index}`).toBe(false);
    }
  });

  it("accepts LF or CRLF PEM line endings but not a mix", async () => {
    const sk = await SecretKey.generate();
    const pem = sk.toPem();

    const crlf = await SecretKey.fromPem(pem.replaceAll("\n", "\r\n"));
    expect(toHex(crlf.toBytes())).toBe(toHex(sk.toBytes()));

    // One body line ending in CRLF within an LF block
    const lines = pem.split("\n");
    lines[1] += "\r";
    await expect(SecretKey.fromPem(lines.join("\n"))).rejects.toThrow(
      /stray line endings/,
    );
  });

  it.each(["\n", "\r\n"])(
    "rejects blank PEM body lines with %j endings",
    async (eol) => {
      const key = await SecretKey.generate();
      const lines = key.toPem().trimEnd().split("\n");

      // Insert a blank line before, within and after the base64 data
      for (const index of [1, 2, lines.length - 1]) {
        const malformed = [
          ...lines.slice(0, index),
          "",
          ...lines.slice(index),
        ].join(eol);
        await expect(
          SecretKey.fromPem(malformed),
          String(index),
        ).rejects.toThrow(/blank line/);
      }
    },
  );

  it("roundtrips Fingerprint through bytes", async () => {
    const sk = await SecretKey.generate();
    const fp = await sk.fingerprint();
    const bytes = fp.toBytes();
    const fp2 = await Fingerprint.fromBytes(bytes);
    expect(toHex(fp2.toBytes())).toBe(toHex(fp.toBytes()));
  });

  describe("equality and codecs", () => {
    it("compares and renders fingerprints", async () => {
      const sk = await SecretKey.generate();
      const other = await SecretKey.generate();
      const fp = sk.fingerprint();
      expect(fp.equals(fp)).toBe(true);
      expect(fp.equals(sk.publicKey().fingerprint())).toBe(true);
      expect(fp.equals(await Fingerprint.fromBytes(fp.toBytes()))).toBe(true);
      expect(fp.equals(other.fingerprint())).toBe(false);
      expect(fp.toHex()).toBe(toHex(fp.toBytes()));
      expect(fp.toHex().length).toBe(64);
    });

    it("compares public keys", async () => {
      const sk = await SecretKey.generate();
      const other = await SecretKey.generate();
      const pk = sk.publicKey();
      expect(pk.equals(pk)).toBe(true);
      expect(pk.equals(await PublicKey.fromBytes(pk.toBytes()))).toBe(true);
      expect(pk.equals(other.publicKey())).toBe(false);
    });

    it("roundtrips keys and fingerprints through their codecs", async () => {
      const sk = await SecretKey.generate();
      const pk = await cbor.decode(
        publicKey.bytes(await cbor.encode(publicKey.value(sk.publicKey()))),
      );
      expect(pk.equals(sk.publicKey())).toBe(true);
      const fp = await cbor.decode(
        fingerprint.bytes(
          await cbor.encode(fingerprint.value(sk.fingerprint())),
        ),
      );
      expect(fp.equals(sk.fingerprint())).toBe(true);
      expect(() => publicKey.decode(new Uint8Array(3))).toThrow(CodecError);
      expect(() => publicKey.decode("key")).toThrow(CodecError);
      expect(() => fingerprint.decode(new Uint8Array(31))).toThrow(CodecError);
      expect(() =>
        publicKey.encode({
          toBytes: () => new Uint8Array(3),
        } as unknown as PublicKey),
      ).toThrow(CodecError);
      expect(() =>
        fingerprint.encode(sk.publicKey() as unknown as Fingerprint),
      ).toThrow(CodecError);
    });
  });

  it("refuses a disposed secret key", async () => {
    const sk = await SecretKey.generate();
    const domain = new TextEncoder().encode("dispose");
    const message = new TextEncoder().encode("message");
    const pk = sk.publicKey();
    const sig = sk.sign(message);

    sk.dispose();
    const operations: [string, () => unknown][] = [
      ["toBytes", () => sk.toBytes()],
      ["toPem", () => sk.toPem()],
      ["publicKey", () => sk.publicKey()],
      ["fingerprint", () => sk.fingerprint()],
      ["sign", () => sk.sign(message)],
    ];
    for (const [name, run] of operations) {
      expect(run, name).toThrow(/used after dispose/);
    }
    await expect(
      cose.signDetached(cbor.bytes.value(message), sk, domain),
    ).rejects.toThrow(/used after dispose/);

    const Subject = cbor.map({
      sub: cwt.claims.subject,
      nbf: cwt.claims.notBefore,
    });
    await expect(
      cwt.issue(Subject.value({ sub: "ark", nbf: 1n }), sk, domain),
    ).rejects.toThrow(/used after dispose/);

    expect(pk.verify(message, sig)).toBe(true);
    sk.dispose();
  });

  it("rejects a call pending on a disposed key", async () => {
    const sk = await SecretKey.generate();
    const pending = cose.signDetached(
      cbor.bytes.value(new Uint8Array(1)),
      sk,
      new TextEncoder().encode("dispose"),
    );
    sk.dispose();
    await expect(pending).rejects.toThrow(/used after dispose/);
  });
});
