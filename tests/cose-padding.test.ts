// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/** COSE padding vectors and rejection cases shared with crypto-rs. */

import { afterEach, describe, expect, it, vi } from "vitest";
import { decode, encode } from "cborg";
import { cbor, cose, xdsa, xhpke } from "../src/index.js";
import { paddedSize } from "../src/internal/padding.js";
import { cose_encrypt as wasmEncrypt } from "../src/wasm/darkbio_crypto_wasm.js";
import fixtures from "./testdata/cose/v0.16.json";
import padded from "./testdata/cose/padded.json";

/** Decodes a binary field from the shared Rust fixtures. */
function fromHex(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g) ?? [], (byte) => parseInt(byte, 16));
}

/** Opens the authenticated plaintext through xHPKE, retaining all padding. */
function openPlaintext(
  envelope: Uint8Array,
  aad: Uint8Array,
  recipient: xhpke.SecretKey,
  domain: Uint8Array,
): Uint8Array {
  const [protectedHeader, unprotected, ciphertext] = decode(envelope, {
    useMaps: true,
  });
  return recipient.open(
    new Uint8Array([...unprotected.get(-4), ...ciphertext]),
    encode(["Encrypt0", protectedHeader, encode(aad)]),
    domain,
  );
}

/** Seals arbitrary plaintext through xHPKE, bypassing the COSE padding writer. */
function sealPlaintext(
  plaintext: Uint8Array,
  aad: Uint8Array,
  recipient: xhpke.PublicKey,
  domain: Uint8Array,
): Uint8Array {
  // Bind the headers and external AAD specified by the wire profile
  const protectedHeader = encode(
    new Map<number, number | Uint8Array>([
      [1, -70001],
      [4, recipient.fingerprint().toBytes()],
    ]),
  );
  const sealed = recipient.seal(
    plaintext,
    encode(["Encrypt0", protectedHeader, encode(aad)]),
    domain,
  );
  return encode([
    protectedHeader,
    new Map([[-4, sealed.slice(0, 1120)]]),
    sealed.slice(1120),
  ]);
}

describe("COSE padding", () => {
  afterEach(() => vi.restoreAllMocks());

  // Pin each bucket and transition to the fixed expectations in crypto-rs.
  it("matches the bucket sequences and boundary targets", async () => {
    const recipient = await xhpke.SecretKey.fromBytes(
      new Uint8Array(32).fill(7),
    );
    const domain = new TextEncoder().encode("padding");
    const aad = new Uint8Array();
    const cases: [number, number, number, number][] = [];
    for (const [floor, step, sizes] of [
      [
        8192,
        20,
        [8192, 8602, 9033, 9485, 9960, 10458, 10981, 11531, 12108, 12714],
      ],
      [100, 3, [100, 134, 179, 239, 319, 426]],
    ] as const) {
      for (let i = 0; i < sizes.length; i++) {
        cases.push([floor, step, sizes[i], sizes[i]]);
        if (i + 1 < sizes.length) {
          cases.push([floor, step, sizes[i] + 1, sizes[i + 1]]);
        }
      }
    }
    cases.push(
      [8192, 20, 0, 8192],
      [8192, 20, 1, 8192],
      [8192, 20, 8193, 8602],
      [8192, 20, 8603, 9033],
      [8192, 20, 300000, 303278],
      [1, 4294967295, 100, 100],
      [1, 3, 101, 115],
    );

    // Check both the TS calculation and the actual encrypted plaintext
    for (const [floor, step, length, expected] of cases) {
      const padding: cose.Padding = { name: "buckets", floor, step };
      const id = `${floor}/${step}/${length}`;
      expect(paddedSize(length, padding), id).toBe(expected);
      const input = new Uint8Array(length).fill(0x42);
      const envelope = await cose.encrypt(
        input,
        cbor.bytes.value(aad),
        recipient.publicKey(),
        domain,
        padding,
      );
      const plaintext = openPlaintext(envelope, aad, recipient, domain);
      expect(plaintext.length, id).toBe(expected);
      expect(plaintext.slice(0, length), id).toEqual(input);
      expect(plaintext.slice(length), id).toEqual(
        new Uint8Array(expected - length),
      );
    }
  });

  // Large arithmetic boundaries are checked without allocating their buffers.
  it("preserves unpadded sizes and handles ceiling division at the wasm32 limit", () => {
    for (const length of [0, 1, 8192, 8193, 300000, 4294967295]) {
      expect(paddedSize(length, { name: "none" }), `${length}`).toBe(length);
    }
    expect(
      paddedSize(4294967295, {
        name: "buckets",
        floor: 4294967294,
        step: 4294967295,
      }),
    ).toBe(4294967295);
    expect(
      paddedSize(4294967295, {
        name: "buckets",
        floor: 1,
        step: 4294967295,
      }),
    ).toBe(4294967295);
    expect(() =>
      paddedSize(4294967295, {
        name: "buckets",
        floor: 4294967294,
        step: 1,
      }),
    ).toThrow(/bucket size/);
  });

  // Pin the raw plaintext, stripping and verification against the v0.16 corpus.
  it("seals and encrypts the exact padded and unpadded signed envelope", async () => {
    const signer = await xdsa.SecretKey.fromBytes(fromHex(fixtures.xdsa_seed));
    const recipient = await xhpke.SecretKey.fromBytes(
      fromHex(fixtures.xhpke_seed),
    );
    const sign1 = fromHex(fixtures.sign1);
    const payload = fromHex(fixtures.payload);
    const aad = fromHex(fixtures.aad);
    const domain = fromHex(fixtures.domain);
    vi.spyOn(Date, "now").mockReturnValue(1700000000000);

    for (const [padding, length, zeros] of [
      [{ name: "none" }, 3461, 0],
      [{ name: "buckets", floor: 8192, step: 20 }, 8192, 4731],
    ] as const) {
      const envelopes = [
        await cose.seal(
          cbor.bytes.value(payload),
          cbor.bytes.value(aad),
          signer,
          recipient.publicKey(),
          domain,
          padding,
        ),
        await cose.encrypt(
          sign1,
          cbor.bytes.value(aad),
          recipient.publicKey(),
          domain,
          padding,
        ),
      ];
      for (const envelope of envelopes) {
        const plaintext = openPlaintext(envelope, aad, recipient, domain);
        expect(plaintext.length, padding.name).toBe(length);
        expect(plaintext.slice(0, 3461), padding.name).toEqual(sign1);
        expect(plaintext.slice(3461), padding.name).toEqual(
          new Uint8Array(zeros),
        );
        expect(
          await cose.decrypt(
            envelope,
            cbor.bytes.value(aad),
            recipient,
            domain,
          ),
        ).toEqual(sign1);
        expect(
          await cose.open(
            cbor.bytes.bytes(envelope),
            cbor.bytes.value(aad),
            recipient,
            signer.publicKey(),
            domain,
            0,
          ),
        ).toEqual(payload);
      }
    }
    expect(sign1).toEqual(fromHex(fixtures.sign1));
    expect(payload).toEqual(fromHex(fixtures.payload));
  });

  // The padded fixture is imported unchanged from crypto-rs/src/cose/testdata.
  it("opens the shared padded Rust fixture", async () => {
    const signer = await xdsa.SecretKey.fromBytes(fromHex(padded.xdsa_seed));
    const recipient = await xhpke.SecretKey.fromBytes(
      fromHex(padded.xhpke_seed),
    );
    const domain = fromHex(padded.domain);
    const aad = fromHex(padded.aad);
    const envelope = fromHex(padded.encrypt0);
    const sign1 = fromHex(padded.sign1);
    const plaintext = openPlaintext(envelope, aad, recipient, domain);
    expect(plaintext.length).toBe(8192);
    expect(plaintext.slice(0, 3470)).toEqual(sign1);
    expect(plaintext.slice(3470)).toEqual(new Uint8Array(4722));
    expect(
      await cose.decrypt(envelope, cbor.bytes.value(aad), recipient, domain),
    ).toEqual(sign1);
    expect(
      await cose.open(
        cbor.bytes.bytes(envelope),
        cbor.bytes.value(aad),
        recipient,
        signer.publicKey(),
        domain,
      ),
    ).toEqual(fromHex(padded.payload));
  });

  // Each rejected policy is followed by a successful seal on the same instance.
  it("rejects every invalid policy without trapping the shared instance", async () => {
    const signer = await xdsa.SecretKey.generate();
    const recipient = await xhpke.SecretKey.generate();
    const domain = new Uint8Array();
    const msg = cbor.text.value("still usable");
    const aad = cbor.nil.value(null);
    const sign1 = await cose.sign(msg, aad, signer, domain);
    const cases: [string, unknown][] = [
      ["name", { name: "unknown" }],
      ["name", {}],
      ["name", null],
      ["name", undefined],
    ];
    for (const field of ["floor", "step"]) {
      for (const value of [
        0,
        -1,
        1.5,
        NaN,
        Infinity,
        -Infinity,
        4294967296,
        Number.MAX_SAFE_INTEGER + 1,
        undefined,
        null,
        "1",
        1n,
      ]) {
        cases.push([
          field,
          { name: "buckets", floor: 8192, step: 20, [field]: value },
        ]);
      }
    }
    cases.push([
      "allocation limit",
      { name: "buckets", floor: 2147483648, step: 20 },
    ]);

    for (const [field, value] of cases) {
      const padding = value as cose.Padding;
      const operations = [
        () =>
          cose.seal(msg, aad, signer, recipient.publicKey(), domain, padding),
        () => cose.encrypt(sign1, aad, recipient.publicKey(), domain, padding),
      ];
      for (const operation of operations) {
        const error = await operation().catch((error: unknown) => error);
        expect(error, field).toBeInstanceOf(Error);
        expect(error, field).not.toBeInstanceOf(WebAssembly.RuntimeError);
        expect((error as Error).message, field).toContain(field);
        const recovered = await cose.seal(
          msg,
          aad,
          signer,
          recipient.publicKey(),
          domain,
          { name: "none" },
        );
        expect(
          await cose.open(
            cbor.text.bytes(recovered),
            aad,
            recipient,
            signer.publicKey(),
            domain,
          ),
        ).toBe("still usable");
      }
    }
  });

  it("reserves encryption overhead and remains usable after boundary rejections", async () => {
    const signer = await xdsa.SecretKey.generate();
    const recipient = await xhpke.SecretKey.generate();
    const recipientKey = recipient.publicKey();
    const domain = new Uint8Array();
    const msg = cbor.text.value("still usable");
    const aad = cbor.nil.value(null);
    const encodedAad = await cbor.encode(aad);
    const sign1 = await cose.sign(msg, aad, signer, domain);

    for (const size of [2147479552, 2147483647]) {
      const padding: cose.Padding = { name: "buckets", floor: size, step: 1 };
      const operations = [
        () => cose.seal(msg, aad, signer, recipientKey, domain, padding),
        () => cose.encrypt(sign1, aad, recipientKey, domain, padding),
        () => wasmEncrypt(sign1, encodedAad, recipientKey._wasm, domain, size),
      ];
      for (const operation of operations) {
        const error = await Promise.resolve()
          .then(operation)
          .catch((error: unknown) => error);
        expect(error, `${size}`).toBeInstanceOf(Error);
        expect(error, `${size}`).not.toBeInstanceOf(WebAssembly.RuntimeError);
        expect((error as Error).message, `${size}`).toContain(
          "padded plaintext",
        );

        const sealed = await cose.seal(msg, aad, signer, recipientKey, domain, {
          name: "none",
        });
        expect(
          await cose.open(
            cbor.text.bytes(sealed),
            aad,
            recipient,
            signer.publicKey(),
            domain,
          ),
        ).toBe("still usable");
      }
    }
  });

  // Model huge input lengths without allocating gigabytes or entering WASM.
  it("rejects overflowing sizes before copying into WASM and remains usable", async () => {
    const signer = await xdsa.SecretKey.generate();
    const recipient = await xhpke.SecretKey.generate();
    const domain = new Uint8Array();
    const aad = cbor.nil.value(null);
    for (const [length, padding, reason] of [
      [
        4294967295,
        { name: "buckets", floor: 4294967294, step: 1 },
        "bucket size",
      ],
      [4294967296, { name: "none" }, "signed envelope length"],
      [2147483648, { name: "none" }, "allocation limit"],
    ] as const) {
      const oversized = new Proxy(new Uint8Array(), {
        get(target, key) {
          return key === "length" ? length : Reflect.get(target, key, target);
        },
      });
      const error = await cose
        .encrypt(oversized, aad, recipient.publicKey(), domain, padding)
        .catch((error: unknown) => error);
      expect(error, reason).toBeInstanceOf(Error);
      expect(error, reason).not.toBeInstanceOf(WebAssembly.RuntimeError);
      expect((error as Error).message, reason).toContain(reason);
      const sealed = await cose.seal(
        cbor.text.value("ok"),
        aad,
        signer,
        recipient.publicKey(),
        domain,
        { name: "none" },
      );
      expect(
        await cose.open(
          cbor.text.bytes(sealed),
          aad,
          recipient,
          signer.publicKey(),
          domain,
        ),
      ).toBe("ok");
    }
  });

  // Accept any count of zeros but reject a nonzero byte anywhere after the item.
  it("opens off-bucket padding and rejects nonzero padding", async () => {
    const signer = await xdsa.SecretKey.fromBytes(fromHex(fixtures.xdsa_seed));
    const recipient = await xhpke.SecretKey.fromBytes(
      new Uint8Array(32).fill(7),
    );
    const sign1 = fromHex(fixtures.sign1);
    const aad = fromHex(fixtures.aad);
    const domain = fromHex(fixtures.domain);
    const plaintext = new Uint8Array(3498);
    plaintext.set(sign1);
    const envelope = sealPlaintext(
      plaintext,
      aad,
      recipient.publicKey(),
      domain,
    );
    expect(
      await cose.decrypt(envelope, cbor.bytes.value(aad), recipient, domain),
    ).toEqual(sign1);
    expect(
      await cose.open(
        cbor.bytes.bytes(envelope),
        cbor.bytes.value(aad),
        recipient,
        signer.publicKey(),
        domain,
      ),
    ).toEqual(fromHex(fixtures.payload));

    for (const position of [3461, 3479, 3497]) {
      for (const byte of [1, 255]) {
        plaintext[position] = byte;
        const invalid = sealPlaintext(
          plaintext,
          aad,
          recipient.publicKey(),
          domain,
        );
        await expect(
          cose.decrypt(invalid, cbor.bytes.value(aad), recipient, domain),
          `${position}/${byte}`,
        ).rejects.toThrow(/invalid padding/);
        await expect(
          cose.open(
            cbor.bytes.bytes(invalid),
            cbor.bytes.value(aad),
            recipient,
            signer.publicKey(),
            domain,
          ),
          `${position}/${byte}`,
        ).rejects.toThrow(/invalid padding/);
        plaintext[position] = 0;
      }
    }
  });

  // Padding starts after one complete CBOR item, including its own trailing zeros.
  it("rejects malformed plaintext and preserves the original CBOR item", async () => {
    const recipient = await xhpke.SecretKey.fromBytes(
      new Uint8Array(32).fill(7),
    );
    const aad = new Uint8Array();
    const domain = new TextEncoder().encode("padding");
    for (const bytes of [
      [],
      [0x82, 0],
      [0x81, 0x42, 0],
      [0x18, 0],
      [0xc0, 0],
      [0x9f, 0xff],
      [0x5b, 255, 255, 255, 255, 255, 255, 255, 255],
      [...Array(32).fill(0x81), 0],
    ]) {
      const envelope = sealPlaintext(
        new Uint8Array(bytes),
        aad,
        recipient.publicKey(),
        domain,
      );
      await expect(
        cose.decrypt(envelope, cbor.bytes.value(aad), recipient, domain),
        bytes.join(","),
      ).rejects.toThrow();
    }
    const item = new Uint8Array([0x82, 0xa2, 2, 0, 1, 0, 0x43, 0, 1, 0]);
    const envelope = sealPlaintext(
      new Uint8Array([...item, 0, 0, 0]),
      aad,
      recipient.publicKey(),
      domain,
    );
    expect(
      await cose.decrypt(envelope, cbor.bytes.value(aad), recipient, domain),
    ).toEqual(item);
  });
});
