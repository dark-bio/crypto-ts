// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/** COSE padding vectors and rejection cases shared with crypto-rs. */

import { afterEach, describe, expect, it, vi } from "vitest";
import { decode, encode } from "cborg";
import { cbor, cose, xdsa, xhpke } from "../src/index.js";
import { CosePadding as WasmPadding } from "../src/wasm/darkbio_crypto_wasm.js";
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

    for (const [floor, step, length, expected] of cases) {
      const padding = cose.Padding.buckets({ floor, step });
      const id = `${floor}/${step}/${length}`;
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

    for (const [name, padding, length, zeros] of [
      ["none", cose.Padding.none(), 3461, 0],
      ["buckets", cose.Padding.buckets({ floor: 8192, step: 20 }), 8192, 4731],
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
        expect(plaintext.length, name).toBe(length);
        expect(plaintext.slice(0, 3461), name).toEqual(sign1);
        expect(plaintext.slice(3461), name).toEqual(new Uint8Array(zeros));
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

  it("rejects invalid bucket parameters when constructing the policy", () => {
    for (const field of ["floor", "step"]) {
      for (const value of [
        0,
        -1,
        1.5,
        NaN,
        Infinity,
        -Infinity,
        4294967296,
        4294967301,
        Number.MAX_SAFE_INTEGER + 1,
        undefined,
        null,
        "1",
        1n,
      ]) {
        expect(
          () =>
            cose.Padding.buckets({
              floor: 8192,
              step: 20,
              [field]: value as number,
            }),
          `${field}/${String(value)}`,
        ).toThrow(`padding ${field} must be a positive 32 bit integer`);
      }
    }
  });

  it("rejects non-instance padding in seal and encrypt", async () => {
    const signer = await xdsa.SecretKey.generate();
    const recipient = await xhpke.SecretKey.generate();
    const domain = new Uint8Array();
    const msg = cbor.text.value("padding");
    const aad = cbor.nil.value(null);
    const sign1 = await cose.sign(msg, aad, signer, domain);
    const cases: [string, unknown][] = [
      ["buckets object", { name: "buckets", floor: 8192, step: 20 }],
      ["undefined", undefined],
    ];

    for (const [name, value] of cases) {
      const padding = value as cose.Padding;
      const operations = [
        () =>
          cose.seal(msg, aad, signer, recipient.publicKey(), domain, padding),
        () => cose.encrypt(sign1, aad, recipient.publicKey(), domain, padding),
      ];
      for (const operation of operations) {
        await expect(operation(), name).rejects.toThrow(
          "padding must be a Padding instance",
        );
      }
    }
  });

  it("frees each temporary WASM policy after success and failure", async () => {
    const signer = await xdsa.SecretKey.generate();
    const recipient = await xhpke.SecretKey.generate();
    const recipientKey = recipient.publicKey();
    const domain = new Uint8Array();
    const msg = cbor.text.value("reusable policy");
    const aad = cbor.nil.value(null);
    const sign1 = await cose.sign(msg, aad, signer, domain);
    const invalidCodec = cbor.text.value(1 as unknown as string);
    const invalidCbor = cbor.raw.value(1.5);
    const free = vi.spyOn(WasmPadding.prototype, "free");

    for (const padding of [
      cose.Padding.none(),
      cose.Padding.buckets({ floor: 8192, step: 20 }),
    ]) {
      const operations: [string, () => Promise<Uint8Array>, RegExp?][] = [
        [
          "seal",
          () => cose.seal(msg, aad, signer, recipientKey, domain, padding),
        ],
        [
          "encrypt",
          () => cose.encrypt(sign1, aad, recipientKey, domain, padding),
        ],
        [
          "payload codec",
          () =>
            cose.seal(invalidCodec, aad, signer, recipientKey, domain, padding),
          /not text/,
        ],
        [
          "seal AAD codec",
          () =>
            cose.seal(msg, invalidCodec, signer, recipientKey, domain, padding),
          /not text/,
        ],
        [
          "encrypt AAD codec",
          () =>
            cose.encrypt(sign1, invalidCodec, recipientKey, domain, padding),
          /not text/,
        ],
        [
          "payload CBOR",
          () =>
            cose.seal(invalidCbor, aad, signer, recipientKey, domain, padding),
          /invalid payload CBOR/,
        ],
        [
          "seal AAD CBOR",
          () =>
            cose.seal(msg, invalidCbor, signer, recipientKey, domain, padding),
          /invalid AAD CBOR/,
        ],
        [
          "encrypt AAD CBOR",
          () => cose.encrypt(sign1, invalidCbor, recipientKey, domain, padding),
          /invalid AAD CBOR/,
        ],
        [
          "seal again",
          () => cose.seal(msg, aad, signer, recipientKey, domain, padding),
        ],
        [
          "encrypt again",
          () => cose.encrypt(sign1, aad, recipientKey, domain, padding),
        ],
      ];
      const freed = new Set<WasmPadding>();
      for (const [name, operation, error] of operations) {
        free.mockClear();
        if (error) {
          await expect(operation(), name).rejects.toThrow(error);
        } else {
          const envelope = await operation();
          expect(
            await cose.open(
              cbor.text.bytes(envelope),
              aad,
              recipient,
              signer.publicKey(),
              domain,
            ),
            name,
          ).toBe("reusable policy");
        }
        expect(free, name).toHaveBeenCalledTimes(1);
        const policy = free.mock.contexts[0];
        expect(freed.has(policy), name).toBe(false);
        freed.add(policy);
      }
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
