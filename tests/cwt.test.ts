// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/** CWT claim schemas, signature verification and validity windows. */

import { describe, it, expect } from "vitest";
import { decode as cborgDecode, encode as cborgEncode } from "cborg";
import * as cbor from "../src/cbor.js";
import { CodecError } from "../src/cbor.js";
import {
  DebugState,
  IntendedUse,
  claims,
  confirmation,
  issue,
  issueAt,
  oemid,
  peek,
  signer,
  verify,
  version,
  type Oemid,
} from "../src/cwt.js";
import * as cose from "../src/cose.js";
import * as xdsa from "../src/xdsa.js";
import * as xhpke from "../src/xhpke.js";
import cwtFixtures from "./testdata/cwt/v0.16.json";

/** Application domain used to sign the test tokens. */
const domain = new TextEncoder().encode("test-domain");

/** Claims carried by the basic device token. */
const Basic = cbor.map({
  sub: claims.subject,
  nbf: claims.notBefore,
  exp: claims.expiration,
  cnf: claims.confirmXdsa,
});

/** Issues a device token bound to the supplied public key. */
async function basicToken(
  issuer: xdsa.SecretKey,
  device: xdsa.PublicKey,
): Promise<Uint8Array> {
  return issue(
    Basic.value({
      sub: "device-abc",
      nbf: 1000000n,
      exp: 2000000n,
      cnf: device,
    }),
    issuer,
    domain,
  );
}

describe("cwt", () => {
  function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function fromHex(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  describe("issue/verify", () => {
    it("issues and verifies a basic token", async () => {
      const issuerKey = await xdsa.SecretKey.generate();
      const deviceKey = await xdsa.SecretKey.generate();
      const token = await basicToken(issuerKey, deviceKey.publicKey());
      expect(token.length).toBeGreaterThan(0);

      const verified = await verify(
        Basic.bytes(token),
        issuerKey.publicKey(),
        domain,
        1500000,
      );
      expect(verified.sub).toBe("device-abc");
      expect(verified.nbf).toBe(1000000n);
      expect(verified.exp).toBe(2000000n);
      expect(verified.cnf.equals(deviceKey.publicKey())).toBe(true);
    });

    it("records the supplied COSE timestamp independently of claim validity", async () => {
      const issuer = await xdsa.SecretKey.generate();
      const validity = cbor.map({ nbf: claims.notBefore });
      const values = { nbf: 1000n };
      const min = -(1n << 63n);
      const max = (1n << 63n) - 1n;

      // Read the timestamp directly from the protected header
      for (const timestamp of [min, -37, max]) {
        const token = await issueAt(
          validity.value(values),
          issuer,
          domain,
          timestamp,
        );
        const [header] = cborgDecode(token, { useMaps: true });
        expect(cborgDecode(header, { useMaps: true }).get(-70002)).toBe(
          timestamp,
        );
        expect(
          await verify(validity.bytes(token), issuer.publicKey(), domain, 1000),
        ).toEqual(values);
      }

      // Invalid signing times fail before the WASM call
      for (const time of [
        0.5,
        NaN,
        Infinity,
        -Infinity,
        2 ** 53,
        min - 1n,
        max + 1n,
        undefined,
      ]) {
        await expect(
          issueAt(validity.value(values), issuer, domain, time as number),
          String(time),
        ).rejects.toThrow(RangeError);
      }
    });

    it("accepts a fractional or bigint now and refuses one outside 64 bits", async () => {
      const issuerKey = await xdsa.SecretKey.generate();
      const deviceKey = await xdsa.SecretKey.generate();
      const token = await basicToken(issuerKey, deviceKey.publicKey());
      const issuerPub = issuerKey.publicKey();
      expect(
        (await verify(Basic.bytes(token), issuerPub, domain, 1500000.5)).nbf,
      ).toBe(1000000n);
      expect(
        (await verify(Basic.bytes(token), issuerPub, domain, 1500000n)).nbf,
      ).toBe(1000000n);
      await expect(
        verify(Basic.bytes(token), issuerPub, domain, -1),
      ).rejects.toThrow();
      await expect(
        verify(Basic.bytes(token), issuerPub, domain, -1n),
      ).rejects.toThrow();
      await expect(
        verify(Basic.bytes(token), issuerPub, domain, 2 ** 64 + 1500000),
      ).rejects.toThrow();
      await expect(
        verify(Basic.bytes(token), issuerPub, domain, (1n << 64n) + 1500000n),
      ).rejects.toThrow();
      for (const bogus of [null, false, "0", []]) {
        await expect(
          verify(
            Basic.bytes(token),
            issuerPub,
            domain,
            bogus as unknown as number,
          ),
        ).rejects.toThrow();
      }
    });

    it("roundtrips all standard CWT claims", async () => {
      const Standard = cbor.map({
        iss: claims.issuer,
        sub: claims.subject,
        aud: claims.audience,
        exp: claims.expiration,
        nbf: claims.notBefore,
        iat: claims.issuedAt,
        cti: claims.tokenId,
      });
      const issuerKey = await xdsa.SecretKey.generate();
      const values = {
        iss: "issuer",
        sub: "subject",
        aud: "audience",
        exp: 2000000n,
        nbf: 1000000n,
        iat: 1000000n,
        cti: new Uint8Array([1, 2, 3, 4]),
      };
      const token = await issue(Standard.value(values), issuerKey, domain);
      const verified = await verify(
        Standard.bytes(token),
        issuerKey.publicKey(),
        domain,
        1500000,
      );
      expect(verified).toEqual(values);
    });

    it("skips temporal validation when now is undefined", async () => {
      const Timeless = cbor.map({ sub: claims.subject, nbf: claims.notBefore });
      const issuerKey = await xdsa.SecretKey.generate();
      const token = await issue(
        Timeless.value({ sub: "test", nbf: 1000000n }),
        issuerKey,
        domain,
      );
      const verified = await verify(
        Timeless.bytes(token),
        issuerKey.publicKey(),
        domain,
      );
      expect(verified.sub).toBe("test");
    });

    it("validates the boundaries of the validity", async () => {
      const issuerKey = await xdsa.SecretKey.generate();
      const deviceKey = await xdsa.SecretKey.generate();
      const token = await basicToken(issuerKey, deviceKey.publicKey());
      const issuerPub = issuerKey.publicKey();
      // now == nbf passes, now == exp fails
      expect(
        (await verify(Basic.bytes(token), issuerPub, domain, 1000000)).sub,
      ).toBe("device-abc");
      await expect(
        verify(Basic.bytes(token), issuerPub, domain, 2000000),
      ).rejects.toThrow();
      // Before nbf and after exp fail
      await expect(
        verify(Basic.bytes(token), issuerPub, domain, 999999),
      ).rejects.toThrow();
      await expect(
        verify(Basic.bytes(token), issuerPub, domain, 3000000),
      ).rejects.toThrow();
    });

    it("rejects token with wrong verifier", async () => {
      const issuerKey = await xdsa.SecretKey.generate();
      const otherKey = await xdsa.SecretKey.generate();
      const deviceKey = await xdsa.SecretKey.generate();
      const token = await basicToken(issuerKey, deviceKey.publicKey());
      await expect(
        verify(Basic.bytes(token), otherKey.publicKey(), domain, 1500000),
      ).rejects.toThrow();
    });

    it("rejects token with wrong domain", async () => {
      const issuerKey = await xdsa.SecretKey.generate();
      const deviceKey = await xdsa.SecretKey.generate();
      const token = await basicToken(issuerKey, deviceKey.publicKey());
      await expect(
        verify(
          Basic.bytes(token),
          issuerKey.publicKey(),
          new TextEncoder().encode("other"),
          1500000,
        ),
      ).rejects.toThrow();
    });

    it("passes without expiration when time check is on", async () => {
      const Permanent = cbor.map({
        sub: claims.subject,
        nbf: claims.notBefore,
      });
      const issuerKey = await xdsa.SecretKey.generate();
      const token = await issue(
        Permanent.value({ sub: "forever", nbf: 1000000n }),
        issuerKey,
        domain,
      );
      const verified = await verify(
        Permanent.bytes(token),
        issuerKey.publicKey(),
        domain,
        9999999999,
      );
      expect(verified.sub).toBe("forever");
    });

    it("requires not before when time check is on", async () => {
      const Undated = cbor.map({ sub: claims.subject });
      const issuerKey = await xdsa.SecretKey.generate();
      const token = await issue(
        Undated.value({ sub: "undated" }),
        issuerKey,
        domain,
      );
      await expect(
        verify(Undated.bytes(token), issuerKey.publicKey(), domain, 1500000),
      ).rejects.toThrow();
      expect(
        (await verify(Undated.bytes(token), issuerKey.publicKey(), domain)).sub,
      ).toBe("undated");
    });
  });

  describe("confirm key binding", () => {
    it("roundtrips an xDSA confirm key", async () => {
      const issuerKey = await xdsa.SecretKey.generate();
      const deviceKey = await xdsa.SecretKey.generate();
      const token = await basicToken(issuerKey, deviceKey.publicKey());
      const verified = await verify(
        Basic.bytes(token),
        issuerKey.publicKey(),
        domain,
        1500000,
      );
      expect(toHex(verified.cnf.toBytes())).toBe(
        toHex(deviceKey.publicKey().toBytes()),
      );
    });

    it("roundtrips an xHPKE confirm key", async () => {
      const Crypto = cbor.map({
        sub: claims.subject,
        cnf: claims.confirmXhpke,
      });
      const issuerKey = await xdsa.SecretKey.generate();
      const deviceKey = await xhpke.SecretKey.generate();
      const token = await issue(
        Crypto.value({ sub: "device", cnf: deviceKey.publicKey() }),
        issuerKey,
        domain,
      );
      const verified = await verify(
        Crypto.bytes(token),
        issuerKey.publicKey(),
        domain,
      );
      expect(verified.cnf.equals(deviceKey.publicKey())).toBe(true);
    });

    it("rejects an xHPKE confirmation decoded as an xDSA key", async () => {
      const Crypto = cbor.map({
        sub: claims.subject,
        cnf: claims.confirmXhpke,
      });
      const Signer = cbor.map({
        sub: claims.subject,
        cnf: claims.confirmXdsa,
      });
      const issuerKey = await xdsa.SecretKey.generate();
      const deviceKey = await xhpke.SecretKey.generate();
      const token = await issue(
        Crypto.value({ sub: "device", cnf: deviceKey.publicKey() }),
        issuerKey,
        domain,
      );
      await expect(
        verify(Signer.bytes(token), issuerKey.publicKey(), domain),
      ).rejects.toThrow(CodecError);
    });

    it("refuses confirmations of the wrong shape", async () => {
      const key = (await xdsa.SecretKey.generate()).publicKey();
      const codec = confirmation(xdsa.ALGORITHM_ID, xdsa.publicKey);
      const coseKey = (entries: [number, unknown][]) =>
        new Map([[1, new Map(entries)]]);
      expect(
        codec
          .decode(
            coseKey([
              [1, -70000],
              [-2, key.toBytes()],
            ]),
          )
          .equals(key),
      ).toBe(true);
      expect(() =>
        codec.decode(
          coseKey([
            [1, -70001],
            [-2, key.toBytes()],
          ]),
        ),
      ).toThrow(CodecError);
      expect(() =>
        codec.decode(
          coseKey([
            [1, -70000],
            [-2, key.toBytes()],
            [3, 1],
          ]),
        ),
      ).toThrow(CodecError);
      expect(() =>
        codec.decode(
          coseKey([
            [1, -70000],
            [-2, key.toBytes().subarray(1)],
          ]),
        ),
      ).toThrow(CodecError);
      expect(() => codec.decode(new Map([[2, new Map()]]))).toThrow(CodecError);
      expect(() => codec.decode(key.toBytes())).toThrow(CodecError);
    });
  });

  describe("signer/peek", () => {
    it("extracts signer fingerprint", async () => {
      const issuerKey = await xdsa.SecretKey.generate();
      const deviceKey = await xdsa.SecretKey.generate();
      const token = await basicToken(issuerKey, deviceKey.publicKey());
      expect((await signer(token)).equals(issuerKey.fingerprint())).toBe(true);
    });

    it("peeks at unverified claims", async () => {
      const issuerKey = await xdsa.SecretKey.generate();
      const deviceKey = await xdsa.SecretKey.generate();
      const token = await basicToken(issuerKey, deviceKey.publicKey());
      const peeked = await peek(Basic.bytes(token));
      expect(peeked.sub).toBe("device-abc");
      expect(peeked.cnf.equals(deviceKey.publicKey())).toBe(true);
    });

    it("refuses a non-canonical payload", async () => {
      const issuerKey = await xdsa.SecretKey.generate();
      const deviceKey = await xdsa.SecretKey.generate();
      const token = await basicToken(issuerKey, deviceKey.publicKey());
      const envelope = cborgDecode(token, { useMaps: true }) as unknown[];
      envelope[2] = new Uint8Array([0xa2, 0x02, 0x61, 0x61, 0x02, 0x61, 0x62]);
      await expect(peek(cbor.raw.bytes(cborgEncode(envelope)))).rejects.toThrow(
        /invalid payload CBOR/,
      );
    });
  });

  describe("claim sets", () => {
    it("refuses a token with claims beyond the set", async () => {
      const issuerKey = await xdsa.SecretKey.generate();
      const deviceKey = await xdsa.SecretKey.generate();
      const token = await basicToken(issuerKey, deviceKey.publicKey());
      const Narrower = cbor.map({
        sub: claims.subject,
        nbf: claims.notBefore,
        exp: claims.expiration,
      });
      await expect(
        verify(Narrower.bytes(token), issuerKey.publicKey(), domain),
      ).rejects.toThrow("unexpected key 8");
    });

    it("refuses a token missing a claim of the set", async () => {
      const issuerKey = await xdsa.SecretKey.generate();
      const deviceKey = await xdsa.SecretKey.generate();
      const token = await basicToken(issuerKey, deviceKey.publicKey());
      const Wider = cbor.map({ ...basicFields(), iss: claims.issuer });
      await expect(
        verify(Wider.bytes(token), issuerKey.publicKey(), domain),
      ).rejects.toThrow("missing key 1");
      const Lenient = cbor.map({
        ...basicFields(),
        iss: cbor.optional(claims.issuer),
      });
      const verified = await verify(
        Lenient.bytes(token),
        issuerKey.publicKey(),
        domain,
      );
      expect(verified.iss).toBeUndefined();
      expect(verified.sub).toBe("device-abc");
    });

    it("carries a 64 bit expiry exactly", async () => {
      const issuerKey = await xdsa.SecretKey.generate();
      const deviceKey = await xdsa.SecretKey.generate();
      const token = await issue(
        Basic.value({
          sub: "placeholder",
          nbf: 0n,
          exp: (1n << 64n) - 1n,
          cnf: deviceKey.publicKey(),
        }),
        issuerKey,
        domain,
      );
      const peeked = await peek(Basic.bytes(token));
      expect(peeked.exp).toBe((1n << 64n) - 1n);
    });

    it("refuses a claim set that is not a map", async () => {
      const issuerKey = await xdsa.SecretKey.generate();
      await expect(
        issue(cbor.text.value("not a claims map"), issuerKey, domain),
      ).rejects.toThrow(/major type/);
      await expect(
        issueAt(cbor.text.value("not a claims map"), issuerKey, domain, 0),
      ).rejects.toThrow(/major type/);

      // Sign the text as an ordinary COSE payload
      const signed = await cose.sign(
        cbor.text.value("not a claims map"),
        cbor.nil.value(null),
        issuerKey,
        domain,
      );
      await expect(peek(cbor.raw.bytes(signed))).rejects.toThrow(/major type/);
      await expect(
        verify(cbor.raw.bytes(signed), issuerKey.publicKey(), domain),
      ).rejects.toThrow(/major type/);
    });

    it("rejects malformed signed claims with and without a validity check", async () => {
      const issuer = await xdsa.SecretKey.generate();
      const verifier = issuer.publicKey();
      const valid = await issueAt(
        cbor.map({ nbf: claims.notBefore }).value({ nbf: 0n }),
        issuer,
        domain,
        0,
      );
      const [header, unprotected] = cborgDecode(valid, { useMaps: true });
      const prefix = new TextEncoder().encode("dark-bio-v1:");
      const aad = cborgEncode([new Uint8Array([...prefix, ...domain]), null]);

      // Sign the raw claims vectors from crypto-rs without normalizing their CBOR
      const cases: [number[], RegExp][] = [
        [[0x80], /major type/],
        [[0xa1, 5], /unexpected end of data/],
        [[0xa1, 5, 0, 0], /unexpected trailing bytes/],
        [[0xa2, 5, 0, 1, 0], /map key order/],
        [[0xa3, 1, 0, 1, 0, 5, 0], /duplicate map key/],
        [[0xa2, 4, 1, 4, 1], /duplicate claim key 4/],
        [[0xa2, 5, 0, 5, 0], /duplicate claim key 5/],
        [[0xa2, 1, 0x81, 0x61, 0xff, 5, 0], /UTF-8/],
        [[0xa2, 1, 0xa2, 4, 0, 4, 0, 5, 0], /duplicate map key/],
        [[0xa2, 1, ...Array(31).fill(0x81), 0, 5, 0], /nesting depth/],
      ];
      for (const [bytes, reason] of cases) {
        const payload = new Uint8Array(bytes);
        const signature = issuer.sign(
          cborgEncode(["Signature1", header, aad, payload]),
        );
        const token = cborgEncode([
          header,
          unprotected,
          payload,
          signature.toBytes(),
        ]);
        for (const now of [0, undefined]) {
          await expect(
            verify(cbor.raw.bytes(token), verifier, domain, now),
            `${toHex(payload)}/${now}`,
          ).rejects.toThrow(reason);
        }
      }
    });

    it("reads a token of unknown shape as a raw map", async () => {
      const issuerKey = await xdsa.SecretKey.generate();
      const deviceKey = await xdsa.SecretKey.generate();
      const token = await basicToken(issuerKey, deviceKey.publicKey());
      const raw = (await peek(cbor.raw.bytes(token))) as Map<number, unknown>;
      expect([...raw.keys()]).toEqual([2, 4, 5, 8]);
    });
  });

  describe("EAT claims", () => {
    it("roundtrips UEID", async () => {
      const Device = cbor.map({
        sub: claims.subject,
        nbf: claims.notBefore,
        ueid: claims.eat.ueid,
      });
      const issuerKey = await xdsa.SecretKey.generate();
      const token = await issue(
        Device.value({
          sub: "device",
          nbf: 1000000n,
          ueid: new Uint8Array([1, 2, 3, 4]),
        }),
        issuerKey,
        domain,
      );
      const verified = await verify(
        Device.bytes(token),
        issuerKey.publicKey(),
        domain,
        1500000,
      );
      expect(toHex(verified.ueid)).toBe("01020304");
    });

    it("roundtrips every OEMID form", async () => {
      const Device = cbor.map({ sub: claims.subject, oem: claims.eat.oemid });
      const issuerKey = await xdsa.SecretKey.generate();
      for (const oem of [
        { pen: 12345n },
        { ieee: new Uint8Array([1, 2, 3]) },
        { random: new Uint8Array(16).fill(0xab) },
      ]) {
        const token = await issue(
          Device.value({ sub: "device", oem }),
          issuerKey,
          domain,
        );
        const verified = await verify(
          Device.bytes(token),
          issuerKey.publicKey(),
          domain,
        );
        expect(verified.oem).toEqual(oem);
      }
    });

    it("validates OEMID lengths", () => {
      expect(() => oemid.encode("acme" as unknown as Oemid)).toThrow(
        CodecError,
      );
      for (const bogus of [
        {},
        { ieee: "abc" },
        { random: "0123456789abcdef" },
        { pen: 1n, ieee: new Uint8Array(3) },
        Object.create({ pen: 1n }) as object,
        { oui: new Uint8Array(3) },
      ]) {
        expect(() => oemid.encode(bogus as unknown as Oemid)).toThrow(
          CodecError,
        );
      }
      expect(() => oemid.encode({ random: new Uint8Array(15) })).toThrow(
        CodecError,
      );
      expect(() => oemid.encode({ random: new Uint8Array(17) })).toThrow(
        CodecError,
      );
      expect(() => oemid.encode({ ieee: new Uint8Array(2) })).toThrow(
        CodecError,
      );
      expect(() => oemid.encode({ ieee: new Uint8Array(4) })).toThrow(
        CodecError,
      );
      expect(() => oemid.decode(new Uint8Array(5))).toThrow(CodecError);
      expect(() => oemid.decode("x")).toThrow(CodecError);
    });

    it("roundtrips hw/sw version", async () => {
      const Device = cbor.map({
        sub: claims.subject,
        hwv: claims.eat.hwVersion,
        swv: claims.eat.swVersion,
      });
      const issuerKey = await xdsa.SecretKey.generate();
      const token = await issue(
        Device.value({ sub: "device", hwv: "2.0", swv: "1.5.3" }),
        issuerKey,
        domain,
      );
      const verified = await verify(
        Device.bytes(token),
        issuerKey.publicKey(),
        domain,
      );
      expect(verified.hwv).toBe("2.0");
      expect(verified.swv).toBe("1.5.3");
    });

    it("refuses versions with the scheme element", () => {
      expect(version.decode(["1.0"])).toBe("1.0");
      expect(() => version.decode(["1.0", "semver"])).toThrow(CodecError);
      expect(() => version.decode("1.0")).toThrow(CodecError);
    });

    it("roundtrips debug state and intended use", async () => {
      const Device = cbor.map({
        sub: claims.subject,
        debug: claims.eat.debugStatus,
        use: claims.eat.intendedUse,
      });
      const issuerKey = await xdsa.SecretKey.generate();
      const token = await issue(
        Device.value({
          sub: "device",
          debug: DebugState.DisabledPermanently,
          use: IntendedUse.Provisioning,
        }),
        issuerKey,
        domain,
      );
      const verified = await verify(
        Device.bytes(token),
        issuerKey.publicKey(),
        domain,
      );
      expect(verified.debug).toBe(DebugState.DisabledPermanently);
      expect(verified.use).toBe(IntendedUse.Provisioning);
      expect(() => claims.eat.debugStatus.codec.decode(9)).toThrow(CodecError);
      expect(() => claims.eat.intendedUse.codec.decode(0)).toThrow(CodecError);
    });

    it("roundtrips boot claims", async () => {
      const Device = cbor.map({
        sub: claims.subject,
        uptime: claims.eat.uptime,
        oemBoot: claims.eat.oemBoot,
        bootCount: claims.eat.bootCount,
        bootSeed: claims.eat.bootSeed,
      });
      const issuerKey = await xdsa.SecretKey.generate();
      const values = {
        sub: "device",
        uptime: 3600n,
        oemBoot: true,
        bootCount: 42n,
        bootSeed: new Uint8Array([9, 8, 7, 6]),
      };
      const token = await issue(Device.value(values), issuerKey, domain);
      const verified = await verify(
        Device.bytes(token),
        issuerKey.publicKey(),
        domain,
      );
      expect(verified).toEqual(values);
    });

    it("roundtrips a full EAT token", async () => {
      const Full = cbor.map({
        iss: claims.issuer,
        sub: claims.subject,
        nbf: claims.notBefore,
        exp: claims.expiration,
        cnf: claims.confirmXdsa,
        ueid: claims.eat.ueid,
        hwv: claims.eat.hwVersion,
        swv: claims.eat.swVersion,
        swn: claims.eat.swName,
        debug: claims.eat.debugStatus,
        oemBoot: claims.eat.oemBoot,
        use: claims.eat.intendedUse,
      });
      const issuerKey = await xdsa.SecretKey.generate();
      const deviceKey = await xdsa.SecretKey.generate();
      const values = {
        iss: "manufacturer",
        sub: "device-001",
        nbf: 1000000n,
        exp: 9000000n,
        cnf: deviceKey.publicKey(),
        ueid: new TextEncoder().encode("SN-999"),
        hwv: "2.0",
        swv: "1.5.3",
        swn: "secure-fw",
        debug: DebugState.DisabledFullyPermanently,
        oemBoot: true,
        use: IntendedUse.Registration,
      };
      const token = await issue(
        Full.value(values),
        issuerKey,
        new TextEncoder().encode("device-attestation"),
      );
      const verified = await verify(
        Full.bytes(token),
        issuerKey.publicKey(),
        new TextEncoder().encode("device-attestation"),
        1500000,
      );
      expect(verified.cnf.equals(deviceKey.publicKey())).toBe(true);
      expect({ ...verified, cnf: undefined }).toEqual({
        ...values,
        cnf: undefined,
      });
    });
  });

  describe("custom claims", () => {
    it("roundtrips custom integer keyed claims", async () => {
      const Custom = cbor.map({
        sub: claims.subject,
        nbf: claims.notBefore,
        label: cbor.field(1000, cbor.text),
        answer: cbor.field(1001, cbor.uint),
      });
      const issuerKey = await xdsa.SecretKey.generate();
      const values = {
        sub: "test",
        nbf: 1000000n,
        label: "custom-value",
        answer: 42n,
      };
      const token = await issue(Custom.value(values), issuerKey, domain);
      const verified = await verify(
        Custom.bytes(token),
        issuerKey.publicKey(),
        domain,
        1500000,
      );
      expect(verified).toEqual(values);
    });
  });

  it("keeps a leading byte order mark in the subject", async () => {
    const issuer = await xdsa.SecretKey.generate();
    const Subject = cbor.map({
      sub: claims.subject,
      nbf: claims.notBefore,
    });
    const token = await issue(
      Subject.value({ sub: "\uFEFFadmin", nbf: 1n }),
      issuer,
      domain,
    );
    const got = await verify(
      Subject.bytes(token),
      issuer.publicKey(),
      domain,
      1,
    );
    expect(got.sub).toBe("\uFEFFadmin");
  });

  // Read the signed claims from the v0.16 wire fixtures
  describe("v0.16 fixtures", () => {
    /** Claims in the fixture whose validity window starts in the future. */
    const NoExp = cbor.map({
      sub: claims.subject,
      nbf: claims.notBefore,
      cnf: claims.confirmXdsa,
    });

    it("verifies the committed tokens", async () => {
      const issuer = await xdsa.SecretKey.fromBytes(
        fromHex(cwtFixtures.xdsa_seed),
      );
      const fixtureDomain = fromHex(cwtFixtures.domain);
      const now = cwtFixtures.now;

      // Verify the committed valid token and check the decoded claims
      const valid = fromHex(cwtFixtures.valid);
      const got = await verify(
        Basic.bytes(valid),
        issuer.publicKey(),
        fixtureDomain,
        now,
      );
      expect(got.sub).toBe("fixture");
      expect(got.exp).toBe(4102444800n);
      expect(got.nbf).toBe(1500000000n);
      expect(got.cnf.equals(issuer.publicKey())).toBe(true);

      // Check the expiration and not-before bounds of the other two tokens
      await expect(
        verify(
          Basic.bytes(fromHex(cwtFixtures.expired)),
          issuer.publicKey(),
          fixtureDomain,
          now,
        ),
      ).rejects.toThrow(/already expired/);
      await expect(
        verify(
          NoExp.bytes(fromHex(cwtFixtures.premature)),
          issuer.publicKey(),
          fixtureDomain,
          now,
        ),
      ).rejects.toThrow(/not yet valid/);

      // A tampered token must fail the signature check
      const tampered = valid.slice();
      tampered[tampered.length - 1] ^= 1;
      await expect(
        verify(Basic.bytes(tampered), issuer.publicKey(), fixtureDomain, now),
      ).rejects.toThrow();
    });
  });
});

/** Returns the fields shared by the basic token schemas. */
function basicFields() {
  return {
    sub: claims.subject,
    nbf: claims.notBefore,
    exp: claims.expiration,
    cnf: claims.confirmXdsa,
  };
}
