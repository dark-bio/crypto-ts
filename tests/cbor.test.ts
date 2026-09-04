// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import { describe, it, expect } from "vitest";
import { encode as cborgEncode } from "cborg";
import * as cbor from "../src/cbor.js";
import { CodecError } from "../src/cbor.js";

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Runs a codec both ways through the bytes, checking the value comes back.
async function roundtrip<T>(codec: cbor.Codec<T>, value: T): Promise<T> {
  const bytes = await cbor.encode(codec.value(value));
  return cbor.decode(codec.bytes(bytes));
}

describe("cbor", () => {
  describe("verify", () => {
    it("accepts restricted deterministic CBOR", async () => {
      const data = cborgEncode(
        new Map<number, unknown>([
          [1, "hello"],
          [2, new Uint8Array([1, 2, 3])],
        ]),
      );
      await expect(cbor.verify(data)).resolves.toBeUndefined();
    });

    it("rejects types outside the restricted system", async () => {
      await expect(cbor.verify(cborgEncode(1.5))).rejects.toThrow();
    });
  });

  describe("primitives", () => {
    it("roundtrips every primitive", async () => {
      expect(await roundtrip(cbor.bool, true)).toBe(true);
      expect(await roundtrip(cbor.bool, false)).toBe(false);
      expect(await roundtrip(cbor.nil, null)).toBe(null);
      expect(await roundtrip(cbor.text, "héllo")).toBe("héllo");
      expect(
        toHex(await roundtrip(cbor.bytes, new Uint8Array([0, 1, 2]))),
      ).toBe("000102");
      expect(await roundtrip(cbor.uint, 0n)).toBe(0n);
      expect(await roundtrip(cbor.uint, (1n << 64n) - 1n)).toBe(
        (1n << 64n) - 1n,
      );
      expect(await roundtrip(cbor.int, -(1n << 63n))).toBe(-(1n << 63n));
      expect(await roundtrip(cbor.int, (1n << 63n) - 1n)).toBe(
        (1n << 63n) - 1n,
      );
    });

    it("passes anything through raw", async () => {
      const value = await roundtrip(cbor.raw, [1, "two", new Map([[3, null]])]);
      expect(value).toEqual([1, "two", new Map([[3, null]])]);
    });

    it("refuses values outside a primitive", () => {
      expect(() => cbor.bool.encode(1 as unknown as boolean)).toThrow(
        CodecError,
      );
      expect(() => cbor.nil.encode(undefined as unknown as null)).toThrow(
        CodecError,
      );
      expect(() => cbor.text.encode(5 as unknown as string)).toThrow(
        CodecError,
      );
      expect(() => cbor.bytes.encode("x" as unknown as Uint8Array)).toThrow(
        CodecError,
      );
      expect(() => cbor.uint.encode(-1n)).toThrow(CodecError);
      expect(() => cbor.uint.encode(1n << 64n)).toThrow(CodecError);
      expect(() => cbor.uint.encode(5 as unknown as bigint)).toThrow(
        CodecError,
      );
      expect(() => cbor.int.encode(1n << 63n)).toThrow(CodecError);
      expect(() => cbor.int.encode(-(1n << 63n) - 1n)).toThrow(CodecError);

      expect(() => cbor.bool.decode(0)).toThrow(CodecError);
      expect(() => cbor.nil.decode(undefined)).toThrow(CodecError);
      expect(() => cbor.text.decode(new Uint8Array(1))).toThrow(CodecError);
      expect(() => cbor.bytes.decode("x")).toThrow(CodecError);
      expect(() => cbor.uint.decode(-1)).toThrow(CodecError);
      expect(() => cbor.uint.decode(1.5)).toThrow(CodecError);
      expect(() => cbor.uint.decode("1")).toThrow(CodecError);
      expect(() => cbor.uint.decode(1n << 64n)).toThrow(CodecError);
      expect(() => cbor.int.decode(1n << 63n)).toThrow(CodecError);
    });

    it("encodes integers minimally from either representation", async () => {
      expect(toHex(await cbor.encode(cbor.uint.value(5n)))).toBe("05");
      expect(toHex(await cbor.encode(cbor.uint.value(256n)))).toBe("190100");
      expect(toHex(await cbor.encode(cbor.uint.value((1n << 64n) - 1n)))).toBe(
        "1bffffffffffffffff",
      );
      expect(toHex(await cbor.encode(cbor.int.value(-1n)))).toBe("20");
      expect(toHex(await cbor.encode(cbor.int.value(-(1n << 63n))))).toBe(
        "3b7fffffffffffffff",
      );
      expect(cbor.uint.decode(5)).toBe(5n);
      expect(cbor.uint.decode(5n)).toBe(5n);
    });
  });

  describe("composites", () => {
    it("roundtrips nullable values", async () => {
      const codec = cbor.nullable(cbor.text);
      expect(await roundtrip(codec, "x")).toBe("x");
      expect(await roundtrip(codec, null)).toBe(null);
      expect(() => codec.decode(5)).toThrow(CodecError);
    });

    it("roundtrips arrays and tuples", async () => {
      const list = cbor.array(cbor.uint);
      expect(await roundtrip(list, [])).toEqual([]);
      expect(await roundtrip(list, [1n, 2n, 3n])).toEqual([1n, 2n, 3n]);
      expect(() => list.decode([1, "x"])).toThrow(CodecError);

      const pair = cbor.tuple(cbor.text, cbor.uint);
      expect(await roundtrip(pair, ["login", 123n])).toEqual(["login", 123n]);
      expect(() => pair.decode(["login"])).toThrow(CodecError);
      expect(() => pair.decode(["login", 123, 4])).toThrow(CodecError);
      expect(() =>
        pair.encode(["login"] as unknown as [string, bigint]),
      ).toThrow(CodecError);
    });

    it("roundtrips enumerations", async () => {
      const codec = cbor.enumeration<number>([1, 2, 5]);
      expect(await roundtrip(codec, 5)).toBe(5);
      expect(() => codec.decode(3)).toThrow(CodecError);
      expect(() => codec.decode(5n)).toThrow(CodecError);
      expect(() => codec.encode(3)).toThrow(CodecError);
    });

    it("roundtrips maps with exactly the declared keys", async () => {
      const codec = cbor.map({
        name: cbor.field(1, cbor.text),
        count: cbor.optional(cbor.field(2, cbor.uint)),
      });
      expect(await roundtrip(codec, { name: "a", count: 3n })).toEqual({
        name: "a",
        count: 3n,
      });
      expect(await roundtrip(codec, { name: "a" })).toEqual({ name: "a" });

      expect(() =>
        codec.decode(
          new Map([
            [1, "a"],
            [3, "x"],
          ]),
        ),
      ).toThrow("unexpected key 3");
      expect(() => codec.decode(new Map([[2, 3]]))).toThrow("missing key 1");
      expect(() => codec.decode(new Map([["1", "a"]]))).toThrow(
        "map key is not an integer",
      );
      expect(() => codec.decode([1, "a"])).toThrow("not a map");
      expect(() =>
        codec.encode({ count: 3n } as unknown as { name: string }),
      ).toThrow("missing field name");
      expect(() =>
        cbor.map({ a: cbor.field(1, cbor.text), b: cbor.field(1, cbor.text) }),
      ).toThrow("declared twice");
      expect(() => cbor.field(1.5, cbor.text)).toThrow(CodecError);
    });

    it("names the path of a mismatch", () => {
      const codec = cbor.tuple(
        cbor.text,
        cbor.map({ inner: cbor.field(1, cbor.array(cbor.uint)) }),
      );
      let caught: unknown;
      try {
        codec.decode(["a", new Map([[1, [1, "x"]]])]);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(CodecError);
      expect((caught as CodecError).path).toBe("[1].inner[1]");
      expect((caught as CodecError).message).toBe(
        "not an unsigned 64 bit integer at [1].inner[1]",
      );
    });
  });

  describe("bytes", () => {
    it("encodes maps canonically", async () => {
      const codec = cbor.map({
        b: cbor.field(2, cbor.text),
        a: cbor.field(1, cbor.text),
      });
      const bytes = await cbor.encode(codec.value({ b: "y", a: "x" }));
      expect(toHex(bytes)).toBe("a2016178026179");
    });

    it("refuses non-canonical bytes", async () => {
      const duplicate = new Uint8Array([0xa2, 0x01, 0x01, 0x01, 0x02]);
      await expect(cbor.decode(cbor.raw.bytes(duplicate))).rejects.toThrow();
      const misordered = new Uint8Array([0xa2, 0x02, 0x02, 0x01, 0x01]);
      await expect(cbor.decode(cbor.raw.bytes(misordered))).rejects.toThrow();
    });

    it("has the encoded null", () => {
      expect(toHex(cbor.NULL)).toBe("f6");
    });
  });
});
