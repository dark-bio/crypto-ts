// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/**
 * Typed codecs over the restricted CBOR type system used across Dark Bio.
 *
 * https://datatracker.ietf.org/doc/html/rfc8949
 *
 * Only a minimal subset of CBOR is supported: booleans, null, 64-bit
 * integers, text strings, byte strings, arrays and maps with integer keys. The
 * encoding is deterministic (RFC 8949 Section 4.2.1). Integers take their
 * shortest form, map keys are sorted by their encoded bytes, and there are no
 * indefinite lengths, floats or tags.
 *
 * A codec declares the shape of a value the way a Rust type deriving `Cbor`
 * does. Values are bound to their codec before they are encoded, and bytes
 * before they are decoded. The `cose` and `cwt` functions take them the same
 * way. {@link encode} and {@link decode} reject any encoding that breaks the
 * rules above. The cborg library handles the bytes, so a codec converts to and
 * from what cborg takes, such as a `Map` for a map.
 *
 * @example
 * ```ts
 * import { cbor } from "@darkbio/crypto";
 *
 * const Triple = cbor.tuple(cbor.uint, cbor.text, cbor.bytes);
 * const bytes = await cbor.encode(Triple.value([1n, "two", new Uint8Array([3])]));
 * // bytes holds 83 01 63 74 77 6f 41 03 in hex
 *
 * const [a, b, c] = await cbor.decode(Triple.bytes(bytes));
 * console.log(a, b, c); // 1n two Uint8Array(1) [ 3 ]
 * ```
 *
 * @module
 */

import { cbor_verify } from "./wasm/darkbio_crypto_wasm.js";
import { parse, serialize } from "./internal/cborg.js";
import { ensureInit } from "./internal/init.js";
import { U64_MAX } from "./internal/limits.js";

/** A value bound to the codec that encodes it. */
export interface Encodable<T> {
  /** The codec that encodes the value. */
  readonly codec: Codec<T>;
  /** The value to encode. */
  readonly value: T;
}

/** Bytes bound to the codec that decodes them. */
export interface Decodable<T> {
  /** The codec that decodes the bytes. */
  readonly codec: Codec<T>;
  /** The CBOR bytes to decode. */
  readonly bytes: Uint8Array;
}

/**
 * A codec between a value of type T and the representation cborg encodes and
 * decodes. Both directions throw a {@link CodecError} on a value of the wrong
 * shape.
 */
export interface Codec<T> {
  /** Converts a value into what cborg encodes, checking its shape. */
  encode(value: T): unknown;
  /** Converts what cborg decoded into a value, checking its shape. */
  decode(value: unknown): T;
  /** Binds a value to this codec for encoding. */
  value(value: T): Encodable<T>;
  /** Binds bytes to this codec for decoding. */
  bytes(data: Uint8Array): Decodable<T>;
}

/** A required field of a map, a codec at an integer key. */
export interface Field<T> {
  /** The integer key of the field in the map. */
  readonly key: number;
  /** The codec of the field's value. */
  readonly codec: Codec<T>;
  /** Marks the field as required. */
  readonly required: true;
}

/** An optional field of a map, absent from the map when undefined. */
export interface OptionalField<T> {
  /** The integer key of the field in the map. */
  readonly key: number;
  /** The codec of the field's value. */
  readonly codec: Codec<T>;
  /** Marks the field as optional. */
  readonly required: false;
}

/** The fields of a map codec, by name. */
export type Fields = Record<string, Field<unknown> | OptionalField<unknown>>;

/** The value type of a map codec, required fields present and optional ones optional. */
export type Values<F extends Fields> = {
  [K in keyof F as F[K] extends Field<unknown> ? K : never]: F[K] extends Field<
    infer T
  >
    ? T
    : never;
} & {
  [
    K in keyof F as F[K] extends OptionalField<unknown> ? K : never
  ]?: F[K] extends OptionalField<infer T> ? T : never;
};

/** The item codecs of a tuple codec, one per position of the value types. */
export type Codecs<T extends unknown[]> = { [I in keyof T]: Codec<T[I]> };

/**
 * A value of the wrong shape for a codec. The path names where in the value
 * the mismatch is, array items as `[i]` and map fields as `.name`, empty at
 * the top.
 */
export class CodecError extends Error {
  /** What is wrong with the value. */
  readonly reason: string;
  /** Where in the value the mismatch is, empty at the top. */
  readonly path: string;

  /**
   * Creates an error for a value of the wrong shape.
   *
   * @param reason - What is wrong with the value
   * @param path - Where in the value the mismatch is, empty at the top
   */
  constructor(reason: string, path = "") {
    super(path === "" ? reason : `${reason} at ${path}`);
    this.name = "CodecError";
    this.reason = reason;
    this.path = path;
  }
}

/** Runs a step of a codec, prefixing the path of a failure inside it. */
function within<T>(segment: string, run: () => T): T {
  try {
    return run();
  } catch (err) {
    if (err instanceof CodecError) {
      throw new CodecError(err.reason, segment + err.path);
    }
    throw err;
  }
}

/**
 * Builds a codec from its two directions, adding the value and bytes bindings.
 * Both directions should throw a {@link CodecError} on a value of the wrong
 * shape.
 *
 * @example
 * ```ts
 * import { cbor } from "@darkbio/crypto";
 *
 * // A date carried as whole seconds since the Unix epoch
 * const date = cbor.codec<Date>(
 *   (value) => cbor.uint.encode(BigInt(Math.floor(value.getTime() / 1000))),
 *   (value) => new Date(Number(cbor.uint.decode(value)) * 1000),
 * );
 * const bytes = await cbor.encode(date.value(new Date("2026-01-01T00:00:00Z")));
 * console.log(await cbor.decode(date.bytes(bytes))); // 2026-01-01T00:00:00.000Z
 * ```
 *
 * @param encode - Converts a value into what cborg encodes
 * @param decode - Converts what cborg decoded into a value
 * @returns The codec
 */
export function codec<T>(
  encode: (value: T) => unknown,
  decode: (value: unknown) => T,
): Codec<T> {
  const self: Codec<T> = {
    encode,
    decode,
    value: (value) => ({ codec: self, value }),
    bytes: (data) => ({ codec: self, bytes: data }),
  };
  return self;
}

/** Builds a codec whose two directions share one check. */
function primitive<T>(
  check: (value: unknown) => value is T,
  reason: string,
): Codec<T> {
  const guard = (value: unknown): T => {
    if (!check(value)) {
      throw new CodecError(reason);
    }
    return value;
  };
  return codec(guard, guard);
}

const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;

/** Reads an integer cborg produced, a number within the safe range or a bigint beyond it. */
function integer(value: unknown, reason: string): bigint {
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    return BigInt(value);
  }
  if (typeof value === "bigint") {
    return value;
  }
  throw new CodecError(reason);
}

/** A boolean. */
export const bool: Codec<boolean> = primitive(
  (value): value is boolean => typeof value === "boolean",
  "not a boolean",
);

/** Null, the counterpart of Rust's `cbor::Null` and of a `None` option. */
export const nil: Codec<null> = primitive(
  (value): value is null => value === null,
  "not null",
);

/**
 * A UTF-8 text string. Decoding keeps every character, a leading U+FEFF
 * included. Encoding rejects a string with a lone surrogate, since it has no
 * UTF-8 form.
 */
export const text: Codec<string> = primitive(
  (value): value is string => typeof value === "string",
  "not text",
);

/** A byte string. */
export const bytes: Codec<Uint8Array> = primitive(
  (value): value is Uint8Array => value instanceof Uint8Array,
  "not bytes",
);

/**
 * Anything, passed through as cborg decoded it, the counterpart of
 * `cbor::Raw`. The value is not checked against any shape, but {@link encode}
 * and {@link decode} still check its encoding.
 */
export const raw: Codec<unknown> = codec(
  (value) => value,
  (value) => value,
);

/** An unsigned 64-bit integer, a bigint in both directions. */
export const uint: Codec<bigint> = codec(
  (value) => {
    if (typeof value !== "bigint" || value < 0n || value > U64_MAX) {
      throw new CodecError("not an unsigned 64 bit integer");
    }
    return value;
  },
  (value) => {
    const parsed = integer(value, "not an unsigned 64 bit integer");
    if (parsed < 0n || parsed > U64_MAX) {
      throw new CodecError("not an unsigned 64 bit integer");
    }
    return parsed;
  },
);

/** A signed 64-bit integer, a bigint in both directions. */
export const int: Codec<bigint> = codec(
  (value) => {
    if (typeof value !== "bigint" || value < I64_MIN || value > I64_MAX) {
      throw new CodecError("not a signed 64 bit integer");
    }
    return value;
  },
  (value) => {
    const parsed = integer(value, "not a signed 64 bit integer");
    if (parsed < I64_MIN || parsed > I64_MAX) {
      throw new CodecError("not a signed 64 bit integer");
    }
    return parsed;
  },
);

/**
 * A value or null, the counterpart of `Option<T>` in an array or as a
 * nullable map field.
 *
 * @param item - The codec of the value when it is not null
 * @returns The codec
 */
export function nullable<T>(item: Codec<T>): Codec<T | null> {
  return codec(
    (value) => (value === null ? null : item.encode(value)),
    (value) => (value === null ? null : item.decode(value)),
  );
}

/**
 * A member of a set of small integers, the counterpart of a Rust enum encoded
 * as its discriminant.
 *
 * @param values - The integers the value may take
 * @returns The codec
 */
export function enumeration<E extends number>(values: readonly E[]): Codec<E> {
  const members = new Set<number>(values);
  const guard = (value: unknown): E => {
    if (typeof value !== "number" || !members.has(value)) {
      throw new CodecError("not a member of the enumeration");
    }
    return value as E;
  };
  return codec(guard, guard);
}

/**
 * An array of any length of one kind of item, the counterpart of `Array<T>`.
 *
 * @param item - The codec of every item
 * @returns The codec
 */
export function array<T>(item: Codec<T>): Codec<T[]> {
  return codec(
    (value) => {
      if (!Array.isArray(value)) {
        throw new CodecError("not an array");
      }
      return value.map((element: T, i) =>
        within(`[${i}]`, () => item.encode(element)),
      );
    },
    (value) => {
      if (!Array.isArray(value)) {
        throw new CodecError("not an array");
      }
      return value.map((element: unknown, i) =>
        within(`[${i}]`, () => item.decode(element)),
      );
    },
  );
}

/**
 * An array of a fixed length with an item codec per position, the counterpart
 * of a tuple or a struct with `#[cbor(array)]`.
 *
 * @param items - The codec of each item, in order
 * @returns The codec
 */
export function tuple<T extends unknown[]>(...items: Codecs<T>): Codec<T> {
  const codecs: Codec<unknown>[] = items;
  return codec(
    (value) => {
      if (!Array.isArray(value) || value.length !== codecs.length) {
        throw new CodecError(`not an array of ${codecs.length}`);
      }
      return codecs.map((item, i) =>
        within(`[${i}]`, () => item.encode(value[i])),
      );
    },
    (value) => {
      if (!Array.isArray(value) || value.length !== codecs.length) {
        throw new CodecError(`not an array of ${codecs.length}`);
      }
      return codecs.map((item, i) =>
        within(`[${i}]`, () => item.decode((value as unknown[])[i])),
      ) as T;
    },
  );
}

/**
 * Declares a required map field.
 *
 * @param key - The integer key of the field in the map
 * @param codec - The codec of the field's value
 * @returns The field
 * @throws CodecError if the key is not a safe integer
 */
export function field<T>(key: number, codec: Codec<T>): Field<T> {
  if (!Number.isSafeInteger(key)) {
    throw new CodecError("map key is not an integer");
  }
  return { key, codec, required: true };
}

/**
 * Declares a map field that may be absent, the counterpart of an
 * `Option<T>` field. The field is left out of the map when its value is
 * undefined.
 *
 * @param field - The field to make optional
 * @returns The optional field
 */
export function optional<T>(field: Field<T>): OptionalField<T> {
  return { key: field.key, codec: field.codec, required: false };
}

/**
 * An integer-keyed map with exactly the declared fields, the counterpart of
 * a struct with `#[cbor(key = N)]` fields. Both ways, a field the map does
 * not declare and a required field missing are refused, as is a key that is
 * not an integer. Only own properties of a value count as its fields.
 *
 * @example
 * ```ts
 * import { cbor } from "@darkbio/crypto";
 *
 * const Bar = cbor.map({
 *   x: cbor.field(1, cbor.uint), // required
 *   y: cbor.optional(cbor.field(2, cbor.bytes)), // omitted when undefined
 *   z: cbor.field(3, cbor.nullable(cbor.uint)), // always present, a value or null
 * });
 * const bytes = await cbor.encode(Bar.value({ x: 7n, z: null }));
 * // bytes holds a2 01 07 03 f6 in hex
 *
 * console.log(await cbor.decode(Bar.bytes(bytes))); // { x: 7n, z: null }
 * ```
 *
 * @param fields - The fields of the map, by name
 * @returns The codec
 * @throws CodecError if two fields share a key
 */
export function map<F extends Fields>(fields: F): Codec<Values<F>> {
  const entries = Object.entries(fields).map(
    ([name, field]) => [name, { ...field }] as const,
  );
  const declared = new Set(entries.map(([name]) => name));
  const names = new Map<number, string>();
  for (const [name, field] of entries) {
    if (names.has(field.key)) {
      throw new CodecError(`map key ${field.key} declared twice`);
    }
    names.set(field.key, name);
  }
  return codec(
    (value) => {
      if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new CodecError("not an object");
      }
      const record = value as Record<string, unknown>;
      for (const name of Object.keys(record)) {
        if (!declared.has(name)) {
          throw new CodecError(`unexpected field ${name}`);
        }
      }
      const encoded = new Map<number, unknown>();
      for (const [name, field] of entries) {
        const item = Object.hasOwn(record, name) ? record[name] : undefined;
        if (item === undefined) {
          if (field.required) {
            throw new CodecError(`missing field ${name}`);
          }
          continue;
        }
        encoded.set(
          field.key,
          within(`.${name}`, () => field.codec.encode(item)),
        );
      }
      return encoded;
    },
    (value) => {
      if (!(value instanceof Map)) {
        throw new CodecError("not a map");
      }
      const decoded: [string, unknown][] = [];
      for (const key of (value as Map<unknown, unknown>).keys()) {
        if (typeof key !== "number" || !Number.isSafeInteger(key)) {
          throw new CodecError("map key is not an integer");
        }
        if (!names.has(key)) {
          throw new CodecError(`unexpected key ${key}`);
        }
      }
      for (const [name, field] of entries) {
        if (!(value as Map<unknown, unknown>).has(field.key)) {
          if (field.required) {
            throw new CodecError(`missing key ${field.key}`);
          }
          continue;
        }
        decoded.push([
          name,
          within(`.${name}`, () =>
            field.codec.decode((value as Map<unknown, unknown>).get(field.key)),
          ),
        ]);
      }
      return Object.fromEntries(decoded) as Values<F>;
    },
  );
}

/**
 * Encodes a value bound to its codec into deterministic CBOR.
 *
 * @param item - The value and the codec to encode it with
 * @returns The CBOR bytes
 * @throws CodecError on a value of the wrong shape
 * @throws If the encoding falls outside the restricted type system, such as a
 *   float in a raw value or text with a lone surrogate
 */
export async function encode<T>(item: Encodable<T>): Promise<Uint8Array> {
  const data = serialize(item);
  await ensureInit();
  cbor_verify(data);
  return data;
}

/**
 * Decodes deterministic CBOR bound to its codec. The bytes must pass
 * {@link verify} before anything is decoded.
 *
 * @param item - The bytes and the codec to decode them with
 * @returns The decoded value
 * @throws If the bytes are not valid restricted CBOR
 * @throws CodecError on bytes of the wrong shape
 */
export async function decode<T>(item: Decodable<T>): Promise<T> {
  await ensureInit();
  cbor_verify(item.bytes);
  return item.codec.decode(parse(item.bytes));
}

/**
 * Verifies that data is exactly one complete CBOR item under the restricted
 * type system.
 *
 * It checks UTF-8 text, deterministic integer and length encodings, integer
 * map keys in order without duplicates, and the nesting limit. It does not
 * check application-specific schemas or values. The `cose` and `cwt`
 * functions apply the same check to every payload they sign, embed or return.
 *
 * @param data - The CBOR bytes to validate
 * @throws If the data is not valid restricted CBOR
 */
export async function verify(data: Uint8Array): Promise<void> {
  await ensureInit();
  cbor_verify(data);
}
