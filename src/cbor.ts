// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/**
 * Typed codecs over the restricted CBOR type system used across the darkbio
 * ecosystem, the counterpart of a Rust type deriving `Cbor`. cborg stays the
 * byte codec; the canonical form of every byte crossing the WASM boundary is
 * checked by the Rust validator.
 *
 * @example
 * ```ts
 * import { cbor, xdsa } from "@darkbio/crypto";
 *
 * const Hello = cbor.tuple(xdsa.publicKey, cbor.bytes);
 * const bytes = await cbor.encode(Hello.value([key, nonce]));
 * const [gotKey, gotNonce] = await cbor.decode(Hello.bytes(bytes));
 * ```
 *
 * @module
 */

import { encode as cborgEncode, decode as cborgDecode } from "cborg";
import { cbor_verify } from "./wasm/darkbio_crypto_wasm.js";
import { ensureInit } from "./init.js";
import { U64_MAX } from "./limits.js";

/** A value bound to the codec that encodes it. */
export interface Encodable<T> {
  readonly codec: Codec<T>;
  readonly value: T;
}

/** Bytes bound to the codec that decodes them. */
export interface Decodable<T> {
  readonly codec: Codec<T>;
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
  readonly key: number;
  readonly codec: Codec<T>;
  readonly required: true;
}

/** An optional field of a map, absent from the map when undefined. */
export interface OptionalField<T> {
  readonly key: number;
  readonly codec: Codec<T>;
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

/** The value types of a tuple codec's items. */
export type Codecs<T extends unknown[]> = { [I in keyof T]: Codec<T[I]> };

/**
 * A value of the wrong shape for a codec. The path names where in the value
 * the mismatch is, array items as `[i]` and map fields as `.name`, empty at
 * the top.
 */
export class CodecError extends Error {
  readonly reason: string;
  readonly path: string;

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
 * Builds a codec from its two directions, the bindings coming for free.
 *
 * @param encode - Converts a value into what cborg encodes
 * @param decode - Converts what cborg decoded into a value
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

/** Null, the value of `Option<T>::None` and of a CWT's authenticated data. */
export const nil: Codec<null> = primitive(
  (value): value is null => value === null,
  "not null",
);

/** A UTF-8 text string. */
export const text: Codec<string> = primitive(
  (value): value is string => typeof value === "string",
  "not text",
);

/** A byte string. */
export const bytes: Codec<Uint8Array> = primitive(
  (value): value is Uint8Array => value instanceof Uint8Array,
  "not bytes",
);

/** Anything, passed through as cborg decoded it, the counterpart of `cbor::Raw`. */
export const raw: Codec<unknown> = codec(
  (value) => value,
  (value) => value,
);

/** An unsigned 64 bit integer. */
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

/** A signed 64 bit integer. */
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

/** An array of any length of one kind of item, the counterpart of `Array<T>`. */
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

/** Declares a required map field. */
export function field<T>(key: number, codec: Codec<T>): Field<T> {
  if (!Number.isSafeInteger(key)) {
    throw new CodecError("map key is not an integer");
  }
  return { key, codec, required: true };
}

/**
 * Declares a map field that may be absent, the counterpart of an
 * `Option<T>` field, absent when undefined.
 */
export function optional<T>(field: Field<T>): OptionalField<T> {
  return { key: field.key, codec: field.codec, required: false };
}

/**
 * An integer keyed map with exactly the declared fields, the counterpart of
 * a struct with `#[cbor(key = N)]` fields. Both ways, a field the map does
 * not declare and a required field missing are refused, as is a key that is
 * not an integer. Only own properties of a value count as its fields.
 */
export function map<F extends Fields>(fields: F): Codec<Values<F>> {
  const entries = Object.entries(fields);
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
        if (!Object.hasOwn(fields, name)) {
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
      const decoded: Record<string, unknown> = {};
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
        decoded[name] = within(`.${name}`, () =>
          field.codec.decode((value as Map<unknown, unknown>).get(field.key)),
        );
      }
      return decoded as Values<F>;
    },
  );
}

/**
 * Encodes a value bound to its codec into canonical CBOR, the bytes checked
 * by the Rust validator before they are returned.
 *
 * @param item - The value and the codec to encode it with
 * @throws CodecError on a value of the wrong shape
 */
export async function encode<T>(item: Encodable<T>): Promise<Uint8Array> {
  const data = cborgEncode(item.codec.encode(item.value));
  await ensureInit();
  cbor_verify(data);
  return data;
}

/**
 * Decodes canonical CBOR bound to its codec, the bytes checked by the Rust
 * validator before anything is decoded.
 *
 * @param item - The bytes and the codec to decode them with
 * @throws CodecError on bytes of the wrong shape
 */
export async function decode<T>(item: Decodable<T>): Promise<T> {
  await ensureInit();
  cbor_verify(item.bytes);
  return item.codec.decode(parse(item.bytes));
}

/**
 * Decodes bytes the Rust validator already checked into what cborg makes of
 * them, maps as `Map`.
 *
 * @internal
 */
export function parse(data: Uint8Array): unknown {
  return cborgDecode(data, {
    useMaps: true,
    rejectDuplicateMapKeys: true,
  }) as unknown;
}

/**
 * Serializes a value bound to its codec into the bytes the WASM boundary
 * takes, canonical by cborg's ordering and verified again on the Rust side.
 *
 * @internal
 */
export function serialize<T>(item: Encodable<T>): Uint8Array {
  return cborgEncode(item.codec.encode(item.value));
}

/**
 * Verify that data is valid CBOR under the restricted deterministic type
 * system used across the darkbio ecosystem (booleans, null, 64-bit integers,
 * text strings, byte strings, arrays, and integer-keyed maps).
 *
 * The COSE and CWT functions run this check internally on every payload they
 * sign, embed or hand back; use it directly to pre-check hand-rolled
 * encodings.
 *
 * @param data - The CBOR bytes to validate
 * @throws If the data is not valid restricted CBOR
 */
export async function verify(data: Uint8Array): Promise<void> {
  await ensureInit();
  cbor_verify(data);
}
