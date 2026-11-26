// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/** CBOR serialization for the WASM interface. */

import {
  decode as cborgDecode,
  encodeInto as cborgEncodeInto,
  Token,
  Tokenizer,
  Type,
} from "cborg";
import type { Decodable, Encodable } from "../cbor.js";

/** Decodes text keeping a leading U+FEFF, which a default TextDecoder drops. */
const bomPreservingDecoder = new TextDecoder("utf-8", { ignoreBOM: true });

/** Encodes text into fresh arrays, never into a pool shared with other code. */
const textEncoder = new TextEncoder();

/**
 * Tokenizer that preserves a leading byte order mark in a text string.
 */
class TextTokenizer extends Tokenizer {
  /** Reads the next token, preserving the full text of a string. */
  next(): Token {
    const start = this.pos();
    const token = super.next();
    if (token.type === Type.string) {
      // The header is one byte, plus 1, 2, 4 or 8 length bytes past minor 23
      const minor = this.data[start] & 0x1f;
      const header = minor < 24 ? 1 : 1 + (1 << (minor - 24));
      const text = this.data.subarray(start + header, this.pos());
      if (text[0] === 0xef && text[1] === 0xbb && text[2] === 0xbf) {
        token.value = bomPreservingDecoder.decode(text);
      }
    }
    return token;
  }
}

/**
 * Decodes validated CBOR with maps as `Map` and byte strings as copies.
 *
 * @internal
 */
export function parse(data: Uint8Array): unknown {
  // cborg copies byte strings out with slice(), which on a Node Buffer
  // returns a view, so decode from a plain view over the same bytes
  const bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);

  // A custom tokenizer does not get cborg's decode defaults, so the one for
  // 64-bit integers is set here explicitly
  const options = {
    allowBigInt: true,
    useMaps: true,
    rejectDuplicateMapKeys: true,
  };
  return cborgDecode(bytes, {
    ...options,
    tokenizer: new TextTokenizer(bytes, options),
  }) as unknown;
}

/**
 * Decodes a WASM result and wipes its temporary JavaScript buffer.
 *
 * @internal
 */
export function decodePayload<T>(envelope: Decodable<T>, bytes: Uint8Array): T {
  try {
    return envelope.codec.decode(parse(bytes));
  } finally {
    bytes.fill(0);
  }
}

/**
 * Reports whether a string is well-formed UTF-16. A lone surrogate has no
 * UTF-8 form, and encoding it would silently turn it into U+FFFD.
 */
function isWellFormed(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return false;
      }
      i++;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/**
 * Serializes a value to CBOR for validation in WASM.
 *
 * The result owns its buffer. Temporary text encodings and scratch buffers
 * are cleared after use.
 *
 * @internal
 */
export function serialize<T>(item: Encodable<T>): Uint8Array {
  const value = item.codec.encode(item.value);

  // Keep encoded text outside Node's shared buffer pool
  const texts: Uint8Array[] = [];
  const options = {
    typeEncoders: {
      string: (text: string) => {
        if (!isWellFormed(text)) {
          throw new Error("text is not well-formed, it holds a lone surrogate");
        }
        const token = new Token(Type.string, text);
        token.encodedBytes = textEncoder.encode(text);
        texts.push(token.encodedBytes);
        return token;
      },
    },
  };

  // Grow a private scratch buffer until the encoded value fits
  try {
    for (let size = 256; ; size *= 2) {
      const scratch = new Uint8Array(size);
      try {
        const { written } = cborgEncodeInto(value, scratch, options);
        return scratch.slice(0, written);
      } catch (err) {
        if (
          !(err instanceof Error) ||
          !err.message.includes("destination buffer is too small")
        ) {
          throw err;
        }
      } finally {
        scratch.fill(0);
      }
    }
  } finally {
    for (const text of texts) {
      text.fill(0);
    }
  }
}

/**
 * Serializes a value for a single call and wipes the temporary buffer afterwards.
 *
 * @internal
 */
export function withSerialized<T, R>(
  item: Encodable<T>,
  run: (bytes: Uint8Array) => R,
): R {
  const bytes = serialize(item);
  try {
    return run(bytes);
  } finally {
    bytes.fill(0);
  }
}
