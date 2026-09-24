// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/**
 * Post-quantum cryptography for the Dark Bio ecosystem, the Rust library
 * compiled to WASM behind a typed API.
 *
 * Signatures come from `xdsa`, encryption from `xhpke`, and `cose` wraps both
 * into COSE envelopes using the Dark Bio wire profile. Payloads and
 * authenticated messages are bound to a `cbor` codec, which declares their
 * shape. The WASM module loads on the first call of any async function, so
 * there is no separate setup step.
 *
 * @module
 */

/** Random bytes from the runtime's secure random source. */
export * as rand from "./rand.js";
/** HKDF-SHA256 key derivation. */
export * as hkdf from "./hkdf.js";
/** Argon2id key derivation from passwords. */
export * as argon2 from "./argon2.js";
/** Typed codecs over the restricted CBOR type system. */
export * as cbor from "./cbor.js";
/** Composite ML-DSA-65 + Ed25519 digital signatures. */
export * as xdsa from "./xdsa.js";
/** X-Wing HPKE encryption. */
export * as xhpke from "./xhpke.js";
/** COSE signing and encryption with xDSA and xHPKE. */
export * as cose from "./cose.js";
/** CBOR Web Tokens on top of COSE Sign1. */
export * as cwt from "./cwt.js";
