// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/** Checks padding policies and argument order through the published declarations. */

import { cbor, cose, xdsa, xhpke } from "@darkbio/crypto";

/** Signing identity for the declaration checks. */
const signer = await xdsa.SecretKey.generate();
/** Receiving identity for the declaration checks. */
const recipient = await xhpke.SecretKey.generate();
/** Application domain for the declaration checks. */
const domain = new Uint8Array();
/** Payload and authenticated message for the declaration checks. */
const message = cbor.text.value("padding");
/** Explicit no-padding policy. */
const none: cose.Padding = { name: "none" };
/** Explicit bucket policy. */
const buckets: cose.Padding = { name: "buckets", floor: 8192, step: 20 };

await cose.seal(message, message, signer, recipient.publicKey(), domain, none);
await cose.encrypt(
  new Uint8Array(),
  message,
  recipient.publicKey(),
  domain,
  buckets,
);

// Opening keeps its signature without a padding argument
await cose.open(
  cbor.text.bytes(new Uint8Array()),
  message,
  recipient,
  signer.publicKey(),
  domain,
);
await cose.decrypt(new Uint8Array(), message, recipient, domain);

// @ts-expect-error A sender must choose a padding policy.
await cose.seal(message, message, signer, recipient.publicKey(), domain);
// @ts-expect-error Re-encryption also requires a padding policy.
await cose.encrypt(new Uint8Array(), message, recipient.publicKey(), domain);
// @ts-expect-error Buckets require both floor and step.
const incomplete: cose.Padding = { name: "buckets", floor: 8192 };
// @ts-expect-error The policy name is a discriminant.
const unknown: cose.Padding = { name: "unknown" };
// @ts-expect-error Bucket parameters are numbers.
const wrongType: cose.Padding = { name: "buckets", floor: 8192n, step: 20 };
// @ts-expect-error Padding arithmetic stays internal.
cose.paddedSize;
