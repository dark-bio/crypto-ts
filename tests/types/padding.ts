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
const none: cose.Padding = cose.Padding.none();
/** Explicit bucket policy. */
const buckets: cose.Padding = cose.Padding.buckets({ floor: 8192, step: 20 });

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
cose.Padding.buckets({ floor: 8192 });
// @ts-expect-error Bucket parameters must be named.
cose.Padding.buckets(8192, 20);
// @ts-expect-error Bucket parameters are numbers.
cose.Padding.buckets({ floor: 8192n, step: 20 });
// @ts-expect-error Padding must be created through a static constructor.
new cose.Padding();
// @ts-expect-error Padding must be created through a static constructor.
new cose.Padding(() => {
  throw new Error();
});
// @ts-expect-error Object literals are not padding instances.
const oldNone: cose.Padding = { name: "none" };
// @ts-expect-error Object literals are not padding instances.
const oldBuckets: cose.Padding = { name: "buckets", floor: 8192, step: 20 };
const object = { name: "none" } as const;
// @ts-expect-error Padding remains opaque in the published declarations.
const structural: cose.Padding = object;
// @ts-expect-error Policy factory stays private.
none.build;
// @ts-expect-error Policy conversion stays internal.
none._toWasm;
// @ts-expect-error Padding has no public discriminant.
none.name;
// @ts-expect-error Padding has no public bucket parameters.
buckets.floor;
// @ts-expect-error Padding has no public bucket parameters.
buckets.step;
