// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/** Checks explicit times and decoded payload types in the published declarations. */

import { cbor, cose, cwt, xdsa, xhpke } from "@darkbio/crypto";

declare const time: number | bigint;
declare const signer: xdsa.SecretKey;
declare const recipient: xhpke.SecretKey;
declare const domain: Uint8Array;

// Use the same timestamp type for all three COSE envelope forms
const verifier = signer.publicKey();
const message = cbor.text.value("payload");
const auth = cbor.nil.value(null);
const signed: Uint8Array = await cose.signAt(
  message,
  auth,
  signer,
  domain,
  time,
);
const embedded: string = await cose.verifyAt(
  cbor.text.bytes(signed),
  auth,
  verifier,
  domain,
  0,
  time,
);
const detached: Uint8Array = await cose.signDetachedAt(
  auth,
  signer,
  domain,
  time,
);
const verified: void = await cose.verifyDetachedAt(
  detached,
  auth,
  verifier,
  domain,
  undefined,
  time,
);
const sealed: Uint8Array = await cose.sealAt(
  message,
  auth,
  signer,
  recipient.publicKey(),
  domain,
  cose.Padding.none(),
  time,
);
const opened: string = await cose.openAt(
  cbor.text.bytes(sealed),
  auth,
  recipient,
  verifier,
  domain,
  0,
  time,
);

// The COSE timestamp is independent of the claim schema
const claims = cbor.map({ sub: cwt.claims.subject }).value({ sub: "device" });
const token: Uint8Array = await cwt.issueAt(claims, signer, domain, time);

// @ts-expect-error The reference time is required even without a drift check.
await cose.verifyAt(cbor.text.bytes(signed), auth, verifier, domain, undefined);
// @ts-expect-error A timestamp must be a number or bigint.
await cwt.issueAt(claims, signer, domain, "0");
