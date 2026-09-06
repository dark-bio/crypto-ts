// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Resolve the package exports to test the declarations emitted by build:ts.
import { cbor, xdsa, xhpke } from "@darkbio/crypto";

// Removing a constructor from a declaration implies a public, zero-argument
// constructor. Every WASM wrapper must instead retain a private constructor.
// @ts-expect-error Fingerprints must be created from bytes or keys.
new xdsa.Fingerprint();
// @ts-expect-error Signatures must be created from bytes or by signing.
new xdsa.Signature();
// @ts-expect-error Public keys must be imported or derived.
new xdsa.PublicKey();
// @ts-expect-error Secret keys must be imported or generated.
new xdsa.SecretKey();
// @ts-expect-error Fingerprints must be created from bytes or keys.
new xhpke.Fingerprint();
// @ts-expect-error Public keys must be imported or derived.
new xhpke.PublicKey();
// @ts-expect-error Secret keys must be imported or generated.
new xhpke.SecretKey();
// @ts-expect-error Senders must be created by a public key.
new xhpke.Sender();
// @ts-expect-error Receivers must be created by a secret key.
new xhpke.Receiver();

// Public factories and codecs must remain usable with the opaque wrappers.
const message = new Uint8Array([1, 2, 3]);
const domain = new Uint8Array([4, 5, 6]);
const aad = new Uint8Array();
const signer: xdsa.SecretKey = await xdsa.SecretKey.generate();
const verifier: xdsa.PublicKey = signer.publicKey();
const signature: xdsa.Signature = signer.sign(message);
verifier.verify(message, signature);
const fingerprint: xdsa.Fingerprint = verifier.fingerprint();
await cbor.encode(xdsa.fingerprint.value(fingerprint));

const recipient: xhpke.SecretKey = await xhpke.SecretKey.generate();
const publicKey: xhpke.PublicKey = recipient.publicKey();
const { sender, encapKey } = publicKey.newSender(domain);
const receiver: xhpke.Receiver = recipient.newReceiver(encapKey, domain);
receiver.open(sender.seal(message, aad), aad);
await cbor.encode(xhpke.publicKey.value(publicKey));

// The internal factories and WASM handles must stay out of the declarations.
// @ts-expect-error Internal factory is not a public API.
xdsa.PublicKey._fromWasm;
// @ts-expect-error Internal factory is not a public API.
xhpke.Sender._fromWasm;
// @ts-expect-error WASM handles are internal.
signer._wasm;
