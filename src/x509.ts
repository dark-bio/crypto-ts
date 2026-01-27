// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/**
 * Parameters for X.509 certificate generation.
 */
export interface Params {
  /** The subject's common name (CN) in the certificate. */
  subjectName: string;
  /** The issuer's common name (CN) in the certificate. */
  issuerName: string;
  /** The certificate validity start time (Unix timestamp in seconds). */
  notBefore: bigint;
  /** The certificate validity end time (Unix timestamp in seconds). */
  notAfter: bigint;
  /** Whether this certificate is a CA certificate (ignored for xHPKE). */
  isCa?: boolean;
  /** Maximum number of intermediate CAs allowed below this one (only if isCa is true, ignored for xHPKE). */
  pathLen?: number;
}

