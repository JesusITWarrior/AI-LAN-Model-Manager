import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";

import type { TransportParsedCertificate } from "@lan-model-manager/core";

/**
 * Native Node.js ECDSA P-256 (secp256r1) signer/verifier.
 *
 * Signatures are DER-encoded (as produced by `crypto.sign`/`crypto.verify` with
 * an ECDSA key and a SHA-256 digest). Go's `ecdsa.SignASN1`/`VerifyASN1`
 * produce byte-for-byte identical DER, so the controller and the Go agent sign
 * and verify each other's envelopes directly. This is the interop contract.
 */
export interface TransportNativeSigner {
  readonly algorithm: "ecdsa-p256-sha256";
  readonly certificate: TransportParsedCertificate;
  /** Sign a canonical field string; returns the hex-encoded DER signature. */
  sign(message: string): string;
}
export interface TransportNativeVerifier {
  readonly algorithm: "ecdsa-p256-sha256";
  readonly certificate: TransportParsedCertificate;
  /** Verify a hex-encoded DER signature over a canonical field string. */
  verify(message: string, signatureHex: string): boolean;
}

const DER_SIGNATURE_MIN = 70; // minimal ECDSA P-256 DER signatures are ~70 bytes
const DER_SIGNATURE_MAX = 720; // generous upper bound for any single signature

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}
// Accept either a Node Buffer or a raw Uint8Array.
function hexOf(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}
function fromHex(value: string): Uint8Array | null {
  if (!/^[a-fA-F0-9]+$/.test(value) || value.length % 2 !== 0) return null;
  return Buffer.from(value, "hex") as Uint8Array;
}

/**
 * Build a signer from a PEM private key and a parsed leaf certificate.
 * Non-throwing: invalid input or key material yields `{ ok: false }`.
 */
export function buildTransportNativeSigner(
  pemKey: string,
  certificate: TransportParsedCertificate,
): { readonly ok: true; readonly value: TransportNativeSigner } | { readonly ok: false; readonly detail: string } {
  let key: KeyObject;
  try {
    key = createPrivateKey({ key: pemKey, format: "pem" });
  } catch {
    return { ok: false, detail: "bad_private_key" };
  }
  // Sanity-check key usage without retaining an intermediate signer.
  try {
    sign("sha256", Buffer.from(""), key);
  } catch {
    return { ok: false, detail: "bad_private_key" };
  }
  return {
    ok: true,
    value: {
      algorithm: "ecdsa-p256-sha256",
      certificate,
      sign(message: string): string {
        const raw = sign("sha256", Buffer.from(message), key);
        return toHex(Buffer.from(raw));
      },
    },
  };
}

/**
 * Build a verifier from a PEM public key (SPKI) and a parsed leaf certificate.
 * Non-throwing: invalid input yields `{ ok: false }`.
 */
export function buildTransportNativeVerifier(
  pemPublic: string,
  certificate: TransportParsedCertificate,
): { readonly ok: true; readonly value: TransportNativeVerifier } | { readonly ok: false; readonly detail: string } {
  let publicKey: KeyObject;
  try {
    publicKey = createPublicKey({ key: pemPublic, format: "pem" });
  } catch {
    return { ok: false, detail: "bad_public_key" };
  }
  const isECDSA = publicKey.asymmetricKeyType === "ec";
  if (!isECDSA) return { ok: false, detail: "not_ecdsa" };
  return {
    ok: true,
    value: {
      algorithm: "ecdsa-p256-sha256",
      certificate,
      verify(message: string, signatureHex: string): boolean {
        const raw = fromHex(signatureHex) ?? Buffer.from([]);
        if (raw.length < DER_SIGNATURE_MIN || raw.length > DER_SIGNATURE_MAX) return false;
        try {
          return verify("sha256", Buffer.from(message), publicKey, raw);
        } catch {
          return false;
        }
      },
    },
  };
}

/** Generate an ephemeral ECDSA P-256 key pair for tests/fixtures (Node crypto). */
export function generateTransportNativeKeyPair(): { readonly keyPem: string; readonly publicPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return {
    keyPem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    publicPem: publicKey.export({ type: "spki", format: "pem" }) as string,
  };
}
