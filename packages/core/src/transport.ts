/**
 * Transport-layer abstractions: HTTPS/mTLS policy, versioned negotiation,
 * certificate identity/revocation status lookup, per-certificate replay
 * protection, and hard request/header/body/time/concurrency bounds.
 *
 * Every boundary function is non-throwing: failures return a discriminated
 * `{ ok: false; error }` result whose `error` is a stable short machine code
 * (never an echo of untrusted input, never a thrown exception).
 *
 * This module is intentionally framework-agnostic and holds no crypto backend:
 * signing/verifying (ECDSA), TLS handshakes, and durable persistence are
 * supplied by the concrete controller/agent implementations via the
 * `TransportSigner`/`TransportVerifier`/`TransportReplayPersistence` interfaces.
 * The controller's serialized field order and canonical body encoding here are
 * the interop contract with the Go agent transport package.
 */

import { isIPv4, isIPv6 } from "node:net";
import { createHash } from "node:crypto";
import type { HostId, ProtocolMessageType, ProtocolVersion, ParseResult, RequestId, UtcTimestamp, JsonValue } from "./protocol.js";
import { CURRENT_PROTOCOL_VERSION, isProtocolVersionCompatible, parseProtocolId, parseProtocolMessageType, parseProtocolVersion, parseUtcTimestamp } from "./protocol.js";

// ---------------------------------------------------------------------------
// TLS version
// ---------------------------------------------------------------------------

/** Explicitly enumerated TLS protocol versions. */
export type TransportTLSVersion = "TLS1.0" | "TLS1.1" | "TLS1.2" | "TLS1.3";

/** The minimum TLS version this deployment will accept. */
export const TRANSPORT_MIN_TLS_VERSION: TransportTLSVersion = "TLS1.3";

const TLS_VERSION_MAP: Record<string, [number, number]> = Object.freeze({
  "TLS1.0": [1, 0],
  "TLS1.1": [1, 1],
  "TLS1.2": [1, 2],
  "TLS1.3": [1, 3],
});

/** Parse an unknown value into a {@link TransportTLSVersion}. */
export function parseTransportTLSVersion(input: unknown): ParseResult<TransportTLSVersion> {
  return typeof input === "string" && Object.prototype.hasOwnProperty.call(TLS_VERSION_MAP, input)
    ? { ok: true, value: input as TransportTLSVersion }
    : { ok: false, error: "ERR_INVALID_TLS_VERSION" };
}

/** Compare two versions by (major, minor). Negative = a earlier than b. */
export function compareTransportTLSVersion(a: TransportTLSVersion, b: TransportTLSVersion): number {
  const av = TLS_VERSION_MAP[a];
  const bv = TLS_VERSION_MAP[b];
  const diff = (av![0] - bv![0]) || (av![1] - bv![1]);
  return diff < 0 ? -1 : diff > 0 ? 1 : 0;
}

/** Whether a version meets the enforced minimum (TLS1.3). */
export function isTransportTLSVersionSupported(v: TransportTLSVersion): boolean {
  return compareTransportTLSVersion(v, TRANSPORT_MIN_TLS_VERSION) >= 0;
}

// ---------------------------------------------------------------------------
// Branded opaque IDs / bounds
// ---------------------------------------------------------------------------

declare const transportSequenceBrand: unique symbol;
/** Monotonic request sequence per authenticated certificate. */
export type TransportSequence = number & { readonly __brand: typeof transportSequenceBrand };
declare const transportNonceBrand: unique symbol;
/** Per-request anti-replay nonce (base64url, no padding). */
export type TransportNonce = string & { readonly __brand: typeof transportNonceBrand };
declare const transportBodyDigestBrand: unique symbol;
/** SHA-256 hex of the canonical body bytes. */
export type TransportBodyDigest = string & { readonly __brand: typeof transportBodyDigestBrand };

const SEQUENCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HEX64 = /^[a-f0-9]{64}$/, SERIAL = /^[A-F0-9]{2,40}$/, TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const B64URL_NO_PAD = /^[A-Za-z0-9_-]{1,256}$/;

function validTime(v: unknown): v is string {
  return typeof v === "string" && TIME.test(v) && !Number.isNaN(Date.parse(v)) && new Date(v).toISOString() === v;
}

/** Parse a non-negative, safe-integer transport sequence. */
export function parseTransportSequence(input: unknown): ParseResult<TransportSequence> {
  if (typeof input !== "number" || !Number.isSafeInteger(input) || input < 0 || input > Number.MAX_SAFE_INTEGER) {
    return { ok: false, error: "ERR_INVALID_SEQUENCE" };
  }
  return { ok: true, value: input as TransportSequence };
}

// ---------------------------------------------------------------------------
// Canonical body encoding (interop contract with the Go agent)
// ---------------------------------------------------------------------------

/**
 * Deterministic canonical JSON: object keys sorted lexicographically, no
 * extraneous whitespace. The UTF-8 encoding of this string is what a
 * `TransportSigner` hashes to produce {@link TransportBodyDigest}. Both
 * implementations must agree byte-for-byte.
 */
export function transportCanonicalJson(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean" || typeof value === "number") return String(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map((child) => transportCanonicalJson(child)).join(",") + "]";
  if (typeof value === "object") {
    const obj = value as { readonly [key: string]: JsonValue };
    const keys = Object.keys(obj).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + transportCanonicalJson(obj[k])).join(",") + "}";
  }
  return "null";
}

/** SHA-256 hex digest of the canonical body bytes. */
export function transportBodyDigest(payload: JsonValue): TransportBodyDigest {
  return createHash("sha256").update(transportCanonicalJson(payload)).digest("hex") as TransportBodyDigest;
}

// ---------------------------------------------------------------------------
// Parsed certificate
// ---------------------------------------------------------------------------

/** A framework-agnostic, fully parsed leaf certificate. No PEM bytes. */
export interface TransportParsedCertificate {
  readonly fingerprint: string;
  readonly serial: string;
  readonly commonName: string;
  readonly address: string;
  readonly spiffe: string;
  readonly notBefore: string;
  readonly notAfter: string;
  /** Fingerprint of the issuing certificate (the controller CA). */
  readonly issuerFingerprint: string;
  /** Whether this certificate is itself a CA. */
  readonly isCa: boolean;
}

const pem = (v: unknown) => typeof v === "string" && v.length <= 16_384 && /-----BEGIN CERTIFICATE-----\n[\s\S]+\n-----END CERTIFICATE-----\n$/.test(v);
const ip = (v: unknown) => typeof v === "string" && !v.includes("%") && (isIPv4(v) || (isIPv6(v) && new URL(`http://${v}/`).hostname.slice(1, -1) === v));

function fields(input: unknown, keys: readonly string[]): Record<string, PropertyDescriptor> | null {
  try {
    if (typeof input !== "object" || input === null || Array.isArray(input)) return null;
    const proto = Object.getPrototypeOf(input);
    if (proto !== Object.prototype && proto !== null) return null;
    const own = Reflect.ownKeys(input);
    if (own.length !== keys.length || own.some((k) => typeof k !== "string" || !keys.includes(k))) return null;
    const d = Object.getOwnPropertyDescriptors(input);
    return keys.every((k) => d[k] && "value" in d[k]) ? d : null;
  } catch {
    return null;
  }
}

/** Parse a leaf certificate into its framework-agnostic representation. */
export function parseTransportParsedCertificate(input: unknown): ParseResult<TransportParsedCertificate> {
  const keys = ["fingerprint", "serial", "commonName", "address", "spiffe", "notBefore", "notAfter", "issuerFingerprint", "isCa"] as const;
  const d = fields(input, keys);
  if (!d) return { ok: false, error: "ERR_CERTIFICATE_PARSE" };
  const g = (k: string) => d[k]!.value;
  const fingerprint = g("fingerprint");
  const serial = g("serial");
  const commonName = g("commonName");
  const address = g("address");
  const spiffe = g("spiffe");
  const notBefore = g("notBefore");
  const notAfter = g("notAfter");
  const issuerFingerprint = g("issuerFingerprint");
  const isCa = g("isCa");
  if (
    typeof fingerprint !== "string" || !HEX64.test(fingerprint) ||
    typeof serial !== "string" || !SERIAL.test(serial) ||
    typeof commonName !== "string" || !SEQUENCE_PATTERN.test(commonName) ||
    !ip(address) || typeof spiffe !== "string" || spiffe.length > 256 ||
    !validTime(notBefore) || !validTime(notAfter) ||
    typeof issuerFingerprint !== "string" || !HEX64.test(issuerFingerprint) ||
    typeof isCa !== "boolean"
  ) {
    return { ok: false, error: "ERR_CERTIFICATE_PARSE" };
  }
  return { ok: true, value: Object.freeze(Object.assign(Object.create(null), { fingerprint, serial, commonName, address, spiffe, notBefore, notAfter, issuerFingerprint, isCa })) as TransportParsedCertificate };
}

// ---------------------------------------------------------------------------
// Trust result / auth status
// ---------------------------------------------------------------------------

/** Whether an authenticated certificate is permitted to act. */
export type TransportCertificateActiveStatus = "active" | "revoked" | "absent";

/**
 * The resolution of a presented certificate against the controller CA and the
 * authoritative host store. `trusted_active` permits action; `trusted_revoked`
 * denotes a still-CA-signed but revoked leaf (the controller may deny new
 * requests and close sessions for it); the other statuses deny outright.
 */
export type TransportTrustStatus =
  | "trusted_active"
  | "trusted_revoked"
  | "expired"
  | "not_yet_valid"
  | "wrong_ca"
  | "bad_identity"
  | "trusted_unknown_host";

/** A complete authentication outcome. `detail` is never echoed in responses. */
export type TransportAuthResult =
  | { readonly ok: true; readonly status: TransportTrustStatus; readonly hostId: HostId; readonly certificate: TransportParsedCertificate }
  | { readonly ok: false; readonly status: TransportTrustStatus; readonly detail: string };

export type TransportAuthStatus = TransportTrustStatus | "missing_peer_certificate" | "handshake_failure" | "unsupported_tls_version" | "bad_signature" | "negotiation_failed";

// ---------------------------------------------------------------------------
// Signed envelope (versioned hello / heartbeat-ready)
// ---------------------------------------------------------------------------

declare const transportSignedEnvelopeBrand: unique symbol;
export type TransportSignedEnvelope<T extends JsonValue = JsonValue> = {
  readonly protocolVersion: ProtocolVersion;
  readonly messageType: ProtocolMessageType;
  readonly hostId: HostId;
  readonly requestId: RequestId;
  readonly sequence: TransportSequence;
  readonly sentAt: UtcTimestamp;
  readonly nonce: TransportNonce;
  readonly bodyDigest: TransportBodyDigest;
  readonly certFingerprint: string;
  readonly certSerial: string;
  readonly signature: string;
  readonly payload: T;
};

const DOMAIN = "lanmm-transport-signed-v1";
const SCHEME = "ecdsa-p256-sha256";

/**
 * The canonical field string over which a {@link TransportSigner} signs (it is
 * not itself hashed). Both implementations must build this identically.
 */
export function transportSignedFields<T extends JsonValue>(env: TransportSignedEnvelope<T>, bodyDigest: TransportBodyDigest): string {
  return [
    DOMAIN,
    SCHEME,
    env.hostId,
    env.requestId,
    String(env.sequence),
    env.sentAt,
    env.nonce,
    env.certFingerprint,
    env.certSerial,
    bodyDigest,
  ].join("\x1f");
}

// ---------------------------------------------------------------------------
// Signer / verifier interfaces (concrete backends live in controller/agent)
// ---------------------------------------------------------------------------

export interface TransportSigner {
  readonly algorithm: "ecdsa-p256-sha256";
  readonly certificate: TransportParsedCertificate;
  /** Produce a hex ECDSA signature over the canonical field string. */
  sign(message: string): string;
}
export interface TransportVerifier {
  readonly algorithm: "ecdsa-p256-sha256";
  readonly certificate: TransportParsedCertificate;
  /** Verify a hex ECDSA signature over the canonical field string. */
  verify(message: string, signatureHex: string): boolean;
}

/** Build a signed envelope, validating inputs without throwing. */
export function signTransportSignedEnvelope<T extends JsonValue>(
  raw: unknown,
  signer: TransportSigner,
): ParseResult<TransportSignedEnvelope<T>> {
  const parsed = parseTransportSignedEnvelope<T>(raw);
  if (!parsed.ok) return parsed;
  const env = parsed.value;
  const bodyDigest = transportBodyDigest(env.payload);
  const nonce = typeof env.nonce === "string" && B64URL_NO_PAD.test(env.nonce) ? (env.nonce as TransportNonce) : "";
  const message = transportSignedFields<T>(env, bodyDigest);
  let signature: string;
  try {
    signature = signer.sign(message);
  } catch {
    return { ok: false, error: "ERR_SIGNATURE" };
  }
  if (typeof signature !== "string" || signature.length < 16 || signature.length > 256) {
    return { ok: false, error: "ERR_SIGNATURE" };
  }
  const output = Object.create(null) as Record<string, unknown>;
  Object.assign(output, {
    protocolVersion: env.protocolVersion,
    messageType: env.messageType,
    hostId: env.hostId,
    requestId: env.requestId,
    sequence: env.sequence,
    sentAt: env.sentAt,
    nonce: nonce,
    bodyDigest,
    certFingerprint: env.certFingerprint,
    certSerial: env.certSerial,
    signature,
    payload: env.payload,
  });
  return { ok: true, value: Object.freeze(output) as unknown as TransportSignedEnvelope<T> };
}

/**
 * Verify a signed envelope against a {@link TransportVerifier}. Returns a
 * machine-code error (`bad_signature`, `negotiation_failed`, envelope parse,
 * ...) but never throws.
 */
export function verifyTransportSignedEnvelope<T extends JsonValue>(
  input: unknown,
  verifier: TransportVerifier,
): ParseResult<TransportSignedEnvelope<T>> {
  const parsed = parseTransportSignedEnvelope<T>(input);
  if (!parsed.ok) return parsed;
  const env = parsed.value;
  const bodyDigest = transportBodyDigest(env.payload);
  if (env.bodyDigest !== bodyDigest) return { ok: false, error: "ERR_BODY_DIGEST" };
  const message = transportSignedFields<T>(env, bodyDigest);
  let ok: boolean;
  try {
    ok = verifier.verify(message, env.signature);
  } catch {
    return { ok: false, error: "ERR_SIGNATURE" };
  }
  if (!ok) return { ok: false, error: "bad_signature" };
  return { ok: true, value: env };
}

/** Parse, detach, and freeze a signed envelope; non-throwing. */
export function parseTransportSignedEnvelope<T extends JsonValue>(input: unknown): ParseResult<TransportSignedEnvelope<T>> {
  const requestRequiredKeys = ["protocolVersion", "messageType", "hostId", "requestId", "sequence", "sentAt", "nonce", "bodyDigest", "certFingerprint", "certSerial", "signature"] as const;
  if (typeof input !== "object" || input === null || Array.isArray(input)) return { ok: false, error: "ERR_ENVELOPE" };
  try {
    const proto = Object.getPrototypeOf(input);
    if (proto !== Object.prototype && proto !== null) return { ok: false, error: "ERR_ENVELOPE" };
    const keys = Reflect.ownKeys(input);
    const allowed = new Set<string>([...requestRequiredKeys, "payload"]);
    if (keys.some((k) => typeof k !== "string" || !allowed.has(k as string))) return { ok: false, error: "ERR_ENVELOPE" };
    if (requestRequiredKeys.some((k) => !keys.includes(k))) return { ok: false, error: "ERR_ENVELOPE" };
    const descriptors = Object.getOwnPropertyDescriptors(input);
    if (keys.some((k) => typeof k !== "string" || !descriptors[k] || !("value" in descriptors[k]))) return { ok: false, error: "ERR_ENVELOPE" };

    const g = (k: string) => descriptors[k]!.value as unknown;
    const version = parseProtocolVersion(g("protocolVersion"));
    if (!version.ok || !isProtocolVersionCompatible(CURRENT_PROTOCOL_VERSION, version.value)) return { ok: false, error: "negotiation_failed" };
    const messageType = parseProtocolMessageType(g("messageType"));
    if (!messageType.ok) return { ok: false, error: "ERR_ENVELOPE" };
    const hostId = parseProtocolId("host", g("hostId"));
    if (!hostId.ok) return { ok: false, error: "ERR_ENVELOPE" };
    const requestId = parseProtocolId("request", g("requestId"));
    if (!requestId.ok) return { ok: false, error: "ERR_ENVELOPE" };
    const sequence = parseTransportSequence(g("sequence"));
    if (!sequence.ok) return { ok: false, error: "ERR_ENVELOPE" };
    const sentAt = parseUtcTimestamp(g("sentAt"));
    if (!sentAt.ok) return { ok: false, error: "ERR_ENVELOPE" };
    const nonce = g("nonce");
    const bodyDigest = g("bodyDigest");
    const certFingerprint = g("certFingerprint");
    const certSerial = g("certSerial");
    const signature = g("signature");
    const payload = g("payload");
    if (typeof nonce !== "string" || !B64URL_NO_PAD.test(nonce)) return { ok: false, error: "ERR_ENVELOPE" };
    if (typeof bodyDigest !== "string" || !HEX64.test(bodyDigest)) return { ok: false, error: "ERR_ENVELOPE" };
    if (typeof certFingerprint !== "string" || !HEX64.test(certFingerprint)) return { ok: false, error: "ERR_ENVELOPE" };
    if (typeof certSerial !== "string" || !SERIAL.test(certSerial)) return { ok: false, error: "ERR_ENVELOPE" };
    if (typeof signature !== "string" || signature.length < 16 || signature.length > 256) return { ok: false, error: "ERR_ENVELOPE" };

    const output = Object.create(null) as Record<string, unknown>;
    output.protocolVersion = version.value;
    output.messageType = messageType.value;
    output.hostId = hostId.value;
    output.requestId = requestId.value;
    output.sequence = sequence.value;
    output.sentAt = sentAt.value;
    output.nonce = nonce;
    output.bodyDigest = bodyDigest;
    output.certFingerprint = certFingerprint;
    output.certSerial = certSerial;
    output.signature = signature;
    output.payload = payload;
    return { ok: true, value: Object.freeze(output) as unknown as TransportSignedEnvelope<T> };
  } catch {
    return { ok: false, error: "ERR_ENVELOPE" };
  }
}

// ---------------------------------------------------------------------------
// Request bounds
// ---------------------------------------------------------------------------

export interface TransportRequestBounds {
  readonly maxRequestBytes: number;
  readonly maxRequestFields: number;
  readonly maxRequestBodyBytes: number;
  readonly maxHeaderBytes: number;
  readonly maxHeaderCount: number;
  readonly maxHeaderNameLength: number;
  readonly maxHeaderValueLength: number;
  readonly maxRequestBodyDepth: number;
  readonly maxCertificateSerialLength: number;
  readonly maxCertificateFingerprintLength: number;
  readonly maxHostIdLength: number;
  readonly maxNonceLength: number;
  readonly maxSequence: number;
  readonly connectionTimeoutMs: number;
  readonly headerTimeoutMs: number;
  readonly bodyTimeoutMs: number;
  readonly maxConcurrent: number;
}

export const TRANSPORT_DEFAULT_REQUEST_BOUNDS: TransportRequestBounds = Object.freeze({
  maxRequestBytes: 64 * 1024,
  maxRequestFields: 32,
  maxRequestBodyBytes: 32 * 1024,
  maxHeaderBytes: 8 * 1024,
  maxHeaderCount: 64,
  maxHeaderNameLength: 256,
  maxHeaderValueLength: 8192,
  maxRequestBodyDepth: 8,
  maxCertificateSerialLength: 40,
  maxCertificateFingerprintLength: 64,
  maxHostIdLength: 128,
  maxNonceLength: 256,
  maxSequence: Number.MAX_SAFE_INTEGER,
  connectionTimeoutMs: 8_000,
  headerTimeoutMs: 4_000,
  bodyTimeoutMs: 8_000,
  maxConcurrent: 256,
});

export function parseTransportRequestBounds(input: unknown): ParseResult<TransportRequestBounds> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) return { ok: false, error: "ERR_INVALID_BOUNDS" };
  const keys = ["maxRequestBytes", "maxRequestFields", "maxRequestBodyBytes", "maxHeaderBytes", "maxHeaderCount", "maxHeaderNameLength", "maxHeaderValueLength", "maxRequestBodyDepth", "maxCertificateSerialLength", "maxCertificateFingerprintLength", "maxHostIdLength", "maxNonceLength", "maxSequence", "connectionTimeoutMs", "headerTimeoutMs", "bodyTimeoutMs", "maxConcurrent"] as const;
  const d = fields(input, keys);
  if (!d) return { ok: false, error: "ERR_INVALID_BOUNDS" };
  const caps = { maxRequestBytes: 64 * 1024, maxRequestFields: 4096, maxRequestBodyBytes: 32 * 1024, maxHeaderBytes: 64 * 1024, maxHeaderCount: 1024, maxHeaderNameLength: 1024, maxHeaderValueLength: 64 * 1024, maxRequestBodyDepth: 64, maxCertificateSerialLength: 64, maxCertificateFingerprintLength: 256, maxHostIdLength: 1024, maxNonceLength: 1024, maxSequence: Number.MAX_SAFE_INTEGER, connectionTimeoutMs: 60_000, headerTimeoutMs: 30_000, bodyTimeoutMs: 60_000, maxConcurrent: 65_535 } as const;
  const out: TransportRequestBounds = {
    maxRequestBytes: 0, maxRequestFields: 0, maxRequestBodyBytes: 0,
    maxHeaderBytes: 0, maxHeaderCount: 0, maxHeaderNameLength: 0,
    maxHeaderValueLength: 0, maxRequestBodyDepth: 0, maxCertificateSerialLength: 0,
    maxCertificateFingerprintLength: 0, maxHostIdLength: 0, maxNonceLength: 0,
    maxSequence: 0, connectionTimeoutMs: 0, headerTimeoutMs: 0,
    bodyTimeoutMs: 0, maxConcurrent: 0,
  };
  for (const key of keys) {
    const v = d[key]!.value;
    if (typeof v !== "number" || !Number.isSafeInteger(v) || v <= 0 || v > caps[key as keyof typeof caps]) return { ok: false, error: "ERR_INVALID_BOUNDS" };
    (out as unknown as Record<string, number>)[key] = v;
  }
  return { ok: true, value: out };
}

/** Bounds status reported when enforcement trips. */
export type TransportBoundsStatus =
  | "ok"
  | "request_too_large"
  | "request_fields_too_many"
  | "body_too_large"
  | "header_too_large"
  | "too_many_headers"
  | "header_name_too_long"
  | "header_value_too_long"
  | "body_too_deep"
  | "serial_too_long"
  | "fingerprint_too_long"
  | "hostId_too_long"
  | "nonce_too_long"
  | "sequence_too_large"
  | "connection_timeout_ms"
  | "header_timeout_ms"
  | "body_timeout_ms"
  | "too_many_concurrent";

export interface TransportBoundsCheck {
  readonly requestBytes: number;
  readonly requestFields: number;
  readonly bodyBytes: number;
  readonly headerBytes: number;
  readonly headerCount: number;
  readonly headerNames: readonly string[];
  readonly headerValues: readonly string[];
  readonly bodyDepth: number;
  readonly serialLength: number;
  readonly fingerprintLength: number;
  readonly hostIdLength: number;
  readonly nonceLength: number;
  readonly sequence: TransportSequence;
}

/** Enforce hard bounds on a parsed envelope+context. Non-throwing. */
export function enforceTransportBounds(env: TransportSignedEnvelope<JsonValue>, bounds: TransportRequestBounds, check: TransportBoundsCheck): TransportBoundsStatus {
  const reqLen = JSON.stringify(env).length;
  if (reqLen > bounds.maxRequestBytes) return "request_too_large";
  if (check.requestFields > bounds.maxRequestFields) return "request_fields_too_many";
  if (check.bodyBytes > bounds.maxRequestBodyBytes) return "body_too_large";
  if (check.headerBytes > bounds.maxHeaderBytes) return "header_too_large";
  if (check.headerCount > bounds.maxHeaderCount) return "too_many_headers";
  for (const name of check.headerNames) if (name.length > bounds.maxHeaderNameLength) return "header_name_too_long";
  for (const value of check.headerValues) if (value.length > bounds.maxHeaderValueLength) return "header_value_too_long";
  if (check.bodyDepth > bounds.maxRequestBodyDepth) return "body_too_deep";
  if (check.serialLength > bounds.maxCertificateSerialLength) return "serial_too_long";
  if (check.fingerprintLength > bounds.maxCertificateFingerprintLength) return "fingerprint_too_long";
  if (check.hostIdLength > bounds.maxHostIdLength) return "hostId_too_long";
  if (check.nonceLength > bounds.maxNonceLength) return "nonce_too_long";
  if (check.sequence > bounds.maxSequence) return "sequence_too_large";
  return "ok";
}

// ---------------------------------------------------------------------------
// Replay window
// ---------------------------------------------------------------------------

export type TransportReplayWindowStatus = "accepted" | "duplicate" | "out_of_order" | "stale" | "future";

export interface TransportReplayWindow {
  readonly windowSize: TransportSequence;
  /** Record and classify a sequence for one authenticated certificate. */
  check(hostId: string, certSerial: string, certFingerprint: string, sequence: TransportSequence, now: string): TransportReplayWindowStatus;
  /** Serialise the internal state for durable persistence. */
  snapshot?(): string;
  /** Rebuild the window from a {@link snapshot} (durability across restart). */
  load?(snapshot: string): void;
}

export interface TransportReplaySnapshot {
  readonly certSerial: string;
  readonly certFingerprint: string;
  readonly highWater: number;
  readonly sequences: readonly string[];
  readonly lastSeenBySequence: Readonly<Record<string, string>>;
}

declare const transportReplayResultBrand: unique symbol;
export type TransportReplayResult = readonly [TransportReplayWindowStatus, { readonly highWater: TransportSequence }];

/**
 * In-memory replay window keyed per certificate. Rejects duplicates,
 * out-of-order (already superseded within the window), stale (outside the
 * window), and future (jumping beyond the window). Accepts everything else
 * and advances the high-water mark.
 */
export class TransportInMemoryReplayWindow implements TransportReplayWindow {
  readonly windowSize: TransportSequence;
  private readonly highWater = new Map<string, number>();
  private readonly seen = new Map<string, Set<string>>();
  private readonly lastSeen = new Map<string, Map<string, string>>();

  constructor(windowSize: TransportSequence) {
    this.windowSize = windowSize;
  }

  check(hostId: string, certSerial: string, _certFingerprint: string, sequence: TransportSequence, now: string): TransportReplayWindowStatus {
    const series = this.seen.get(certSerial) ?? new Set<string>();
    const hw = this.highWater.get(certSerial) ?? 0;
    if (series.has(String(sequence))) return "duplicate";
    if (sequence < hw - this.windowSize) return "stale";
    if (sequence > hw + this.windowSize + 1) return "future";
    if (sequence <= hw) return "out_of_order";
    series.add(String(sequence));
    this.seen.set(certSerial, series);
    this.highWater.set(certSerial, sequence);
    const bucket = this.lastSeen.get(certSerial) ?? new Map<string, string>();
    bucket.set(String(sequence), now);
    this.lastSeen.set(certSerial, bucket);
    return "accepted";
  }

  snapshot(): string {
    const out: TransportReplaySnapshot[] = [];
    for (const [certSerial, hwValue] of this.highWater) {
      const series = this.seen.get(certSerial) ?? new Set<string>();
      const bucket = this.lastSeen.get(certSerial) ?? new Map<string, string>();
      out.push({ certSerial, certFingerprint: "", highWater: hwValue, sequences: [...series].sort(), lastSeenBySequence: Object.fromEntries(bucket) });
    }
    return JSON.stringify(out);
  }

  load(snapshot: string): void {
    let parsed: TransportReplaySnapshot[];
    try {
      parsed = JSON.parse(snapshot);
    } catch {
      return;
    }
    if (!Array.isArray(parsed)) return;
    for (const entry of parsed) {
      if (typeof entry.certSerial !== "string") continue;
      const hw = entry.highWater;
      if (typeof hw !== "number" || hw < 0) continue;
      const series = new Set<string>((entry.sequences ?? []).map((s) => String(s)));
      this.seen.set(entry.certSerial, series);
      this.highWater.set(entry.certSerial, hw);
      const bucket = new Map<string, string>(Object.entries(entry.lastSeenBySequence ?? {}));
      this.lastSeen.set(entry.certSerial, bucket);
    }
  }
}

// ---------------------------------------------------------------------------
// Trust resolver / negotiation
// ---------------------------------------------------------------------------

export interface TransportTrustResolver {
  /** Runtime role of the party evaluating the certificate. */
  readonly role: "controller" | "agent";
  /**
   * Resolve a presented leaf certificate. `authorityStatus` reports the
   * authoritative active/revoked/absent state of the leaf's serial (from the
   * controller's host certificate store). Never throws.
   */
  resolve(leaf: TransportParsedCertificate, ca: TransportParsedCertificate | null, now: string, authorityStatus: (serial: string) => TransportCertificateActiveStatus): TransportTrustResult;
}

export type TransportTrustResult =
  | { readonly ok: true; readonly status: TransportTrustStatus; readonly hostId: HostId; readonly certificate: TransportParsedCertificate }
  | { readonly ok: false; readonly status: TransportTrustStatus; readonly detail: string };

export function trustToAuthResult(result: TransportTrustResult): TransportAuthResult {
  const status: TransportTrustStatus = result.status;
  const detail: string = result.ok ? "" : result.detail;
  if (!result.ok) return { ok: false, status, detail };
  if (result.status === "trusted_active") {
    return { ok: true, status, hostId: result.hostId, certificate: result.certificate };
  }
  return { ok: false, status, detail };
}

export function negotiateProtocol(peer: ProtocolVersion, options: { readonly minimum?: TransportTLSVersion } = {}): boolean {
  const minimum = options.minimum ?? TRANSPORT_MIN_TLS_VERSION;
  return isProtocolVersionCompatible(CURRENT_PROTOCOL_VERSION, peer) && isTransportTLSVersionSupported(minimum);
}

export const TRANSPORT_HELLO_MESSAGE_TYPE: ProtocolMessageType = "transport.hello" as ProtocolMessageType;
export const TRANSPORT_HEARTBEAT_MESSAGE_TYPE: ProtocolMessageType = "transport.heartbeat" as ProtocolMessageType;
