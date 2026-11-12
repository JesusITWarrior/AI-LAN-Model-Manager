import { createHash, randomBytes } from "node:crypto";
import { types } from "node:util";
import type { GuardResult } from "./guard.js";
import type { SessionManager } from "./session-manager.js";
import type { SessionMetadata } from "./session-types.js";

/** Volatile prototype only: not persisted consent, a receipt, ACK, or trust proof. */
export const OWNER_NATIVE_EVIDENCE_ACTION = "append-supplemental-native-evidence" as const;
export const OWNER_NATIVE_EVIDENCE_DISPOSITION = "evidence-only" as const;
export const OWNER_NATIVE_EVIDENCE_CANDIDATE_TTL_MS = 60_000;
export const OWNER_NATIVE_EVIDENCE_MAX_CANDIDATES = 16;
export const OWNER_NATIVE_EVIDENCE_MAX_RETAINED_BYTES = 8 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 768 * 1024;
const MAX_RESPONSE_BYTES = 512 * 1024;
const HEX = /^[a-f0-9]{64}$/;
const TUPLE_KEYS = ["domain", "hostId", "jobId", "requestId", "commandSequence", "idempotencyKey", "authorizationRequestDigest", "storedQueueDigest", "terminalState", "terminalRevision", "responseDigest", "responseByteLength", "evidenceKind", "holdClass"] as const;
const CERTIFICATE_KEYS = ["certificateId", "serial", "fingerprint", "version", "candidateId", "address", "port", "protocolVersion", "caId", "caVersion", "spiffeUri"] as const;
const VIEW_KEYS = ["tuple", "tupleDigest", "payloadBytes", "responseBytes", "certificateBindingAssertion"] as const;
const SYNC_KEYS = ["ok", "session"] as const;
const TYPED_ARRAY_PROTO = Object.getPrototypeOf(Uint8Array.prototype) as object;
const intrinsic = (key: string) => Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, key)?.get;
const getBuffer = intrinsic("buffer")!;
const getByteLength = intrinsic("byteLength")!;
const getByteOffset = intrinsic("byteOffset")!;

export interface NativeEvidenceCandidateTuple {
  readonly domain: string;
  readonly hostId: string;
  readonly jobId: string;
  readonly requestId: string;
  readonly commandSequence: number;
  readonly idempotencyKey: string;
  readonly authorizationRequestDigest: string;
  readonly storedQueueDigest: string;
  readonly terminalState: "succeeded" | "failed" | "timed-out" | "cancelled";
  readonly terminalRevision: string;
  readonly responseDigest: string;
  readonly responseByteLength: number;
  readonly evidenceKind: "succeeded" | "failed" | "cancelled";
  readonly holdClass: "unknown" | "in_flight" | "retained" | "pending_uncertain";
}
export interface NativeEvidenceCertificateAssertion {
  readonly certificateId: string;
  readonly serial: string;
  readonly fingerprint: string;
  readonly version: number;
  readonly candidateId: string;
  readonly address: string;
  readonly port: number;
  readonly protocolVersion: number;
  readonly caId: string;
  readonly caVersion: number;
  readonly spiffeUri: string;
}
/** Caller is an internal trusted seam; its certificate/history fields remain assertions, never fresh proof. */
export interface NativeEvidenceCandidateInput {
  readonly tuple: NativeEvidenceCandidateTuple;
  readonly tupleDigest: string;
  readonly payloadBytes: Uint8Array;
  readonly responseBytes: Uint8Array;
  readonly certificateBindingAssertion: NativeEvidenceCertificateAssertion;
}
export interface CapturedNativeEvidenceCandidate extends NativeEvidenceCandidateInput {
  readonly action: typeof OWNER_NATIVE_EVIDENCE_ACTION;
  readonly disposition: typeof OWNER_NATIVE_EVIDENCE_DISPOSITION;
}
export interface CandidateRegistryOptions {
  readonly clock?: () => string;
  readonly id?: () => string;
  readonly prepareCandidate: (session: SessionMetadata, binding: Readonly<{ id: string; credentialVersion: number; expiresAt: string }>) => unknown;
  /** Synchronous callback; return void. Any returned value is a closed failure. */
  readonly consumeCandidate: (candidate: CapturedNativeEvidenceCandidate) => void;
}
export type CandidateFailure = Readonly<{ ok: false; error: "ERR_NATIVE_EVIDENCE_CANDIDATE" }>;
export type CandidateSummary = Readonly<{
  action: typeof OWNER_NATIVE_EVIDENCE_ACTION;
  disposition: typeof OWNER_NATIVE_EVIDENCE_DISPOSITION;
  handle: string;
  tuple: NativeEvidenceCandidateTuple;
  tupleDigest: string;
  payloadBytes: number;
  responseBytes: number;
  certificateAssertion: Readonly<{ certificateId: string; serial: string; fingerprint: string; version: number; candidateId: string; caId: string; caVersion: number }>;
  expiresAt: string;
  currentHistoryAndCertificateRevalidated: false;
}>;
export type CandidateSuccess = Readonly<{ ok: true; handle: string; summary: CandidateSummary }>;
export type CandidateResult = CandidateFailure | CandidateSuccess;
export type ConsumeResult = Readonly<{ ok: true; consumed: true }> | CandidateFailure;

/** Opaque, object-identity lease token. Intentionally contains no handle string and no
 *  raw bytes: it is a per-registry-instance, per-entry reference resolved only through
 *  this registry's WeakMap, so a forged object, a deep copy, or a token minted by
 *  another registry instance all fail identity lookup. */
export type CandidateLeaseToken = object;
export type LeaseFailure = Readonly<{ ok: false; error: "ERR_NATIVE_EVIDENCE_LEASE" }>;
export interface LeaseRequest {
  readonly handle: string;
  readonly action: typeof OWNER_NATIVE_EVIDENCE_ACTION;
  readonly disposition: typeof OWNER_NATIVE_EVIDENCE_DISPOSITION;
}
export type LeaseResult = Readonly<{ ok: true; token: CandidateLeaseToken }> | LeaseFailure;
export type CommitResult = Readonly<{ ok: true; committed: true }> | LeaseFailure;
export type ReleaseResult = Readonly<{ ok: true; released: true }> | LeaseFailure;

type Binding = Readonly<{ id: string; credentialVersion: number; expiresAt: string }>;
type LeaseRecord = { readonly handle: string; readonly bytes: number };
type Entry = { readonly ownerId: string; readonly sessionId: string; readonly credentialVersion: number; readonly expiresAt: string; readonly summary: CandidateSummary; readonly candidate: CapturedNativeEvidenceCandidate; readonly integrity: string; readonly bytes: number; lease: LeaseRecord | null };
const fail = (): CandidateFailure => Object.freeze({ ok: false, error: "ERR_NATIVE_EVIDENCE_CANDIDATE" });
const failLease = (): LeaseFailure => Object.freeze({ ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" });
// Resolves a lease token purely by object identity, independent of its literal contents: a
// deeply-equal copy, a forged object with matching nonce/seq, or a token from a different
// registry instance all fail because their reference is absent from this WeakMap.
function leaseToken(leases: WeakMap<object, LeaseRecord>, token: unknown): LeaseRecord | null {
  return token && typeof token === "object" && leases.has(token as object) ? leases.get(token as object)! : null;
}
function record(input: unknown, keys: readonly string[]): Record<string, unknown> | null {
  try {
    if (!input || typeof input !== "object" || Array.isArray(input) || types.isProxy(input)) return null;
    const proto = Object.getPrototypeOf(input);
    if (proto !== Object.prototype && proto !== null) return null;
    const own = Reflect.ownKeys(input), descriptors = Object.getOwnPropertyDescriptors(input);
    if (own.length !== keys.length || own.some(k => typeof k !== "string" || !keys.includes(k)) || keys.some(k => !descriptors[k] || !("value" in descriptors[k]!))) return null;
    return Object.fromEntries(keys.map(k => [k, descriptors[k]!.value]));
  } catch { return null; }
}
function boundedText(value: unknown, max = 256): value is string { return typeof value === "string" && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value); }
function copyBytes(input: unknown, cap: number): Uint8Array | null {
  try {
    // Intrinsic typed-array slot getters accept Uint8Array and Buffer while
    // ignoring caller-shadowed accessors; proxies and SharedArrayBuffer fail.
    if (types.isProxy(input) || !types.isUint8Array(input)) return null;
    const backing = getBuffer!.call(input) as ArrayBuffer;
    const length = getByteLength!.call(input) as number;
    const offset = getByteOffset!.call(input) as number;
    if (!types.isArrayBuffer(backing) || !Number.isSafeInteger(length) || length < 1 || length > cap || !Number.isSafeInteger(offset)) return null;
    const source = new Uint8Array(backing, offset, length), copy = new Uint8Array(length);
    Uint8Array.prototype.set.call(copy, source);
    return copy;
  } catch { return null; }
}
function cloneTuple(input: unknown): NativeEvidenceCandidateTuple | null {
  const t = record(input, TUPLE_KEYS);
  if (!t) return null;
  const states = ["succeeded", "failed", "timed-out", "cancelled"];
  const kinds = ["succeeded", "failed", "cancelled"];
  const holds = ["unknown", "in_flight", "retained", "pending_uncertain"];
  if (![t.domain, t.hostId, t.jobId, t.requestId, t.idempotencyKey, t.terminalRevision].every(v => boundedText(v, 128)) ||
      !Number.isSafeInteger(t.commandSequence) || (t.commandSequence as number) < 1 || typeof t.authorizationRequestDigest !== "string" || !HEX.test(t.authorizationRequestDigest) ||
      typeof t.storedQueueDigest !== "string" || !HEX.test(t.storedQueueDigest) || typeof t.terminalState !== "string" || !states.includes(t.terminalState) ||
      typeof t.responseDigest !== "string" || !HEX.test(t.responseDigest) || !Number.isSafeInteger(t.responseByteLength) || (t.responseByteLength as number) < 1 ||
      typeof t.evidenceKind !== "string" || !kinds.includes(t.evidenceKind) || typeof t.holdClass !== "string" || !holds.includes(t.holdClass)) return null;
  const result = Object.create(null) as Record<string, unknown>;
  for (const key of TUPLE_KEYS) result[key] = t[key];
  return Object.freeze(result) as unknown as NativeEvidenceCandidateTuple;
}
function cloneCertificate(input: unknown): NativeEvidenceCertificateAssertion | null {
  const c = record(input, CERTIFICATE_KEYS);
  if (!c || ![c.certificateId, c.serial, c.candidateId, c.address, c.caId, c.spiffeUri].every(v => boundedText(v, 512)) ||
      typeof c.fingerprint !== "string" || !HEX.test(c.fingerprint) || !Number.isSafeInteger(c.version) || (c.version as number) < 1 ||
      !Number.isSafeInteger(c.port) || (c.port as number) < 1 || (c.port as number) > 65535 ||
      !Number.isSafeInteger(c.protocolVersion) || (c.protocolVersion as number) < 1 || !Number.isSafeInteger(c.caVersion) || (c.caVersion as number) < 1) return null;
  const result = Object.create(null) as Record<string, unknown>;
  for (const key of CERTIFICATE_KEYS) result[key] = c[key];
  return Object.freeze(result) as unknown as NativeEvidenceCertificateAssertion;
}
function responseDigest(bytes: Uint8Array): string { return createHash("sha256").update("lanmm-native-response-bytes-v1\0", "utf8").update(bytes).digest("hex"); }
function tupleDigest(tuple: NativeEvidenceCandidateTuple): string { return createHash("sha256").update("lanmm-native-terminal-evidence-tuple-digest-v1\0", "utf8").update(JSON.stringify(TUPLE_KEYS.map(k => tuple[k])), "utf8").digest("hex"); }
function integrity(candidate: CapturedNativeEvidenceCandidate): string {
  return createHash("sha256").update(JSON.stringify(TUPLE_KEYS.map(k => candidate.tuple[k]))).update(candidate.tupleDigest).update(candidate.payloadBytes).update(candidate.responseBytes).digest("hex");
}
function guardSession(input: GuardResult, manager: SessionManager): { session: SessionMetadata; binding: Binding } | null {
  const g = record(input, SYNC_KEYS);
  if (!g || g.ok !== true || !g.session || typeof g.session !== "object") return null;
  const session = g.session as SessionMetadata;
  const binding = manager.binding(session);
  if (!binding || !boundedText(session.ownerId, 128) || !Number.isSafeInteger(session.credentialVersion) || session.credentialVersion !== binding.credentialVersion) return null;
  return { session, binding };
}
function nowMs(clock: () => string): number {
  const value = clock();
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) throw new Error("clock");
  return Date.parse(value);
}

/** In-memory prototype. It cannot re-read latest job history or active certificate state. */
export class OwnerNativeEvidenceCandidateRegistry {
  private readonly entries = new Map<string, Entry>();
  private retainedBytes = 0;
  private issuedSequence = 0;
  private leaseSequence = 0;
  /** Maps each issued lease token object (by identity) to its internal lease record. The
   *  value carries the entry handle/bytes; the token carries neither raw bytes nor the
   *  handle string, so only this registry instance can resolve a token it minted. */
  private leases: WeakMap<object, LeaseRecord> = new WeakMap();
  private readonly instanceNonce = randomBytes(16).toString("hex");
  private closed = false;
  private preparing = false;
  private readonly clock: () => string;
  private readonly makeId: () => string;
  constructor(private readonly manager: SessionManager, private readonly options: CandidateRegistryOptions) {
    this.clock = options.clock ?? (() => new Date().toISOString());
    this.makeId = options.id ?? (() => randomBytes(24).toString("hex"));
  }
  private prune(now: number): void {
    for (const [handle, entry] of this.entries) if (Date.parse(entry.expiresAt) <= now) this.drop(handle);
  }
  private drop(handle: string): void {
    const entry = this.entries.get(handle);
    if (entry) { this.retainedBytes -= entry.bytes; this.entries.delete(handle); }
  }
  prepare(guard: GuardResult): CandidateResult {
    if (this.closed || this.preparing) return fail();
    this.preparing = true;
    try {
      const auth = guardSession(guard, this.manager);
      if (!auth) return fail();
      const now = nowMs(this.clock);
      this.prune(now);
      if (this.closed || this.entries.size >= OWNER_NATIVE_EVIDENCE_MAX_CANDIDATES) return fail();
      const raw = this.options.prepareCandidate(auth.session, auth.binding);
      if (this.closed) return fail();
      // Exact descriptor-only shape validation rejects promises/thenables and
      // extra `then` accessors without ever reading/invoking a caller getter.
      const source = record(raw, VIEW_KEYS);
      if (!source) return fail();
      const tuple = cloneTuple(source.tuple), certificateBindingAssertion = cloneCertificate(source.certificateBindingAssertion);
      const payloadBytes = copyBytes(source.payloadBytes, MAX_PAYLOAD_BYTES), responseBytes = copyBytes(source.responseBytes, MAX_RESPONSE_BYTES);
      if (!tuple || !certificateBindingAssertion || !payloadBytes || !responseBytes || typeof source.tupleDigest !== "string" || !HEX.test(source.tupleDigest) ||
          tuple.responseByteLength !== responseBytes.length || responseDigest(responseBytes) !== tuple.responseDigest || tupleDigest(tuple) !== source.tupleDigest) return fail();
      const capturedTupleDigest = source.tupleDigest as string;
      const bytes = payloadBytes.length + responseBytes.length;
      if (bytes > OWNER_NATIVE_EVIDENCE_MAX_RETAINED_BYTES || this.retainedBytes + bytes > OWNER_NATIVE_EVIDENCE_MAX_RETAINED_BYTES) return fail();
      const expiresAt = new Date(Math.min(now + OWNER_NATIVE_EVIDENCE_CANDIDATE_TTL_MS, Date.parse(auth.binding.expiresAt))).toISOString();
      if (Date.parse(expiresAt) <= now) return fail();
      const baseId = this.makeId();
      if (this.closed || !boundedText(baseId, 128) || !Number.isSafeInteger(this.issuedSequence + 1)) return fail();
      const handle = `${baseId}:${this.instanceNonce}:${++this.issuedSequence}`;
      if (!boundedText(handle, 128)) return fail();
      const candidate: CapturedNativeEvidenceCandidate = Object.freeze({ action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION,
        tuple, tupleDigest: capturedTupleDigest, payloadBytes, responseBytes, certificateBindingAssertion });
      const certSummary = Object.freeze({ certificateId: certificateBindingAssertion.certificateId, serial: certificateBindingAssertion.serial,
        fingerprint: certificateBindingAssertion.fingerprint, version: certificateBindingAssertion.version, candidateId: certificateBindingAssertion.candidateId,
        caId: certificateBindingAssertion.caId, caVersion: certificateBindingAssertion.caVersion });
      const summary: CandidateSummary = Object.freeze({ action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION, handle,
        tuple, tupleDigest: capturedTupleDigest, payloadBytes: payloadBytes.length, responseBytes: responseBytes.length, certificateAssertion: certSummary,
        expiresAt, currentHistoryAndCertificateRevalidated: false });
      this.entries.set(handle, { ownerId: auth.session.ownerId, sessionId: auth.binding.id, credentialVersion: auth.binding.credentialVersion,
        expiresAt, summary, candidate, integrity: integrity(candidate), bytes, lease: null });
      this.retainedBytes += bytes;
      return Object.freeze({ ok: true, handle, summary });
    } catch { return fail(); }
    finally { this.preparing = false; }
  }
  inspect(guard: GuardResult, handle: unknown): CandidateResult {
    try {
      if (this.closed) return fail();
      const auth = guardSession(guard, this.manager);
      if (!auth || !boundedText(handle, 128)) return fail();
      const now = nowMs(this.clock); this.prune(now);
      const entry = this.entries.get(handle);
      if (!entry || entry.ownerId !== auth.session.ownerId || entry.sessionId !== auth.binding.id || entry.credentialVersion !== auth.binding.credentialVersion ||
          Date.parse(entry.expiresAt) <= now || integrity(entry.candidate) !== entry.integrity) return fail();
      return Object.freeze({ ok: true, handle, summary: entry.summary });
    } catch { return fail(); }
  }
  consume(guard: GuardResult, input: unknown): ConsumeResult {
    try {
      if (this.closed) return fail();
      const auth = guardSession(guard, this.manager);
      const request = record(input, ["handle", "action", "disposition"]);
      if (!auth || !request || !boundedText(request.handle, 128) || request.action !== OWNER_NATIVE_EVIDENCE_ACTION || request.disposition !== OWNER_NATIVE_EVIDENCE_DISPOSITION) return fail();
      const now = nowMs(this.clock); this.prune(now);
      const handle = request.handle as string, entry = this.entries.get(handle);
      if (!entry || entry.lease || entry.ownerId !== auth.session.ownerId || entry.sessionId !== auth.binding.id || entry.credentialVersion !== auth.binding.credentialVersion ||
          Date.parse(entry.expiresAt) <= now || integrity(entry.candidate) !== entry.integrity) return fail();
      this.drop(handle);
      // Give trusted synchronous callback an owned private copy; never expose retained storage.
      const delivered = Object.freeze({ ...entry.candidate, tuple: entry.candidate.tuple,
        payloadBytes: copyBytes(entry.candidate.payloadBytes, MAX_PAYLOAD_BYTES)!, responseBytes: copyBytes(entry.candidate.responseBytes, MAX_RESPONSE_BYTES)! });
      const result = this.options.consumeCandidate(delivered);
      // The seam is synchronous-void only. Reject any return value without
      // probing `then`, so hostile accessors are never invoked.
      if (result !== undefined) return fail();
      return Object.freeze({ ok: true, consumed: true });
    } catch { return fail(); }
  }
  /**
   * Reserve an already-prepared (available) candidate into a single lease that must be
   * settled with exactly one commit (transaction success) or release (confirmed
   * rollback).
   *
   * Security contract: the GuardResult forwarded here carries no method provenance — the
   * external caller MUST have verified it is its own real `POST` to an *exact* allowed
   * origin with a matching CSRF token. This lease is not proof of any DB record, current
   * job history, or certificate binding, and it holds no raw bytes or handle. The
   * returned token is an opaque, registry-instance- and exact-entry-bound object-identity
   * reference resolved through this registry's WeakMap: a forged object, a deep copy, or
   * a token from another registry instance all fail. Repeated or reentrant claim fails.
   * While leased, the entry stays owned and counts toward capacity; its bytes remain
   * capacity-counted. Expiry/revocation/rotation/credential change/close all fail closed
   * without exposing bytes. If the caller's transaction outcome is unknown it must call
   * neither commit nor release and leave the lease unavailable.
   */
  claim(guard: GuardResult, input: unknown): LeaseResult {
    try {
      if (this.closed) return failLease();
      const auth = guardSession(guard, this.manager);
      if (!auth) return failLease();
      const request = record(input, ["handle", "action", "disposition"]);
      if (!request || !boundedText(request.handle, 128) ||
          request.action !== OWNER_NATIVE_EVIDENCE_ACTION ||
          request.disposition !== OWNER_NATIVE_EVIDENCE_DISPOSITION) return failLease();
      const now = nowMs(this.clock); this.prune(now);
      const entry = this.entries.get(request.handle as string);
      if (!entry || entry.lease || entry.ownerId !== auth.session.ownerId || entry.sessionId !== auth.binding.id ||
          entry.credentialVersion !== auth.binding.credentialVersion || Date.parse(entry.expiresAt) <= now ||
          integrity(entry.candidate) !== entry.integrity) return failLease();
      const seq = ++this.leaseSequence;
      if (!Number.isSafeInteger(seq) || (seq as number) < 1) return failLease();
      // A zero-field object token is opaque and can only be resolved by this registry's WeakMap.
      const token = Object.freeze(Object.create(null)) as CandidateLeaseToken;
      const lease: LeaseRecord = { handle: request.handle as string, bytes: entry.bytes };
      this.leases.set(token, lease);
      entry.lease = lease;
      return Object.freeze({ ok: true, token });
    } catch { return failLease(); }
  }
  /**
   * Mark the leased entry spent and drop it (releasing its bytes) — call only AFTER the
   * caller's transaction has been observed successful. Requires the exact token, a
   * still-valid owner/session/credential guard, and an unexpired, nonclosed leased entry;
   * otherwise fails closed without exposing bytes. One-shot: a committed token can
   * neither be committed, released, nor re-claimed.
   */
  commitLease(guard: GuardResult, token: unknown): CommitResult {
    try {
      if (this.closed) return failLease();
      const auth = guardSession(guard, this.manager);
      if (!auth) return failLease();
      const lease = leaseToken(this.leases, token);
      if (!lease || !boundedText(lease.handle, 128)) return failLease();
      const now = nowMs(this.clock); this.prune(now);
      const entry = this.entries.get(lease.handle);
      if (!entry || entry.lease !== lease || entry.ownerId !== auth.session.ownerId || entry.sessionId !== auth.binding.id ||
          entry.credentialVersion !== auth.binding.credentialVersion || Date.parse(entry.expiresAt) <= now ||
          integrity(entry.candidate) !== entry.integrity) return failLease();
      this.leases.delete(token as object);
      // Commit is terminal: remove the entry and release its exact accounting once.
      this.drop(lease.handle);
      return Object.freeze({ ok: true, committed: true });
    } catch { return failLease(); }
  }
  /**
   * Return the leased entry to available — call only AFTER the caller's rollback has been
   * confirmed. Same exactness as `commitLease`: exact token, a still-valid
   * owner/session/credential guard, and an unexpired, nonclosed leased entry; otherwise
   * fails closed. One-shot: after release the token cannot be reused, but the entry
   * becomes claimable anew.
   */
  releaseLease(guard: GuardResult, token: unknown): ReleaseResult {
    try {
      if (this.closed) return failLease();
      const auth = guardSession(guard, this.manager);
      if (!auth) return failLease();
      const lease = leaseToken(this.leases, token);
      if (!lease || !boundedText(lease.handle, 128)) return failLease();
      const now = nowMs(this.clock); this.prune(now);
      const entry = this.entries.get(lease.handle);
      if (!entry || entry.lease !== lease || entry.ownerId !== auth.session.ownerId || entry.sessionId !== auth.binding.id ||
          entry.credentialVersion !== auth.binding.credentialVersion || Date.parse(entry.expiresAt) <= now ||
          integrity(entry.candidate) !== entry.integrity) return failLease();
      this.leases.delete(token as object);
      entry.lease = null;
      return Object.freeze({ ok: true, released: true });
    } catch { return failLease(); }
  }
  /** Test/diagnostic count only; no payload or authority is returned. */
  get size(): number { return this.entries.size; }
  get retainedByteCount(): number { return this.retainedBytes; }
  /** Drop retained data and permanently disable this volatile registry instance. */
  close(): void {
    if (this.closed) return;
    for (const handle of this.entries.keys()) this.drop(handle);
    this.leases = new WeakMap();
    this.retainedBytes = 0;
    this.closed = true;
  }
}
