/** OFFLINE unsigned evidence payload codec, not a receipt, approval, signer or
 * authorization candidate. No trust assertion supplied by a caller is proof.
 * No production importer is permitted until separate review/authority gates.
 */
import { createHash } from "node:crypto";
import { types } from "node:util";
import { commandAuthorizationDigest, parseCommandRequest, parseCommandResponse,
  parseStreamWireJSON, responseMatches } from "@lan-model-manager/core";

export const NATIVE_EVIDENCE_PAYLOAD_DOMAIN = "lanmm-native-terminal-evidence-payload-v1";
export const NATIVE_EVIDENCE_KIND = "agent.command.terminal-evidence";
export const NATIVE_EVIDENCE_VERSION = 1;
export const NATIVE_EVIDENCE_DISPOSITION = "evidence-only";
export const MAX_EVIDENCE_RESPONSE_BYTES = 512 * 1024;
/** Entire unsigned payload, including base64 and all metadata; outer transport
 * overhead must ALSO fit 786432 bytes in any future separately reviewed handler. */
export const MAX_EVIDENCE_PAYLOAD_BYTES = 768 * 1024;
const RESPONSE_DOMAIN = "lanmm-native-response-bytes-v1\0";
const TUPLE_DIGEST_DOMAIN = "lanmm-native-terminal-evidence-tuple-digest-v1\0";
const TUPLE_DOMAIN = "lanmm-native-terminal-evidence-v1";
const TUPLE_KEYS = ["domain", "hostId", "jobId", "requestId", "commandSequence", "idempotencyKey",
  "authorizationRequestDigest", "storedQueueDigest", "terminalState", "terminalRevision", "responseDigest",
  "responseByteLength", "evidenceKind", "holdClass"] as const;
const PAYLOAD_KEYS = ["domain", "kind", "version", "disposition", "tuple", "responseBase64", "evidenceSource"] as const;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HEX = /^[a-f0-9]{64}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
type Terminal = "timed-out" | "failed" | "succeeded" | "cancelled";
type Hold = "unknown" | "in_flight" | "retained" | "pending_uncertain";
type Source = "retained_same_process" | "explicit_snapshot" | "synthetic";
type TrustAssertion = "verified_current" | "unverified" | "unavailable";
export interface NativeEvidenceTuple {
  readonly domain: typeof TUPLE_DOMAIN;
  readonly hostId: string; readonly jobId: string; readonly requestId: string;
  readonly commandSequence: number; readonly idempotencyKey: string;
  readonly authorizationRequestDigest: string; readonly storedQueueDigest: string;
  readonly terminalState: Terminal; readonly terminalRevision: string;
  readonly responseDigest: string; readonly responseByteLength: number;
  readonly evidenceKind: "failed" | "succeeded" | "cancelled"; readonly holdClass: Hold;
}
export interface NativeEvidencePayload {
  readonly domain: typeof NATIVE_EVIDENCE_PAYLOAD_DOMAIN;
  readonly kind: typeof NATIVE_EVIDENCE_KIND; readonly version: 1;
  readonly disposition: "evidence-only"; readonly tuple: NativeEvidenceTuple;
  readonly responseBase64: string; readonly evidenceSource: Source;
}
export type NativeEvidenceCodecResult = Readonly<{ ok: false; error: "ERR_NATIVE_EVIDENCE_CODEC" }> | Readonly<{
  ok: true; payload: NativeEvidencePayload; tupleDigest: string;
  /** Original full payload bytes (not a parsed/reencoded approximation). */
  payloadBase64: string;
  /** Merely repeated from the caller snapshot; NEVER verified by this codec. */
  callerTrustAssertion: TrustAssertion;
  releasePermitted: false; executionPermitted: false; receiptCommitted: false;
}>;
const reject = (): never => { throw new Error("ERR_NATIVE_EVIDENCE_CODEC"); };
const failure = (): NativeEvidenceCodecResult => Object.freeze({ ok: false, error: "ERR_NATIVE_EVIDENCE_CODEC" });
function exact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || types.isProxy(value) || Array.isArray(value)) return reject();
  const prototype = Object.getPrototypeOf(value), own = Reflect.ownKeys(value);
  if (prototype !== Object.prototype && prototype !== null || own.length !== keys.length) return reject();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (own.some(key => typeof key !== "string" || !keys.includes(key)) ||
      keys.some(key => !descriptors[key] || !("value" in descriptors[key]!))) return reject();
  return Object.fromEntries(keys.map(key => [key, descriptors[key]!.value]));
}
function stamp(value: unknown): boolean {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}
function id(value: unknown): value is string { return typeof value === "string" && ID.test(value); }
function digest(value: unknown): value is string { return typeof value === "string" && HEX.test(value); }
function wellFormed(value: string): boolean {
  return !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value);
}
/** Local bounded data-descriptor snapshot mirrors the accepted classifier's
 * defensive boundary. Keep classifier unwired (its import-isolation gate forbids
 * production importers). Core parsers see only owned, accessor-free JSON data.
 * Fractions/exponents/-0, unsafe numbers and lone surrogates are unsupported.
 */
function dataSnapshot(input: unknown): unknown {
  let nodes = 0, bytes = 0;
  const walk = (value: unknown, depth: number): unknown => {
    if (++nodes > 65536 || depth > 16) return reject();
    if (value === null || typeof value === "boolean") return value;
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) return reject();
      return value;
    }
    if (typeof value === "string") {
      bytes += Buffer.byteLength(value);
      if (bytes > 600 * 1024 || !wellFormed(value)) return reject();
      return value;
    }
    if (typeof value !== "object" || types.isProxy(value)) return reject();
    const array = Array.isArray(value), prototype = Object.getPrototypeOf(value);
    if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) return reject();
    const descriptors = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(value);
    if (array) {
      const length = descriptors.length?.value;
      if (!Number.isSafeInteger(length) || length > 65536 || keys.length !== length + 1) return reject();
      const result: unknown[] = [];
      for (let i = 0; i < length; i++) {
        const descriptor = descriptors[String(i)];
        if (!descriptor || !("value" in descriptor)) return reject();
        result.push(walk(descriptor.value, depth + 1));
      }
      return result;
    }
    const result = Object.create(null) as Record<string, unknown>;
    for (const key of keys) {
      if (typeof key !== "string" || !wellFormed(key)) return reject();
      bytes += Buffer.byteLength(key);
      const descriptor = descriptors[key]!;
      if (!("value" in descriptor) || bytes > 600 * 1024) return reject();
      result[key] = walk(descriptor.value, depth + 1);
    }
    return result;
  };
  return walk(input, 0);
}
/** Intrinsic slots only: never read shadowable byte-view accessors/iterators.
 * Shared/detached buffers and proxies fail closed. Bounds precede allocation. */
function byteSnapshot(view: unknown, cap: number): Uint8Array {
  if (types.isProxy(view) || !types.isUint8Array(view)) return reject();
  const proto = Object.getPrototypeOf(Uint8Array.prototype);
  const slot = (key: string) => Object.getOwnPropertyDescriptor(proto, key)!.get!.call(view);
  const backing = slot("buffer"), length = slot("byteLength"), offset = slot("byteOffset");
  if (!types.isArrayBuffer(backing) || length < 1 || length > cap) return reject();
  const bytes = new Uint8Array(length);
  bytes.set(new Uint8Array(backing, offset, length));
  return bytes;
}
function responseBase64(value: unknown): Uint8Array {
  if (typeof value !== "string" || value.length < 4 || value.length > 4 * Math.ceil(MAX_EVIDENCE_RESPONSE_BYTES / 3) ||
      !BASE64.test(value)) return reject();
  const bytes = Buffer.from(value, "base64");
  if (bytes.length > MAX_EVIDENCE_RESPONSE_BYTES || bytes.toString("base64") !== value) return reject();
  return bytes;
}
/** Accepts exactly the accepted classifier's explicit snapshot shape, not paths
 * or adapters. The historical capability identifies history even after expiry.
 * No clock, terminal revision derivation, or independent trust proof is supplied.
 */
function expected(snapshot: unknown): { payload: NativeEvidencePayload; trust: TrustAssertion } {
  const top = exact(snapshot, ["storedRequest", "storedQueueDigest", "terminal", "native", "runnerHold", "currentTrust"]);
  const terminal = exact(top.terminal, ["hostId", "jobId", "requestId", "state", "revision", "occurredAt"]);
  const trust = exact(top.currentTrust, ["provenance", "hostId", "bindingRevision"]);
  const native = exact(top.native, ["kind", "responseBytes", "authorizationDigest", "source"]);
  if (![terminal.hostId, terminal.jobId, terminal.requestId, terminal.revision].every(id) ||
      !["timed-out", "failed", "succeeded", "cancelled"].includes(terminal.state as string) || !stamp(terminal.occurredAt) ||
      !["unknown", "in_flight", "retained", "pending_uncertain"].includes(top.runnerHold as string) ||
      native.kind !== "response" || !["retained_same_process", "explicit_snapshot", "synthetic"].includes(native.source as string)) return reject();
  if (!(trust.provenance === "unavailable" && trust.hostId === null && trust.bindingRevision === null ||
        trust.provenance === "unverified" && (trust.hostId === null || id(trust.hostId)) && (trust.bindingRevision === null || id(trust.bindingRevision)) ||
        trust.provenance === "verified_current" && id(trust.hostId) && id(trust.bindingRevision))) return reject();
  const request = parseCommandRequest(dataSnapshot(top.storedRequest));
  if (!request.ok || !stamp(request.value.deadline) || !stamp(request.value.capability.expiresAt)) return reject();
  const q = request.value;
  const queueDigest = createHash("sha256").update(JSON.stringify(q)).digest("hex");
  const authorizationDigest = commandAuthorizationDigest(q);
  if (!digest(top.storedQueueDigest) || queueDigest !== top.storedQueueDigest ||
      !digest(native.authorizationDigest) || authorizationDigest !== native.authorizationDigest ||
      terminal.hostId !== q.hostId || terminal.jobId !== q.jobId || terminal.requestId !== q.requestId ||
      trust.provenance === "verified_current" && trust.hostId !== q.hostId) return reject();
  const bytes = byteSnapshot(native.responseBytes, MAX_EVIDENCE_RESPONSE_BYTES);
  const response = parseCommandResponse(dataSnapshot(parseStreamWireJSON(bytes, MAX_EVIDENCE_RESPONSE_BYTES)));
  if (!response.ok || !stamp(response.value.observedAt) ||
      !["failed", "succeeded", "cancelled"].includes(response.value.status) || !responseMatches(q, response.value)) return reject();
  const tuple: NativeEvidenceTuple = Object.freeze({ domain: TUPLE_DOMAIN, hostId: q.hostId, jobId: q.jobId, requestId: q.requestId,
    commandSequence: q.sequence, idempotencyKey: q.idempotencyKey, authorizationRequestDigest: authorizationDigest,
    storedQueueDigest: queueDigest, terminalState: terminal.state as Terminal, terminalRevision: terminal.revision as string,
    responseDigest: createHash("sha256").update(RESPONSE_DOMAIN, "utf8").update(bytes).digest("hex"),
    responseByteLength: bytes.length, evidenceKind: response.value.status as NativeEvidenceTuple["evidenceKind"], holdClass: top.runnerHold as Hold });
  return { payload: Object.freeze({ domain: NATIVE_EVIDENCE_PAYLOAD_DOMAIN, kind: NATIVE_EVIDENCE_KIND,
    version: NATIVE_EVIDENCE_VERSION, disposition: NATIVE_EVIDENCE_DISPOSITION, tuple,
    responseBase64: Buffer.from(bytes).toString("base64"), evidenceSource: native.source as Source }), trust: trust.provenance as TrustAssertion };
}
function success(payload: NativeEvidencePayload, trust: TrustAssertion, raw: Uint8Array): NativeEvidenceCodecResult {
  // Stable encoding: UTF8(domain + NUL) || UTF8(JSON.stringify([T fields in
  // TUPLE_KEYS order])). IDs/digests/enums are bounded ASCII, numbers safe integers.
  const tupleDigest = createHash("sha256").update(TUPLE_DIGEST_DOMAIN, "utf8")
    .update(JSON.stringify(TUPLE_KEYS.map(key => payload.tuple[key])), "utf8").digest("hex");
  return Object.freeze({ ok: true, payload, tupleDigest, payloadBase64: Buffer.from(raw).toString("base64"),
    callerTrustAssertion: trust, releasePermitted: false, executionPermitted: false, receiptCommitted: false });
}
/** Returns private evidence data, never approval/receipt/execution authority. */
export function encodeNativeTerminalEvidence(snapshot: unknown): NativeEvidenceCodecResult {
  try {
    const { payload, trust } = expected(snapshot), raw = Buffer.from(JSON.stringify(payload), "utf8");
    if (raw.length > MAX_EVIDENCE_PAYLOAD_BYTES) return failure();
    return success(payload, trust, raw);
  } catch { return failure(); }
}
/** Strict raw payload boundary, revalidated against the complete independent
 * caller snapshot. Payload domain/kind/version must be inside any future signed
 * body; outer messageType alone is insufficient and is NOT authenticated here.
 * Even an exact match cannot commit a receipt, release a hold or execute work.
 */
export function decodeNativeTerminalEvidence(raw: unknown, snapshot: unknown): NativeEvidenceCodecResult {
  try {
    const bytes = byteSnapshot(raw, MAX_EVIDENCE_PAYLOAD_BYTES);
    const parsed = exact(parseStreamWireJSON(bytes, MAX_EVIDENCE_PAYLOAD_BYTES), PAYLOAD_KEYS);
    const tuple = exact(parsed.tuple, TUPLE_KEYS);
    // Canonical base64 only; retain/hash the complete original response, no JSON
    // reconstruction, whitespace removal, key sorting or observation truncation.
    const response = responseBase64(parsed.responseBase64);
    const { payload, trust } = expected(snapshot);
    if (response.length !== tuple.responseByteLength ||
        TUPLE_KEYS.some(key => tuple[key] !== payload.tuple[key]) ||
        PAYLOAD_KEYS.some(key => key !== "tuple" && parsed[key] !== payload[key])) return failure();
    return success(payload, trust, bytes);
  } catch { return failure(); }
}
