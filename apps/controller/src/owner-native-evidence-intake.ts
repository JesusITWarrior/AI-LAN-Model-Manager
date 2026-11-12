import { types } from "node:util";
import { parseStreamWireJSON } from "@lan-model-manager/core";
import { guardManagementRequest } from "./guard.js";
import { createAllowedOrigins } from "./origin.js";
import type { OriginPolicyOptions } from "./origin.js";
import { createJobStores } from "./jobs-store.js";
import { OwnerNativeEvidenceCandidateRegistry, OWNER_NATIVE_EVIDENCE_ACTION, OWNER_NATIVE_EVIDENCE_DISPOSITION } from "./owner-native-evidence-candidates.js";
import type { DatabaseSync } from "node:sqlite";
import type { SessionManager } from "./session-manager.js";
import { buildOwnerNativeEvidenceSnapshot } from "./owner-native-evidence-snapshot.js";
import { decodeNativeTerminalEvidence, MAX_EVIDENCE_PAYLOAD_BYTES, MAX_EVIDENCE_RESPONSE_BYTES } from "./native-terminal-evidence-codec.js";

const PATH = "/api/v1/native-evidence/prepare";
const LABEL = "Owner-provided unsigned evidence; source not independently proven";
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TYPED_ARRAY_PROTO = Object.getPrototypeOf(Uint8Array.prototype) as object;
const slot = (key: string) => Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, key)?.get;
const getBuffer = slot("buffer")!, getLength = slot("byteLength")!, getOffset = slot("byteOffset")!;
const fail = () => Object.freeze({ ok: false as const, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" as const });

type Staging = { raw: Uint8Array; response: Uint8Array | null; jobId: string; source: string };
export type OwnerNativeEvidencePreview = Readonly<{
  candidateHandle: string;
  expectedTupleDigest: string;
  jobId: string;
  hostId: string;
  requestId: string;
  terminalState: string;
  terminalRevision: string;
  evidenceKind: string;
  payloadBytes: number;
  responseBytes: number;
  expiresAt: string;
  action: typeof OWNER_NATIVE_EVIDENCE_ACTION;
  disposition: typeof OWNER_NATIVE_EVIDENCE_DISPOSITION;
  label: typeof LABEL;
}>;
export type OwnerNativeEvidenceIntakeResult = Readonly<{ ok: true; preview: OwnerNativeEvidencePreview }> | ReturnType<typeof fail>;

function exactOwnData(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) return null;
    const proto = Object.getPrototypeOf(value), own = Reflect.ownKeys(value), descriptors = Object.getOwnPropertyDescriptors(value);
    if ((proto !== Object.prototype && proto !== null) || own.length !== keys.length ||
        own.some(key => typeof key !== "string" || !keys.includes(key))) return null;
    const result = Object.create(null) as Record<string, unknown>;
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!descriptor || !("value" in descriptor)) return null;
      result[key] = descriptor.value;
    }
    return result;
  } catch { return null; }
}
function copyBytes(input: unknown): Uint8Array | null {
  try {
    if (types.isProxy(input) || !types.isUint8Array(input)) return null;
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Uint8Array.prototype && prototype !== Buffer.prototype) return null;
    if (["buffer", "byteLength", "byteOffset", Symbol.iterator].some(key => Object.getOwnPropertyDescriptor(input, key) !== undefined)) return null;
    const backing = getBuffer.call(input) as ArrayBuffer;
    const length = getLength.call(input) as number;
    const offset = getOffset.call(input) as number;
    if (!types.isArrayBuffer(backing) || !Number.isSafeInteger(length) || length < 1 || length > MAX_EVIDENCE_PAYLOAD_BYTES || !Number.isSafeInteger(offset)) return null;
    const copy = new Uint8Array(length);
    Uint8Array.prototype.set.call(copy, new Uint8Array(backing, offset, length));
    return copy;
  } catch { return null; }
}
function payloadFields(value: unknown): { jobId: string; source: string; responseBase64: string } | null {
  const top = exactOwnData(value, ["domain", "kind", "version", "disposition", "tuple", "responseBase64", "evidenceSource"]);
  const tuple = top && exactOwnData(top.tuple, ["domain", "hostId", "jobId", "requestId", "commandSequence", "idempotencyKey", "authorizationRequestDigest", "storedQueueDigest", "terminalState", "terminalRevision", "responseDigest", "responseByteLength", "evidenceKind", "holdClass"]);
  if (!top || !tuple || typeof tuple.jobId !== "string" || !ID.test(tuple.jobId) || typeof top.evidenceSource !== "string" ||
      typeof top.responseBase64 !== "string") return null;
  return { jobId: tuple.jobId, source: top.evidenceSource, responseBase64: top.responseBase64 };
}
function canonicalBase64(value: string): Uint8Array | null {
  let decoded: Buffer | null = null;
  try {
    if (value.length < 4 || value.length > 4 * Math.ceil(MAX_EVIDENCE_RESPONSE_BYTES / 3) ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return null;
    decoded = Buffer.from(value, "base64");
    if (decoded.length < 1 || decoded.length > MAX_EVIDENCE_RESPONSE_BYTES || decoded.toString("base64") !== value) {
      decoded.fill(0);
      return null;
    }
    return decoded;
  } catch { decoded?.fill(0); return null; }
}

/** Authenticated synchronous staging adapter; it is deliberately not an HTTP route. */
export class OwnerNativeEvidenceIntakeService {
  private readonly origins: readonly string[];
  private readonly stores: ReturnType<typeof createJobStores>;
  private staging: Staging | null = null;
  private preparing = false;
  private closed = false;
  private readonly registry: OwnerNativeEvidenceCandidateRegistry;

  constructor(private readonly db: DatabaseSync, private readonly sessions: SessionManager, allowedOrigins: readonly string[],
    private readonly clock: () => string = () => new Date().toISOString(), private readonly originOptions: OriginPolicyOptions = {}) {
    this.origins = createAllowedOrigins([...allowedOrigins], this.originOptions);
    this.stores = createJobStores(db);
    this.registry = new OwnerNativeEvidenceCandidateRegistry(sessions, { clock,
      prepareCandidate: () => this.prepareStagedCandidate(), consumeCandidate: () => undefined });
  }

  /** The sole registry is exposed for later confirm-service composition. */
  get candidateRegistry(): OwnerNativeEvidenceCandidateRegistry { return this.registry; }

  prepare(input: unknown): OwnerNativeEvidenceIntakeResult {
    if (this.preparing || this.closed) return fail();
    this.preparing = true;
    let rawCopy: Uint8Array | null = null;
    try {
      const envelope = exactOwnData(input, ["method", "path", "cookieHeader", "originHeader", "csrfHeader", "jobSelector", "rawPayloadBytes"]);
      if (!envelope || envelope.method !== "POST" || envelope.path !== PATH ||
          typeof envelope.cookieHeader !== "string" || envelope.cookieHeader.length > 4096 ||
          envelope.originHeader !== null && (typeof envelope.originHeader !== "string" || envelope.originHeader.length > 2048) ||
          envelope.csrfHeader !== null && (typeof envelope.csrfHeader !== "string" || envelope.csrfHeader.length > 128) ||
          typeof envelope.jobSelector !== "string" || !ID.test(envelope.jobSelector) || types.isProxy(envelope.rawPayloadBytes) || !types.isUint8Array(envelope.rawPayloadBytes)) return fail();
      const guard = guardManagementRequest(this.sessions, this.origins, { method: envelope.method as string,
        cookieHeader: envelope.cookieHeader, originHeader: envelope.originHeader as string | null, csrfHeader: envelope.csrfHeader as string | null }, this.originOptions);
      if (!guard.ok) return fail();

      // No byte copy or retained reference exists until owner/origin/CSRF auth succeeds.
      rawCopy = copyBytes(envelope.rawPayloadBytes);
      if (!rawCopy) return fail();
      const parsed = parseStreamWireJSON(rawCopy, MAX_EVIDENCE_PAYLOAD_BYTES);
      const fields = payloadFields(parsed);
      if (!fields || fields.jobId !== envelope.jobSelector) return fail();
      const response = canonicalBase64(fields.responseBase64);
      if (!response) return fail();
      this.staging = { raw: rawCopy, response, jobId: fields.jobId, source: fields.source };
      const candidate = this.registry.prepare(guard);
      if (!candidate.ok) return fail();
      const tuple = candidate.summary.tuple;
      const preview: OwnerNativeEvidencePreview = Object.freeze({ candidateHandle: candidate.handle,
        expectedTupleDigest: candidate.summary.tupleDigest, jobId: tuple.jobId, hostId: tuple.hostId, requestId: tuple.requestId,
        terminalState: tuple.terminalState, terminalRevision: tuple.terminalRevision, evidenceKind: tuple.evidenceKind,
        payloadBytes: candidate.summary.payloadBytes, responseBytes: candidate.summary.responseBytes, expiresAt: candidate.summary.expiresAt,
        action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION, label: LABEL });
      return Object.freeze({ ok: true as const, preview });
    } catch { return fail(); }
    finally {
      if (rawCopy) rawCopy.fill(0);
      if (this.staging?.response) this.staging.response.fill(0);
      this.staging = null;
      this.preparing = false;
    }
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.registry.close();
  }

  private prepareStagedCandidate(): unknown {
    const staged = this.staging;
    if (!staged || this.closed || !staged.response) return null;
    const now = this.clock();
    let prepared: unknown = null;
    this.stores.withAuditTransaction(tx => {
      const built = buildOwnerNativeEvidenceSnapshot(this.db, tx, staged.jobId, staged.response!, staged.source, now);
      if (!built) return;
      staged.response!.fill(0);
      staged.response = built.responseBytes;
      const decoded = decodeNativeTerminalEvidence(staged.raw, built.snapshot);
      if (!decoded.ok || decoded.tupleDigest !== built.tupleDigest ||
          JSON.stringify(decoded.payload.tuple) !== JSON.stringify(built.tuple)) return;
      prepared = Object.freeze({ tuple: built.tuple, tupleDigest: built.tupleDigest, payloadBytes: staged.raw,
        responseBytes: built.responseBytes, certificateBindingAssertion: built.certificateBindingAssertion });
    });
    return prepared;
  }
}
