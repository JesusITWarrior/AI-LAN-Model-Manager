import { createHash } from "node:crypto";
import { types } from "node:util";
import type { DatabaseSync } from "node:sqlite";
import { createJobStores } from "./jobs-store.js";

/**
 * Synthetic, append-only persistence core. Every value supplied here is a
 * caller assertion; this class does not authenticate a codec result, owner
 * session, certificate, signature, or transport. It creates no authority,
 * command ACK, hold transition, or runtime integration.
 */
export const EVIDENCE_ONLY_ACTION = "append-supplemental-native-evidence" as const;
export const EVIDENCE_ONLY_DISPOSITION = "evidence-only" as const;
export const EVIDENCE_MAX_PAYLOAD_BYTES = 768 * 1024;
export const EVIDENCE_MAX_RESPONSE_BYTES = 512 * 1024;

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HEX = /^[0-9a-f]{64}$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const TUPLE_DOMAIN = "lanmm-native-terminal-evidence-v1";
const TUPLE_HASH_DOMAIN = "lanmm-native-terminal-evidence-tuple-digest-v1\0";
const RESPONSE_HASH_DOMAIN = "lanmm-native-response-bytes-v1\0";
const RECEIPT_ID_DOMAIN = "lanmm-native-evidence-storage-core-id-v1\0";
const RECEIPT_CORE_DOMAIN = "lanmm-native-evidence-storage-core-v1";
const CONSENT_HASH_DOMAIN = "lanmm-native-evidence-consent-binding-v1\0";
const TUPLE_KEYS = ["domain", "hostId", "jobId", "requestId", "commandSequence", "idempotencyKey",
  "authorizationRequestDigest", "storedQueueDigest", "terminalState", "terminalRevision", "responseDigest",
  "responseByteLength", "evidenceKind", "holdClass"] as const;
const TERMINALS = ["timed-out", "failed", "succeeded", "cancelled"] as const;
const EVIDENCE_KINDS = ["failed", "succeeded", "cancelled"] as const;
const HOLD_CLASSES = ["unknown", "in_flight", "retained", "pending_uncertain"] as const;

export interface EvidenceTuple {
  readonly domain: typeof TUPLE_DOMAIN;
  readonly hostId: string;
  readonly jobId: string;
  readonly requestId: string;
  readonly commandSequence: number;
  readonly idempotencyKey: string;
  readonly authorizationRequestDigest: string;
  readonly storedQueueDigest: string;
  readonly terminalState: (typeof TERMINALS)[number];
  readonly terminalRevision: string;
  readonly responseDigest: string;
  readonly responseByteLength: number;
  readonly evidenceKind: (typeof EVIDENCE_KINDS)[number];
  readonly holdClass: (typeof HOLD_CLASSES)[number];
}

/** Non-proof owner/session/certificate assertions bound to this exact tuple. */
export interface ConsentAssertion {
  readonly ownerId: string;
  readonly sessionBindingDigest: string;
  readonly credentialVersion: number;
  readonly hostCertificateBindingDigest: string;
  readonly action: typeof EVIDENCE_ONLY_ACTION;
  readonly disposition: typeof EVIDENCE_ONLY_DISPOSITION;
  readonly consentedAt: string;
}

export interface SupplementalEvidenceInput {
  /** Exact bounded opaque payload bytes; caller must validate them separately. */
  readonly payloadBytes: Uint8Array;
  /** Exact response bytes named by tuple.responseDigest/responseByteLength. */
  readonly responseBytes: Uint8Array;
  readonly tuple: EvidenceTuple;
  readonly tupleDigest: string;
  readonly consent: ConsentAssertion;
}

export interface ReceiptCore {
  readonly domain: typeof RECEIPT_CORE_DOMAIN;
  readonly disposition: typeof EVIDENCE_ONLY_DISPOSITION;
  readonly receiptId: string;
  readonly tupleDigest: string;
  readonly terminalRevision: string;
  readonly consentBindingDigest: string;
  readonly committedAt: string;
}

export type AppendResult = Readonly<{
  ok: true;
  duplicate: boolean;
  tupleDigest: string;
  receiptCore: ReceiptCore;
}> | Readonly<{
  ok: false;
  code: "ERR_SUPPLEMENTAL_EVIDENCE_INPUT" | "ERR_SUPPLEMENTAL_EVIDENCE_CONFLICT" | "ERR_SUPPLEMENTAL_EVIDENCE_DATABASE";
}>;

type Data = Record<string, unknown>;
type Prepared = {
  tuple: EvidenceTuple; tupleJson: string; tupleDigest: string;
  payloadBytes: Uint8Array; payloadDigest: string;
  responseBytes: Uint8Array; consent: ConsentAssertion; consentJson: string; consentBindingDigest: string;
};

function ownData(value: unknown, keys: readonly string[]): Data | null {
  if (typeof value !== "object" || value === null || Array.isArray(value) || types.isProxy(value)) return null;
  try {
    const proto = Object.getPrototypeOf(value), own = Reflect.ownKeys(value);
    if ((proto !== Object.prototype && proto !== null) || own.length !== keys.length ||
        own.some((key) => typeof key !== "string" || !keys.includes(key))) return null;
    const ds = Object.getOwnPropertyDescriptors(value), out = Object.create(null) as Data;
    for (const key of keys) {
      const d = ds[key]; if (!d || !("value" in d)) return null;
      out[key] = d.value as unknown;
    }
    return out;
  } catch { return null; }
}

function copyBytes(value: unknown, cap: number): Uint8Array | null {
  if (types.isProxy(value) || !types.isUint8Array(value)) return null;
  try {
    const proto = Object.getPrototypeOf(Uint8Array.prototype);
    const slot = (name: string) => Object.getOwnPropertyDescriptor(proto, name)!.get!.call(value) as number | ArrayBuffer;
    const buffer = slot("buffer") as ArrayBuffer;
    const length = slot("byteLength") as number;
    const offset = slot("byteOffset") as number;
    if (!types.isArrayBuffer(buffer) || types.isSharedArrayBuffer(buffer) || length < 1 || length > cap) return null;
    const copy = new Uint8Array(length);
    copy.set(new Uint8Array(buffer, offset, length));
    return copy;
  } catch { return null; }
}

function validId(value: unknown): value is string { return typeof value === "string" && ID.test(value); }
function validHex(value: unknown): value is string { return typeof value === "string" && HEX.test(value); }
function validTime(value: unknown): value is string {
  if (typeof value !== "string" || !TIME.test(value)) return false;
  try { return new Date(value).toISOString() === value; } catch { return false; }
}
function hash(domain: string, bytes: Uint8Array | string): string {
  return createHash("sha256").update(domain, "utf8").update(bytes).digest("hex");
}
function tupleValues(t: EvidenceTuple): readonly (string | number)[] { return TUPLE_KEYS.map((key) => t[key]); }
function tupleDigest(t: EvidenceTuple): string { return hash(TUPLE_HASH_DOMAIN, Buffer.from(JSON.stringify(tupleValues(t)), "utf8")); }

function prepare(input: unknown): Prepared | null {
  const top = ownData(input, ["payloadBytes", "responseBytes", "tuple", "tupleDigest", "consent"]);
  if (!top) return null;
  const tuple = ownData(top.tuple, [...TUPLE_KEYS]);
  const consent = ownData(top.consent, ["ownerId", "sessionBindingDigest", "credentialVersion", "hostCertificateBindingDigest", "action", "disposition", "consentedAt"]);
  const payloadBytes = copyBytes(top.payloadBytes, EVIDENCE_MAX_PAYLOAD_BYTES);
  const responseBytes = copyBytes(top.responseBytes, EVIDENCE_MAX_RESPONSE_BYTES);
  if (!tuple || !consent || !payloadBytes || !responseBytes || !validHex(top.tupleDigest)) return null;
  if (tuple.domain !== TUPLE_DOMAIN || ![tuple.hostId, tuple.jobId, tuple.requestId, tuple.idempotencyKey, tuple.terminalRevision].every(validId) ||
      ![tuple.authorizationRequestDigest, tuple.storedQueueDigest, tuple.responseDigest].every(validHex) ||
      typeof tuple.commandSequence !== "number" || !Number.isSafeInteger(tuple.commandSequence) || tuple.commandSequence < 1 ||
      typeof tuple.responseByteLength !== "number" || !Number.isSafeInteger(tuple.responseByteLength) || tuple.responseByteLength < 1 ||
      !TERMINALS.includes(tuple.terminalState as (typeof TERMINALS)[number]) ||
      !EVIDENCE_KINDS.includes(tuple.evidenceKind as (typeof EVIDENCE_KINDS)[number]) ||
      !HOLD_CLASSES.includes(tuple.holdClass as (typeof HOLD_CLASSES)[number])) return null;
  if (tuple.responseByteLength !== responseBytes.length || hash(RESPONSE_HASH_DOMAIN, responseBytes) !== tuple.responseDigest ||
      tupleDigest(tuple as unknown as EvidenceTuple) !== top.tupleDigest) return null;
  if (!validId(consent.ownerId) || !validHex(consent.sessionBindingDigest) || !validHex(consent.hostCertificateBindingDigest) ||
      typeof consent.credentialVersion !== "number" || !Number.isSafeInteger(consent.credentialVersion) || consent.credentialVersion < 1 ||
      consent.action !== EVIDENCE_ONLY_ACTION || consent.disposition !== EVIDENCE_ONLY_DISPOSITION || !validTime(consent.consentedAt)) return null;

  const tupleCopy = Object.freeze(Object.fromEntries(TUPLE_KEYS.map((key) => [key, tuple[key]]))) as unknown as EvidenceTuple;
  const consentCopy: ConsentAssertion = Object.freeze({ ownerId: consent.ownerId as string,
    sessionBindingDigest: consent.sessionBindingDigest as string, credentialVersion: consent.credentialVersion as number,
    hostCertificateBindingDigest: consent.hostCertificateBindingDigest as string,
    action: EVIDENCE_ONLY_ACTION, disposition: EVIDENCE_ONLY_DISPOSITION, consentedAt: consent.consentedAt as string });
  const tupleJson = JSON.stringify(tupleValues(tupleCopy));
  const consentJson = JSON.stringify([consentCopy.ownerId, consentCopy.sessionBindingDigest, consentCopy.credentialVersion,
    consentCopy.hostCertificateBindingDigest, consentCopy.action, consentCopy.disposition, consentCopy.consentedAt]);
  const consentBindingDigest = hash(CONSENT_HASH_DOMAIN, Buffer.from(JSON.stringify([top.tupleDigest, consentJson]), "utf8"));
  return { tuple: tupleCopy, tupleJson, tupleDigest: top.tupleDigest as string, payloadBytes, payloadDigest: hash("lanmm-native-evidence-payload-bytes-v1\0", payloadBytes),
    responseBytes, consent: consentCopy, consentJson, consentBindingDigest };
}

function fixedFailure(code: Extract<AppendResult, { ok: false }>["code"]): AppendResult { return Object.freeze({ ok: false as const, code }); }
function parseReceipt(text: unknown, expected: Pick<ReceiptCore, "receiptId" | "tupleDigest" | "terminalRevision" | "consentBindingDigest">): ReceiptCore | null {
  if (typeof text !== "string" || text.length > 2048) return null;
  try {
    const v = JSON.parse(text) as Record<string, unknown>;
    if (v.domain !== RECEIPT_CORE_DOMAIN || v.disposition !== EVIDENCE_ONLY_DISPOSITION || v.receiptId !== expected.receiptId ||
        v.tupleDigest !== expected.tupleDigest || v.terminalRevision !== expected.terminalRevision ||
        v.consentBindingDigest !== expected.consentBindingDigest || !validTime(v.committedAt)) return null;
    return Object.freeze({ domain: RECEIPT_CORE_DOMAIN, disposition: EVIDENCE_ONLY_DISPOSITION, receiptId: expected.receiptId,
      tupleDigest: expected.tupleDigest, terminalRevision: expected.terminalRevision,
      consentBindingDigest: expected.consentBindingDigest, committedAt: v.committedAt });
  } catch { return null; }
}

/**
 * The fixture/repository is opt-in. The production database schema has not been
 * changed or registered. Owning the JobStores constructed from this exact `db`
 * guarantees its evidence INSERT and audit append share the one connection and
 * one BEGIN IMMEDIATE transaction.
 */
export class SupplementalNativeEvidenceRepository {
  private readonly stores;
  constructor(private readonly db: DatabaseSync, private readonly now: () => string = () => new Date().toISOString()) {
    this.stores = createJobStores(db, { now });
  }

  append(input: unknown): AppendResult {
    const p = prepare(input);
    if (!p) return fixedFailure("ERR_SUPPLEMENTAL_EVIDENCE_INPUT");
    const receiptId = hash(RECEIPT_ID_DOMAIN, Buffer.from(p.tupleDigest, "ascii"));
    const expected = { receiptId, tupleDigest: p.tupleDigest, terminalRevision: p.tuple.terminalRevision,
      consentBindingDigest: p.consentBindingDigest };
    let result: AppendResult | null = null;
    try {
      this.stores.withAuditTransaction((tx) => {
        const existing = this.db.prepare("SELECT tuple_json,payload_bytes,payload_digest,response_bytes,response_digest,response_byte_length,owner_id,session_binding_digest,credential_version,host_certificate_binding_digest,consent_action,consent_disposition,consented_at,consent_json,consent_binding_digest,receipt_core_json FROM supplemental_native_evidence WHERE tuple_digest=?")
          .get(p.tupleDigest) as Record<string, unknown> | undefined;
        if (existing) {
          const bytesEqual = (value: unknown, expectedBytes: Uint8Array) => value instanceof Uint8Array && Buffer.from(value).equals(Buffer.from(expectedBytes));
          const same = existing.tuple_json === p.tupleJson && existing.payload_digest === p.payloadDigest &&
            bytesEqual(existing.payload_bytes, p.payloadBytes) && bytesEqual(existing.response_bytes, p.responseBytes) &&
            existing.response_digest === p.tuple.responseDigest && Number(existing.response_byte_length) === p.responseBytes.length &&
            existing.owner_id === p.consent.ownerId && existing.session_binding_digest === p.consent.sessionBindingDigest &&
            Number(existing.credential_version) === p.consent.credentialVersion &&
            existing.host_certificate_binding_digest === p.consent.hostCertificateBindingDigest &&
            existing.consent_action === p.consent.action && existing.consent_disposition === p.consent.disposition &&
            existing.consented_at === p.consent.consentedAt && existing.consent_json === p.consentJson &&
            existing.consent_binding_digest === p.consentBindingDigest;
          if (!same) throw new Error("ERR_SUPPLEMENTAL_EVIDENCE_CONFLICT");
          const core = parseReceipt(existing.receipt_core_json, expected);
          if (!core) throw new Error("ERR_SUPPLEMENTAL_EVIDENCE_DATABASE");
          result = Object.freeze({ ok: true as const, duplicate: true, tupleDigest: p.tupleDigest, receiptCore: core });
          return;
        }
        const committedAt = this.now();
        if (!validTime(committedAt)) throw new Error("ERR_SUPPLEMENTAL_EVIDENCE_DATABASE");
        const receiptCore: ReceiptCore = Object.freeze({ domain: RECEIPT_CORE_DOMAIN, disposition: EVIDENCE_ONLY_DISPOSITION,
          receiptId, tupleDigest: p.tupleDigest, terminalRevision: p.tuple.terminalRevision,
          consentBindingDigest: p.consentBindingDigest, committedAt });
        this.db.prepare(`INSERT INTO supplemental_native_evidence
          (tuple_digest,tuple_json,payload_bytes,payload_digest,response_bytes,response_digest,response_byte_length,
           owner_id,session_binding_digest,credential_version,host_certificate_binding_digest,consent_action,consent_disposition,consented_at,
           consent_json,consent_binding_digest,receipt_core_json,committed_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
          .run(p.tupleDigest,p.tupleJson,p.payloadBytes,p.payloadDigest,p.responseBytes,p.tuple.responseDigest,p.responseBytes.length,
            p.consent.ownerId,p.consent.sessionBindingDigest,p.consent.credentialVersion,p.consent.hostCertificateBindingDigest,
            p.consent.action,p.consent.disposition,p.consent.consentedAt,p.consentJson,p.consentBindingDigest,JSON.stringify(receiptCore),committedAt);
        tx.audit.append({ actorKind: "system", actorId: "controller", action: "supplemental-native-evidence-append",
          outcome: "succeeded", requestId: p.tuple.requestId, jobId: p.tuple.jobId, hostId: p.tuple.hostId,
          details: { tupleDigest: p.tupleDigest, receiptId, disposition: EVIDENCE_ONLY_DISPOSITION,
            consentBindingDigest: p.consentBindingDigest }, occurredAt: committedAt });
        result = Object.freeze({ ok: true as const, duplicate: false, tupleDigest: p.tupleDigest, receiptCore });
      });
      return result ?? fixedFailure("ERR_SUPPLEMENTAL_EVIDENCE_DATABASE");
    } catch (error) {
      // withAuditTransaction rolls back mutation failures; SQLite can still leave
      // a transaction open when COMMIT itself fails (for example a deferred FK).
      // Attempt cleanup on this same owned connection, tolerating an already-closed
      // transaction, so commit failures cannot leave the evidence row visible.
      try { this.db.exec("ROLLBACK"); } catch { /* transaction already rolled back or closed */ }
      if (error instanceof Error && error.message === "ERR_SUPPLEMENTAL_EVIDENCE_CONFLICT") return fixedFailure("ERR_SUPPLEMENTAL_EVIDENCE_CONFLICT");
      return fixedFailure("ERR_SUPPLEMENTAL_EVIDENCE_DATABASE");
    }
  }
}
