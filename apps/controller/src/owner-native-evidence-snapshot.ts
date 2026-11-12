import { createHash, X509Certificate } from "node:crypto";
import { types } from "node:util";
import type { DatabaseSync } from "node:sqlite";
import { guardManagementRequest } from "./guard.js";
import type { SessionManager } from "./session-manager.js";
import { createAllowedOrigins } from "./origin.js";
import {
  canonicalCertificateSerial, sameCertificateSerial, commandAuthorizationDigest, parseCertificateAuthorityMetadata,
  parseCommandRequest, parseCommandResponse, parseHostCertificateMetadata, parseJobSnapshot,
  parseStreamWireJSON, parseUtcTimestamp, responseMatches,
} from "@lan-model-manager/core";
import type { GuardResult } from "./guard.js";
import { createJobStores, isActiveCoupledContext } from "./jobs-store.js";
import {
  OwnerNativeEvidenceCandidateRegistry, type CandidateLeaseToken,
} from "./owner-native-evidence-candidates.js";
import { computeTerminalRevision } from "./native-terminal-revision.js";
import { SupplementalNativeEvidenceRepository, EVIDENCE_ONLY_ACTION, EVIDENCE_ONLY_DISPOSITION, type AppendResult } from "./supplemental-native-evidence-repository.js";
import type { CoupledContext } from "./jobs-store.js";

const MAX_JOB_JSON = 64 * 1024;
// parseCommandRequest permits up to 512 KiB of inference.chat params, plus bounded envelope fields.
const MAX_COMMAND_JSON = 550_000;
const MAX_RESPONSE_BYTES = 512 * 1024;
const responseDomain = Buffer.from("lanmm-native-response-bytes-v1\0", "utf8");
const terminal = new Set(["succeeded", "failed", "timed-out", "cancelled"]);
const evidenceTerminal = new Set(["succeeded", "failed", "cancelled"]);
type Row = Record<string, unknown>;
const EXPECTED_TUPLE_DOMAIN = "lanmm-native-terminal-evidence-v1";
function strictWireJson(bytes: Uint8Array, max: number): unknown {
  const value = parseStreamWireJSON(bytes, max);
  const safe = (item: unknown): boolean => {
    if (typeof item === "number") return Number.isSafeInteger(item);
    if (Array.isArray(item)) return item.every(safe);
    if (item && typeof item === "object") return Object.values(item as Record<string, unknown>).every(safe);
    return true;
  };
  if (!safe(value)) throw new Error("ERR_SNAPSHOT_NUMBER");
  return value;
}
function canonicalTime(value: unknown): value is string {
  const parsed = parseUtcTimestamp(value);
  return parsed.ok && parsed.value === value;
}
function sameJson(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) || Array.isArray(b)) return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((v, i) => sameJson(v, b[i]));
  const left = Object.keys(a as Record<string, unknown>).sort(), right = Object.keys(b as Record<string, unknown>).sort();
  return left.length === right.length && left.every((key, i) => key === right[i] && sameJson((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key]));
}
const digest = (data: Uint8Array): string => createHash("sha256").update(data).digest("hex");
const all = (db: DatabaseSync, sql: string, ...args: unknown[]): Row[] => db.prepare(sql).all(...args as never[]) as Row[];

/** Read-only server snapshot comparison. All reads occur within the caller's live transaction. */
export class OwnerNativeEvidenceSnapshotReader {
  constructor(
    private readonly db: DatabaseSync,
    private readonly registry: OwnerNativeEvidenceCandidateRegistry,
    private readonly options: { readonly clock?: () => string } = {},
  ) {}

  read(guard: GuardResult, tx: unknown, token: CandidateLeaseToken) {
    if (!isActiveCoupledContext(tx, this.db)) return Object.freeze({ ok: false as const, error: "ERR_NATIVE_EVIDENCE_LEASE" as const });
    return this.registry.withLeaseView(guard, tx, token, view => {
      try { return compareCurrentSnapshot(this.db, tx, view, this.options.clock?.() ?? new Date().toISOString()); }
      catch { return "mismatch"; }
    });
  }

  /**
   * Read-only current DB-backed X.509 enrollment-trust facts. This does not
   * establish consent, append authority, fresh mTLS, remote-host possession,
   * historical proof, a native receipt, or an ACK.
   */
  readVerified(guard: GuardResult, tx: unknown, token: CandidateLeaseToken): VerifiedCurrentTrustResult {
    if (!isActiveCoupledContext(tx, this.db)) return Object.freeze({ ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" });
    let detached: VerifiedCurrentTrustSnapshot | null = null, authorityView: SnapshotComparisonView | null = null, sampledAt: string | null = null;
    const lease = this.registry.withLeaseView(guard, tx, token, view => {
      try {
        const now = this.options.clock?.() ?? new Date().toISOString();
        if (!canonicalTime(now) || !isActiveCoupledContext(tx, this.db) || compareCurrentSnapshot(this.db, tx, view, now) !== "match") return "mismatch";
        detached = verifyCurrentTrust(this.db, view, now);
        if (!detached) return "mismatch";
        authorityView = view;
        sampledAt = now;
        return "match";
      } catch { detached = null; authorityView = null; sampledAt = null; return "mismatch"; }
    });
    if (!lease.ok) return Object.freeze({ ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" });
    if (!lease.match || !detached || !authorityView || !sampledAt) return Object.freeze({ ok: true, match: false });
    // Registry postchecks invoke its own clock callback. That callback may
    // synchronously reenter this DB and rotate/revoke trust rows after the
    // callback's first verification. Re-read and re-verify only after those
    // postchecks, with no injected callback between this check and exposure.
    try {
      if (!isActiveCoupledContext(tx, this.db) || compareCurrentSnapshot(this.db, tx, authorityView, sampledAt) !== "match") return Object.freeze({ ok: true, match: false });
      const finalSnapshot = verifyCurrentTrust(this.db, authorityView, sampledAt);
      if (!finalSnapshot || JSON.stringify(finalSnapshot) !== JSON.stringify(detached)) return Object.freeze({ ok: true, match: false });
      return Object.freeze({ ok: true, match: true, snapshot: finalSnapshot });
    } catch { return Object.freeze({ ok: true, match: false }); }
  }
}


export type VerifiedCurrentTrustSnapshot = Readonly<{
  verdict: "verified_current_trust";
  verifiedAt: string;
  hostId: string;
  jobId: string;
  requestId: string;
  terminalRevision: string;
  hostCertificateId: string;
  hostCertificateVersion: number;
  certificateAuthorityId: string;
  certificateAuthorityVersion: number;
  hostCertificateBindingDigest: string;
}>;
export type VerifiedCurrentTrustResult =
  | Readonly<{ ok: false; error: "ERR_NATIVE_EVIDENCE_LEASE" }>
  | Readonly<{ ok: true; match: false }>
  | Readonly<{ ok: true; match: true; snapshot: VerifiedCurrentTrustSnapshot }>;

const MAX_CERTIFICATE_PEM_BYTES = 16_384;
const TRUST_DIGEST_DOMAIN = "lanmm-owner-current-trust-snapshot-v1\0";
function parsedTime(cert: X509Certificate, which: "validFrom" | "validTo"): string {
  const ms = Date.parse(cert[which]);
  if (!Number.isFinite(ms)) throw new Error("ERR_TRUST_CERT_TIME");
  return new Date(ms).toISOString();
}
function boundedPem(value: unknown): value is string {
  return typeof value === "string" && Buffer.byteLength(value, "utf8") <= MAX_CERTIFICATE_PEM_BYTES;
}
function verifyCurrentTrust(db: DatabaseSync, view: SnapshotComparisonView, now: string): VerifiedCurrentTrustSnapshot | null {
  const hostId = view.tuple.hostId;
  if (typeof hostId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(hostId)) return null;
  const hostRows = all(db, "SELECT cert_id,serial,fingerprint,candidate_id,binding_address,binding_port,protocol_major,protocol_minor,spiffe_uri,certificate,not_before,not_after,ca_id,ca_version,challenge_id,transcript_digest,status,version,issued_at,revoked_at FROM host_certificates WHERE candidate_id=? AND status='active' AND revoked_at IS NULL LIMIT 2", hostId);
  if (hostRows.length !== 1) return null;
  const row = hostRows[0]!;
  if (!boundedPem(row.certificate)) return null;
  const parsedHost = parseHostCertificateMetadata({ certificateId: row.cert_id, serial: row.serial, fingerprint: row.fingerprint, certificatePem: row.certificate,
    caId: row.ca_id, caVersion: Number(row.ca_version), binding: { candidateId: row.candidate_id, address: row.binding_address, port: Number(row.binding_port), protocolMajor: Number(row.protocol_major), protocolMinor: Number(row.protocol_minor) },
    spiffeUri: row.spiffe_uri, challengeId: row.challenge_id, transcriptDigest: row.transcript_digest, notBefore: row.not_before, notAfter: row.not_after,
    status: row.status, version: Number(row.version), issuedAt: row.issued_at, revokedAt: row.revoked_at });
  if (!parsedHost.ok || parsedHost.value.binding.candidateId !== hostId) return null;
  const host = parsedHost.value, assertion = view.certificateBindingAssertion;
  if (host.certificateId !== assertion.certificateId || !sameCertificateSerial(host.serial, assertion.serial) ||
      host.fingerprint !== assertion.fingerprint || host.version !== assertion.version || host.binding.address !== assertion.address ||
      host.binding.port !== assertion.port || host.binding.protocolMajor !== assertion.protocolMajor || host.binding.protocolMinor !== assertion.protocolMinor ||
      host.notBefore !== assertion.notBefore || host.notAfter !== assertion.notAfter || host.caId !== assertion.caId ||
      host.caVersion !== assertion.caVersion || host.spiffeUri !== assertion.spiffeUri) return null;
  const caRows = all(db, "SELECT ca_id,ca_version,serial,fingerprint,subject,certificate,not_before,not_after,created_at FROM certificate_authorities WHERE ca_id=? LIMIT 2", host.caId);
  if (caRows.length !== 1 || !boundedPem(caRows[0]!.certificate)) return null;
  const caRow = caRows[0]!;
  const parsedCa = parseCertificateAuthorityMetadata({ caId: caRow.ca_id, version: Number(caRow.ca_version), serial: caRow.serial,
    fingerprint: caRow.fingerprint, certificatePem: caRow.certificate, notBefore: caRow.not_before, notAfter: caRow.not_after, createdAt: caRow.created_at });
  if (!parsedCa.ok || parsedCa.value.version !== host.caVersion || typeof caRow.subject !== "string" || caRow.subject.length > 1024) return null;

  const leaf = new X509Certificate(host.certificatePem), ca = new X509Certificate(parsedCa.value.certificatePem);
  const nowMs = Date.parse(now), leafFrom = parsedTime(leaf, "validFrom"), leafTo = parsedTime(leaf, "validTo"), caFrom = parsedTime(ca, "validFrom"), caTo = parsedTime(ca, "validTo");
  const leafFingerprint = createHash("sha256").update(leaf.raw).digest("hex"), caFingerprint = createHash("sha256").update(ca.raw).digest("hex");
  const leafSerial = canonicalCertificateSerial(leaf.serialNumber.toUpperCase()), caSerial = canonicalCertificateSerial(ca.serialNumber.toUpperCase());
  const san = leaf.subjectAltName ?? "", expectedUri = `spiffe://lanmodelmanager/host/${host.binding.candidateId}`;
  const usage = leaf.keyUsage ?? [];
  if (!ca.ca || ca.issuer !== ca.subject || ca.subject !== caRow.subject || !ca.verify(ca.publicKey) || leaf.ca || !leaf.verify(ca.publicKey) || leaf.issuer !== ca.subject ||
      caFingerprint !== parsedCa.value.fingerprint || caFingerprint !== parsedCa.value.caId || caSerial === null || !sameCertificateSerial(caSerial, parsedCa.value.serial) ||
      caFrom !== parsedCa.value.notBefore || caTo !== parsedCa.value.notAfter || nowMs < Date.parse(caFrom) || nowMs >= Date.parse(caTo) ||
      leafFingerprint !== host.fingerprint || leafFingerprint !== host.certificateId || leafSerial === null || !sameCertificateSerial(leafSerial, host.serial) ||
      leafFrom !== host.notBefore || leafTo !== host.notAfter || nowMs < Date.parse(leafFrom) || nowMs >= Date.parse(leafTo) ||
      leaf.subject !== `CN=${host.binding.candidateId}` || san !== `IP Address:${host.binding.address}, URI:${expectedUri}` || host.spiffeUri !== expectedUri ||
      !usage.includes("1.3.6.1.5.5.7.3.1") || !usage.includes("1.3.6.1.5.5.7.3.2")) return null;

  const projection = {
    host: { id: host.certificateId, version: host.version, status: host.status, serial: canonicalCertificateSerial(host.serial), fingerprint: host.fingerprint,
      candidateId: host.binding.candidateId, address: host.binding.address, port: host.binding.port, protocolMajor: host.binding.protocolMajor,
      protocolMinor: host.binding.protocolMinor, spiffeUri: host.spiffeUri, notBefore: host.notBefore, notAfter: host.notAfter },
    ca: { id: parsedCa.value.caId, version: parsedCa.value.version, serial: canonicalCertificateSerial(parsedCa.value.serial), fingerprint: parsedCa.value.fingerprint,
      notBefore: parsedCa.value.notBefore, notAfter: parsedCa.value.notAfter },
    crypto: { leafSubject: leaf.subject, leafIssuer: leaf.issuer, leafSubjectAltName: san, leafKeyUsage: [...usage].sort(), leafIsCa: leaf.ca,
      caSubject: ca.subject, caIsCa: ca.ca, caSelfSignatureVerified: true, leafSignatureVerified: true },
  };
  const hostCertificateBindingDigest = createHash("sha256").update(TRUST_DIGEST_DOMAIN, "utf8").update(JSON.stringify(projection), "utf8").digest("hex");
  return Object.freeze({ verdict: "verified_current_trust", verifiedAt: now, hostId: view.tuple.hostId, jobId: view.tuple.jobId,
    requestId: view.tuple.requestId, terminalRevision: view.tuple.terminalRevision, hostCertificateId: host.certificateId, hostCertificateVersion: host.version,
    certificateAuthorityId: parsedCa.value.caId, certificateAuthorityVersion: parsedCa.value.version, hostCertificateBindingDigest });
}

type SnapshotComparisonView = Readonly<{
  tuple: import("./owner-native-evidence-candidates.js").NativeEvidenceCandidateTuple;
  responseBytes: Uint8Array;
  certificateBindingAssertion: import("./owner-native-evidence-candidates.js").NativeEvidenceCertificateAssertion;
  serverBinding: Readonly<{ ownerId: string; sessionId: string; credentialVersion: number; expiresAt: string }>;
}>;
function compareCurrentSnapshot(db: DatabaseSync, tx: unknown, view: SnapshotComparisonView, now: string): "match" | "mismatch" {
  try {
    const tuple = view.tuple;
    if (tuple.domain !== EXPECTED_TUPLE_DOMAIN) return "mismatch";
    // Evaluate injected code before selecting any authoritative row. A clock
    // callback may reenter this connection; its changes must be in the snapshot.
    if (!canonicalTime(now) || !isActiveCoupledContext(tx, db)) return "mismatch";
    const jobs = all(db, "SELECT job_id,state,host_id,submitted_at,updated_at,attempt,idempotency_key,payload_json FROM jobs WHERE job_id=? LIMIT 2", tuple.jobId);
    if (jobs.length !== 1) return "mismatch";
    const j = jobs[0]!;
    if (typeof j.payload_json !== "string" || Buffer.byteLength(j.payload_json, "utf8") > MAX_JOB_JSON) return "mismatch";
    const parsedJob = parseJobSnapshot(strictWireJson(Buffer.from(j.payload_json, "utf8"), MAX_JOB_JSON));
    if (!parsedJob.ok) return "mismatch";
    const job = parsedJob.value, op = job.operation;
    if (op.jobId !== j.job_id || op.hostId !== j.host_id || op.submittedAt !== j.submitted_at || op.idempotencyKey !== j.idempotency_key ||
        job.state !== j.state || job.updatedAt !== j.updated_at || job.attempt !== Number(j.attempt) || !terminal.has(job.state) ||
        job.state !== tuple.terminalState || op.requestId !== tuple.requestId || op.hostId !== tuple.hostId) return "mismatch";

    const histories = all(db, "SELECT history_id,job_id,from_state,to_state,attempt,occurred_at,created_at FROM job_history WHERE job_id=? ORDER BY history_id DESC LIMIT 1", j.job_id);
    if (histories.length !== 1) return "mismatch";
    const h = histories[0]!;
    if (!Number.isSafeInteger(h.history_id) || Number(h.history_id) < 1 || h.job_id !== j.job_id || h.to_state !== j.state ||
        Number(h.attempt) !== job.attempt || h.occurred_at !== j.updated_at || typeof h.from_state !== "string" ||
        typeof h.occurred_at !== "string" || typeof h.created_at !== "string") return "mismatch";

    const queues = all(db, "SELECT job_id,host_id,request_json,request_digest,state,lease_until,result_json FROM agent_commands WHERE job_id=? AND host_id=? LIMIT 2", j.job_id, j.host_id);
    if (queues.length !== 1) return "mismatch";
    const q = queues[0]!;
    if (typeof q.request_json !== "string" || Buffer.byteLength(q.request_json, "utf8") > MAX_COMMAND_JSON || typeof q.request_digest !== "string") return "mismatch";
    const requestRaw = strictWireJson(Buffer.from(q.request_json, "utf8"), MAX_COMMAND_JSON);
    const parsedRequest = parseCommandRequest(requestRaw);
    if (!parsedRequest.ok) return "mismatch";
    const request = parsedRequest.value;
    const storedDigest = digest(Buffer.from(JSON.stringify(request), "utf8"));
    const authorizationDigest = commandAuthorizationDigest(request);
    if (q.job_id !== j.job_id || q.host_id !== j.host_id || request.jobId !== j.job_id || request.hostId !== j.host_id ||
        request.requestId !== tuple.requestId || request.idempotencyKey !== tuple.idempotencyKey || request.sequence !== tuple.commandSequence ||
        request.capability.requestDigest !== authorizationDigest || q.request_digest !== storedDigest ||
        storedDigest !== tuple.storedQueueDigest || authorizationDigest !== tuple.authorizationRequestDigest) return "mismatch";
    const expectedAction = ["probe", "inventory", "estimate", "inference.chat"].includes(request.operation) ? "load" : request.operation;
    if (op.action !== expectedAction) return "mismatch";

    if (!(q.state === "queued" || q.state === "leased" || q.state === "completed" || q.state === "cancelled" || q.state === "expired")) return "mismatch";
    if (q.state === "leased") {
      const leaseUntil = parseUtcTimestamp(q.lease_until);
      if (!leaseUntil.ok) return "mismatch";
    } else if (q.lease_until !== null) return "mismatch";
    let storedResult: ReturnType<typeof parseCommandResponse> extends { ok: true; value: infer T } ? T | null : never = null as never;
    if (q.result_json !== null) {
      if (typeof q.result_json !== "string" || Buffer.byteLength(q.result_json, "utf8") > MAX_RESPONSE_BYTES) return "mismatch";
      const parsed = parseCommandResponse(strictWireJson(Buffer.from(q.result_json, "utf8"), MAX_RESPONSE_BYTES));
      if (!parsed.ok || !responseMatches(request, parsed.value) || !canonicalTime(parsed.value.observedAt)) return "mismatch";
      storedResult = parsed.value as never;
      const intermediate = parsed.value.status === "accepted" || parsed.value.status === "running";
      const storedTerminal = evidenceTerminal.has(parsed.value.status);
      if ((q.state === "completed") !== storedTerminal || (q.state !== "completed" && !intermediate)) return "mismatch";
    } else if (q.state === "completed") return "mismatch";

    const response = parseCommandResponse(strictWireJson(view.responseBytes, MAX_RESPONSE_BYTES));
    if (!response.ok || !responseMatches(request, response.value) || !canonicalTime(response.value.observedAt) || !evidenceTerminal.has(response.value.status) ||
        view.responseBytes.byteLength !== tuple.responseByteLength ||
        createHash("sha256").update(responseDomain).update(view.responseBytes).digest("hex") !== tuple.responseDigest ||
        tuple.evidenceKind !== response.value.status) return "mismatch";
    if (q.state === "completed" && !sameJson(storedResult, response.value)) return "mismatch";

    const revision = computeTerminalRevision({
      job: { jobId: String(j.job_id), requestId: op.requestId, state: job.state as "succeeded" | "failed" | "timed-out" | "cancelled",
        hostId: String(j.host_id), submittedAt: String(j.submitted_at), updatedAt: String(j.updated_at), attempt: job.attempt, idempotencyKey: String(j.idempotency_key) },
      history: { historyId: Number(h.history_id), jobId: String(h.job_id), fromState: String(h.from_state), toState: String(h.to_state) as "succeeded" | "failed" | "timed-out" | "cancelled",
        attempt: Number(h.attempt), occurredAt: String(h.occurred_at), createdAt: String(h.created_at) },
      binding: { jobId: request.jobId, hostId: request.hostId, requestId: request.requestId, operation: request.operation,
        idempotencyKey: request.idempotencyKey, sequence: request.sequence, deadline: request.deadline,
        storedQueueDigest: storedDigest, authorizationDigest },
    });
    if (!revision.ok || revision.revision !== tuple.terminalRevision || revision.state !== tuple.terminalState) return "mismatch";

    const certRows = all(db, "SELECT cert_id,serial,fingerprint,candidate_id,binding_address,binding_port,protocol_major,protocol_minor,spiffe_uri,certificate,not_before,not_after,ca_id,ca_version,challenge_id,transcript_digest,status,version,issued_at,revoked_at FROM host_certificates WHERE candidate_id=? AND status='active' AND revoked_at IS NULL LIMIT 2", j.host_id);
    if (certRows.length !== 1) return "mismatch";
    const c = certRows[0]!;
    const host = parseHostCertificateMetadata({ certificateId: c.cert_id, serial: c.serial, fingerprint: c.fingerprint, certificatePem: c.certificate,
      caId: c.ca_id, caVersion: Number(c.ca_version), binding: { candidateId: c.candidate_id, address: c.binding_address, port: Number(c.binding_port), protocolMajor: Number(c.protocol_major), protocolMinor: Number(c.protocol_minor) },
      spiffeUri: c.spiffe_uri, challengeId: c.challenge_id, transcriptDigest: c.transcript_digest, notBefore: c.not_before, notAfter: c.not_after,
      status: c.status, version: Number(c.version), issuedAt: c.issued_at, revokedAt: c.revoked_at });
    if (!host.ok) return "mismatch";
    const a = view.certificateBindingAssertion, m = host.value;
    if (m.certificateId !== a.certificateId || !canonicalCertificateSerial(m.serial) || canonicalCertificateSerial(m.serial) !== canonicalCertificateSerial(a.serial) ||
        m.fingerprint !== a.fingerprint || m.version !== a.version || m.binding.candidateId !== a.candidateId || m.binding.address !== a.address ||
        m.binding.port !== a.port || m.binding.protocolMajor !== a.protocolMajor || m.binding.protocolMinor !== a.protocolMinor ||
        m.notBefore !== a.notBefore || m.notAfter !== a.notAfter || m.caId !== a.caId || m.caVersion !== a.caVersion || m.spiffeUri !== a.spiffeUri) return "mismatch";
    if (Date.parse(m.notBefore) > Date.parse(now) || Date.parse(m.notAfter) <= Date.parse(now)) return "mismatch";
    const caRows = all(db, "SELECT ca_id,ca_version,serial,fingerprint,subject,certificate,not_before,not_after,created_at FROM certificate_authorities WHERE ca_id=? LIMIT 2", c.ca_id);
    if (caRows.length !== 1) return "mismatch";
    const caRow = caRows[0]!;
    const ca = parseCertificateAuthorityMetadata({ caId: caRow.ca_id, version: Number(caRow.ca_version), serial: caRow.serial,
      fingerprint: caRow.fingerprint, certificatePem: caRow.certificate, notBefore: caRow.not_before, notAfter: caRow.not_after, createdAt: caRow.created_at });
    if (!ca.ok || ca.value.caId !== c.ca_id || ca.value.version !== Number(c.ca_version) ||
        Date.parse(ca.value.notBefore) > Date.parse(now) || Date.parse(ca.value.notAfter) <= Date.parse(now)) return "mismatch";
    return "match";
  } catch { return "mismatch"; }
}

const CONSENT_ASSERTION_KEYS = ["hostCertificateBindingDigest", "consentedAt"] as const;
function consentAssertion(value: unknown): { hostCertificateBindingDigest: unknown; consentedAt: unknown } | null {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) return null;
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return null;
    const keys = Reflect.ownKeys(value), descriptors = Object.getOwnPropertyDescriptors(value);
    if (keys.length !== CONSENT_ASSERTION_KEYS.length || keys.some(k => typeof k !== "string" || !(CONSENT_ASSERTION_KEYS as readonly string[]).includes(k)) || CONSENT_ASSERTION_KEYS.some(k => !descriptors[k] || !("value" in descriptors[k]!))) return null;
    return { hostCertificateBindingDigest: descriptors.hostCertificateBindingDigest!.value, consentedAt: descriptors.consentedAt!.value };
  } catch { return null; }
}
export type MatchedAppendResult = Readonly<{ ok: true; match: boolean; append: AppendResult | null }> | Readonly<{ ok: false; error: "ERR_NATIVE_EVIDENCE_LEASE" }>;
const MATCHED_APPEND_ABORT = "ERR_NATIVE_EVIDENCE_MATCHED_APPEND_ABORT";
/**
 * Synthetic, opt-in assertion binding only: caller values are not consent or trust proof.
 * A returned append/receipt remains provisional until the caller transaction commits.
 * The caller must let ERR_NATIVE_EVIDENCE_MATCHED_APPEND_ABORT escape its transaction callback.
 */
export class OwnerNativeEvidenceMatchedAppendCoordinator {
  private readonly repository: SupplementalNativeEvidenceRepository;
  constructor(private readonly db: DatabaseSync, private readonly registry: OwnerNativeEvidenceCandidateRegistry) { this.repository = new SupplementalNativeEvidenceRepository(db); }
  append(guard: GuardResult, tx: unknown, token: CandidateLeaseToken, assertion: unknown): MatchedAppendResult {
    if (!isActiveCoupledContext(tx, this.db)) return Object.freeze({ ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" });
    const consent = consentAssertion(assertion);
    if (!consent) return Object.freeze({ ok: true, match: false, append: null });
    let appendAttempted = false, appendResult: AppendResult | null = null;
    const viewResult = this.registry.withLeaseView(guard, tx, token, view => {
      const now = new Date().toISOString();
      if (!canonicalTime(now) || !isActiveCoupledContext(tx, this.db)) return "mismatch";
      if (compareCurrentSnapshot(this.db, tx, view, now) !== "match") return "mismatch";
      if (typeof consent.hostCertificateBindingDigest !== "string" || !/^[0-9a-f]{64}$/.test(consent.hostCertificateBindingDigest) || !canonicalTime(consent.consentedAt)) return "mismatch";
      const input = { tuple: view.tuple, tupleDigest: view.tupleDigest, payloadBytes: view.payloadBytes, responseBytes: view.responseBytes, consent: {
        ownerId: view.serverBinding.ownerId, sessionBindingDigest: view.serverBinding.sessionId, credentialVersion: view.serverBinding.credentialVersion,
        hostCertificateBindingDigest: consent.hostCertificateBindingDigest, action: EVIDENCE_ONLY_ACTION, disposition: EVIDENCE_ONLY_DISPOSITION, consentedAt: consent.consentedAt } };
      appendAttempted = true;
      appendResult = this.repository.appendInTransaction(tx as CoupledContext, input);
      return "match";
    });
    if (appendAttempted && !(viewResult.ok && viewResult.match)) throw new Error(MATCHED_APPEND_ABORT);
    return viewResult.ok ? Object.freeze({ ok: true, match: viewResult.match, append: appendResult }) : Object.freeze({ ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" });
  }
}

export type OwnerNativeEvidenceTransactionOutcome =
  | Readonly<{ outcome: "committed_append_settled" }>
  | Readonly<{ outcome: "committed_append_unsettled" }>
  | Readonly<{ outcome: "committed_no_append" }>
  | Readonly<{ outcome: "transaction_unknown" }>;

/**
 * Synthetic transaction owner. Normal return from the owned transaction is the
 * only commit signal; assertion values still are not consent or trust proof.
 */
export class OwnerNativeEvidenceTransactionOwner {
  private readonly stores: ReturnType<typeof createJobStores>;
  private readonly coordinator: OwnerNativeEvidenceMatchedAppendCoordinator;

  constructor(private readonly db: DatabaseSync, private readonly registry: OwnerNativeEvidenceCandidateRegistry) {
    this.stores = createJobStores(db);
    this.coordinator = new OwnerNativeEvidenceMatchedAppendCoordinator(db, registry);
  }

  append(guard: GuardResult, token: CandidateLeaseToken, assertion: unknown): OwnerNativeEvidenceTransactionOutcome {
    let result: MatchedAppendResult | undefined;
    try {
      this.stores.withAuditTransaction(tx => {
        result = this.coordinator.append(guard, tx, token, assertion);
      });
    } catch {
      // A throw at any point, including COMMIT, is deliberately non-success.
      return Object.freeze({ outcome: "transaction_unknown" });
    }
    if (!result?.ok || !result.match || !result.append?.ok) {
      return Object.freeze({ outcome: "committed_no_append" });
    }
    try {
      const settlement = this.registry.commitLease(guard, token);
      return Object.freeze({ outcome: settlement.ok ? "committed_append_settled" : "committed_append_unsettled" });
    } catch {
      return Object.freeze({ outcome: "committed_append_unsettled" });
    }
  }
}

const OWNER_CONFIRM_ABORT = "ERR_OWNER_CONFIRM_ABORT";
const OWNER_CONFIRM_PATH = "/api/v1/native-evidence/confirm";
const OWNER_CONFIRM_MAX_BODY = 4096;
export type OwnerConfirmResult = Readonly<{ outcome: "stored" | "already_stored" | "conflict" | "stale" | "denied" | "transaction_unknown" | "committed_unsettled"; tupleDigest?: string }>;
function exactOwnData(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) return null;
  try {
    const proto = Object.getPrototypeOf(value), own = Reflect.ownKeys(value), descriptors = Object.getOwnPropertyDescriptors(value);
    if ((proto !== Object.prototype && proto !== null) || own.length !== keys.length || own.some(k => typeof k !== "string" || !keys.includes(k))) return null;
    const result = Object.create(null) as Record<string, unknown>;
    for (const key of keys) { const descriptor = descriptors[key]; if (!descriptor || !("value" in descriptor)) return null; result[key] = descriptor.value; }
    return result;
  } catch { return null; }
}
function confirmResult(outcome: OwnerConfirmResult["outcome"], tupleDigest?: string): OwnerConfirmResult {
  return Object.freeze(tupleDigest ? { outcome, tupleDigest } : { outcome });
}
function finalOwnerSessionCheck(db: DatabaseSync, session: import("./session-types.js").SessionMetadata,
  binding: Readonly<{ ownerId: string; sessionId: string; credentialVersion: number; expiresAt: string }>, now: string): boolean {
  // This is deliberately plain SQL after registry/session callbacks have all returned.
  // SessionManager keeps the token digest private, so match its immutable metadata and
  // require a unique persisted row; ambiguity fails closed rather than guessing a token.
  if (session.ownerId !== binding.ownerId || session.credentialVersion !== binding.credentialVersion ||
      session.revokedAt !== null || !canonicalTime(now)) return false;
  const owner = db.prepare("SELECT disabled,credential_version FROM owners WHERE owner_id=? LIMIT 2").all(session.ownerId) as Row[];
  if (owner.length !== 1 || owner[0]!.disabled !== 0 || Number(owner[0]!.credential_version) !== binding.credentialVersion) return false;
  const rows = db.prepare("SELECT session_digest,credential_version,session_version,created_at,last_seen_at,absolute_expires_at,idle_expires_at,revoked_at FROM sessions WHERE owner_id=? AND credential_version=? AND session_version=? AND created_at=? AND last_seen_at=? AND absolute_expires_at=? AND idle_expires_at=?").all(
    session.ownerId, session.credentialVersion, session.sessionVersion, session.createdAt, session.lastSeenAt, session.absoluteExpiresAt, session.idleExpiresAt) as Row[];
  const exact = rows.filter(row => typeof row.session_digest === "string" && /^[a-f0-9]{64}$/.test(row.session_digest) &&
    createHash("sha256").update(`owner-lifecycle-session:${row.session_digest}:${row.credential_version}`).digest("hex") === binding.sessionId);
  if (exact.length !== 1 || exact[0]!.revoked_at !== null || exact[0]!.credential_version !== session.credentialVersion ||
      exact[0]!.session_version !== session.sessionVersion || exact[0]!.created_at !== session.createdAt || exact[0]!.last_seen_at !== session.lastSeenAt ||
      exact[0]!.absolute_expires_at !== session.absoluteExpiresAt || exact[0]!.idle_expires_at !== session.idleExpiresAt) return false;
  const expiresAt = new Date(Math.min(Date.parse(session.absoluteExpiresAt), Date.parse(session.idleExpiresAt))).toISOString();
  return expiresAt === binding.expiresAt && Date.parse(now) < Date.parse(expiresAt);
}

/** Server-owned, explicit POST boundary. This service is not itself an HTTP route. */
export class OwnerNativeEvidenceOwnerConfirmService {
  private readonly stores: ReturnType<typeof createJobStores>;
  private readonly origins: readonly string[];
  constructor(private readonly db: DatabaseSync, private readonly registry: OwnerNativeEvidenceCandidateRegistry,
    private readonly sessions: SessionManager, allowedOrigins: readonly string[], private readonly clock: () => string = () => new Date().toISOString()) {
    this.origins = createAllowedOrigins([...allowedOrigins]);
    this.stores = createJobStores(db);
  }

  confirm(request: unknown): OwnerConfirmResult {
    const envelope = exactOwnData(request, ["method", "path", "cookieHeader", "originHeader", "csrfHeader", "body"]);
    if (!envelope || envelope.method !== "POST" || envelope.path !== OWNER_CONFIRM_PATH ||
        typeof envelope.cookieHeader !== "string" || envelope.cookieHeader.length > 4096 || (envelope.originHeader !== null && (typeof envelope.originHeader !== "string" || envelope.originHeader.length > 2048)) ||
        (envelope.csrfHeader !== null && (typeof envelope.csrfHeader !== "string" || envelope.csrfHeader.length > 128)) || typeof envelope.body !== "string" ||
        Buffer.byteLength(envelope.body, "utf8") > OWNER_CONFIRM_MAX_BODY) return confirmResult("denied");
    let body: Record<string, unknown> | null = null;
    try { body = exactOwnData(strictWireJson(Buffer.from(envelope.body, "utf8"), OWNER_CONFIRM_MAX_BODY), ["candidateHandle", "expectedTupleDigest", "action", "disposition"]); } catch { /* fixed denial */ }
    if (!body || typeof body.candidateHandle !== "string" || !/^[\x21-\x7e]{1,128}$/.test(body.candidateHandle) ||
        typeof body.expectedTupleDigest !== "string" || !/^[a-f0-9]{64}$/.test(body.expectedTupleDigest) ||
        body.action !== EVIDENCE_ONLY_ACTION || body.disposition !== EVIDENCE_ONLY_DISPOSITION) return confirmResult("denied");
    const guard = guardManagementRequest(this.sessions, this.origins, { method: envelope.method, cookieHeader: envelope.cookieHeader,
      originHeader: envelope.originHeader, csrfHeader: envelope.csrfHeader });
    if (!guard.ok) return confirmResult("denied");
    const observed = this.registry.inspect(guard, body.candidateHandle);
    if (!observed.ok || observed.summary.tupleDigest !== body.expectedTupleDigest) return confirmResult("stale");
    const claimed = this.registry.claim(guard, { handle: body.candidateHandle, action: EVIDENCE_ONLY_ACTION, disposition: EVIDENCE_ONLY_DISPOSITION });
    if (!claimed.ok) return confirmResult("stale");
    const token = claimed.token;
    let sampledAt = "", attempted = false, callbackComplete = false;
    const state: { appendResult: AppendResult | null; captured: { view: SnapshotComparisonView; trust: VerifiedCurrentTrustSnapshot } | null } = { appendResult: null, captured: null };
    const repository = new SupplementalNativeEvidenceRepository(this.db, () => sampledAt);
    try {
      this.stores.withAuditTransaction(tx => {
        sampledAt = this.clock();
        if (!canonicalTime(sampledAt)) throw new Error(OWNER_CONFIRM_ABORT);
        const lease = this.registry.withLeaseView(guard, tx, token, view => {
          if (view.tupleDigest !== body!.expectedTupleDigest || compareCurrentSnapshot(this.db, tx, view, sampledAt) !== "match") return "mismatch";
          const trust = verifyCurrentTrust(this.db, view, sampledAt);
          if (!trust) return "mismatch";
          const prior = this.db.prepare("SELECT consented_at FROM supplemental_native_evidence WHERE tuple_digest=?").get(view.tupleDigest) as { consented_at: unknown } | undefined;
          const priorTime = prior && canonicalTime(prior.consented_at) ? prior.consented_at : null;
          const consentedAt = priorTime ?? sampledAt;
          const input = { tuple: view.tuple, tupleDigest: view.tupleDigest, payloadBytes: view.payloadBytes, responseBytes: view.responseBytes,
            consent: { ownerId: view.serverBinding.ownerId, sessionBindingDigest: view.serverBinding.sessionId,
              credentialVersion: view.serverBinding.credentialVersion, hostCertificateBindingDigest: trust.hostCertificateBindingDigest,
              action: EVIDENCE_ONLY_ACTION, disposition: EVIDENCE_ONLY_DISPOSITION, consentedAt } };
          state.captured = { view, trust };
          attempted = true;
          try { state.appendResult = repository.appendInTransaction(tx as CoupledContext, input); }
          catch (error) {
            if (error instanceof Error && error.message === "ERR_SUPPLEMENTAL_EVIDENCE_CONFLICT") {
              state.appendResult = Object.freeze({ ok: false as const, code: "ERR_SUPPLEMENTAL_EVIDENCE_CONFLICT" as const });
              return "match";
            }
            throw error;
          }
          return "match";
        });
        if (attempted && !(lease.ok && lease.match)) throw new Error(OWNER_CONFIRM_ABORT);
        if (!lease.ok || !lease.match) { callbackComplete = true; return; }
        // All callback-capable registry/session checks are complete. Re-read only SQLite facts now.
        const final = state.captured;
        if (!final || !finalOwnerSessionCheck(this.db, guard.session, final.view.serverBinding, sampledAt) ||
            compareCurrentSnapshot(this.db, tx, final.view, sampledAt) !== "match") throw new Error(OWNER_CONFIRM_ABORT);
        const finalTrust = verifyCurrentTrust(this.db, final.view, sampledAt);
        if (!finalTrust || JSON.stringify(finalTrust) !== JSON.stringify(final.trust)) throw new Error(OWNER_CONFIRM_ABORT);
        callbackComplete = true;
      });
    } catch {
      // The transaction wrapper does not report whether rollback itself succeeded.
      // A thrown callback/COMMIT therefore leaves both DB and lease outcome unknown.
      return confirmResult("transaction_unknown");
    }
    if (!callbackComplete) {
      try { this.registry.releaseLease(guard, token); } catch { /* fixed stale result */ }
      return confirmResult("stale");
    }
    const appendResult = state.appendResult;
    if (!appendResult?.ok) {
      try { this.registry.releaseLease(guard, token); } catch { /* known no-append transaction */ }
      return confirmResult(appendResult?.code === "ERR_SUPPLEMENTAL_EVIDENCE_CONFLICT" ? "conflict" : "stale");
    }
    let settled = false;
    try { settled = this.registry.commitLease(guard, token).ok; } catch { /* committed state remains truthful */ }
    if (!settled) return confirmResult("committed_unsettled", appendResult.tupleDigest);
    return confirmResult(appendResult.duplicate ? "already_stored" : "stored", appendResult.tupleDigest);
  }
}
