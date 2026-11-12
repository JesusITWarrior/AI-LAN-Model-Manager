import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import {
  canonicalCertificateSerial, commandAuthorizationDigest, parseCertificateAuthorityMetadata,
  parseCommandRequest, parseCommandResponse, parseHostCertificateMetadata, parseJobSnapshot,
  parseStreamWireJSON, parseUtcTimestamp, responseMatches,
} from "@lan-model-manager/core";
import type { GuardResult } from "./guard.js";
import { isActiveCoupledContext } from "./jobs-store.js";
import {
  OwnerNativeEvidenceCandidateRegistry, type CandidateLeaseToken,
} from "./owner-native-evidence-candidates.js";
import { computeTerminalRevision } from "./native-terminal-revision.js";

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
      try {
        const tuple = view.tuple;
        if (tuple.domain !== EXPECTED_TUPLE_DOMAIN) return "mismatch";
        // Evaluate injected code before selecting any authoritative row. A clock
        // callback may reenter this connection; its changes must be in the snapshot.
        const now = this.options.clock?.() ?? new Date().toISOString();
        if (!canonicalTime(now) || !isActiveCoupledContext(tx, this.db)) return "mismatch";
        const jobs = all(this.db, "SELECT job_id,state,host_id,submitted_at,updated_at,attempt,idempotency_key,payload_json FROM jobs WHERE job_id=? LIMIT 2", tuple.jobId);
        if (jobs.length !== 1) return "mismatch";
        const j = jobs[0]!;
        if (typeof j.payload_json !== "string" || Buffer.byteLength(j.payload_json, "utf8") > MAX_JOB_JSON) return "mismatch";
        const parsedJob = parseJobSnapshot(strictWireJson(Buffer.from(j.payload_json, "utf8"), MAX_JOB_JSON));
        if (!parsedJob.ok) return "mismatch";
        const job = parsedJob.value, op = job.operation;
        if (op.jobId !== j.job_id || op.hostId !== j.host_id || op.submittedAt !== j.submitted_at || op.idempotencyKey !== j.idempotency_key ||
            job.state !== j.state || job.updatedAt !== j.updated_at || job.attempt !== Number(j.attempt) || !terminal.has(job.state) ||
            job.state !== tuple.terminalState || op.requestId !== tuple.requestId || op.hostId !== tuple.hostId) return "mismatch";

        const histories = all(this.db, "SELECT history_id,job_id,from_state,to_state,attempt,occurred_at,created_at FROM job_history WHERE job_id=? ORDER BY history_id DESC LIMIT 1", j.job_id);
        if (histories.length !== 1) return "mismatch";
        const h = histories[0]!;
        if (!Number.isSafeInteger(h.history_id) || Number(h.history_id) < 1 || h.job_id !== j.job_id || h.to_state !== j.state ||
            Number(h.attempt) !== job.attempt || h.occurred_at !== j.updated_at || typeof h.from_state !== "string" ||
            typeof h.occurred_at !== "string" || typeof h.created_at !== "string") return "mismatch";

        const queues = all(this.db, "SELECT job_id,host_id,request_json,request_digest,state,lease_until,result_json FROM agent_commands WHERE job_id=? AND host_id=? LIMIT 2", j.job_id, j.host_id);
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

        const certRows = all(this.db, "SELECT cert_id,serial,fingerprint,candidate_id,binding_address,binding_port,protocol_major,protocol_minor,spiffe_uri,certificate,not_before,not_after,ca_id,ca_version,challenge_id,transcript_digest,status,version,issued_at,revoked_at FROM host_certificates WHERE candidate_id=? AND status='active' AND revoked_at IS NULL LIMIT 2", j.host_id);
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
        const caRows = all(this.db, "SELECT ca_id,ca_version,serial,fingerprint,subject,certificate,not_before,not_after,created_at FROM certificate_authorities WHERE ca_id=? LIMIT 2", c.ca_id);
        if (caRows.length !== 1) return "mismatch";
        const caRow = caRows[0]!;
        const ca = parseCertificateAuthorityMetadata({ caId: caRow.ca_id, version: Number(caRow.ca_version), serial: caRow.serial,
          fingerprint: caRow.fingerprint, certificatePem: caRow.certificate, notBefore: caRow.not_before, notAfter: caRow.not_after, createdAt: caRow.created_at });
        if (!ca.ok || ca.value.caId !== c.ca_id || ca.value.version !== Number(c.ca_version) ||
            Date.parse(ca.value.notBefore) > Date.parse(now) || Date.parse(ca.value.notAfter) <= Date.parse(now)) return "mismatch";
        return "match";
      } catch { return "mismatch"; }
    });
  }
}
