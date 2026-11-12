import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { commandAuthorizationDigest, parseCommandRequest, type CommandRequest } from "@lan-model-manager/core";
import { CONTROLLER_MIGRATIONS, migrateControllerDatabase, openControllerDatabase } from "./database.js";
import { decodeNativeTerminalEvidence, encodeNativeTerminalEvidence, MAX_EVIDENCE_RESPONSE_BYTES } from "./native-terminal-evidence-codec.js";
import { SupplementalNativeEvidenceRepository, EVIDENCE_MAX_PAYLOAD_BYTES, EVIDENCE_MAX_RESPONSE_BYTES, type EvidenceTuple, type SupplementalEvidenceInput } from "./supplemental-native-evidence-repository.js";
import { createJobStores, type CoupledContext } from "./jobs-store.js";

const NOW = "2026-11-11T19:00:00.000Z";
// These hashes are the immutable migration ledger checksums from committed baseline
// 8a5b9a6e4bb0eb85ddf3ca9fa2b4259ab8e39a10, not values captured from the candidate.
const BASELINE_MIGRATION_CHECKSUMS_1_TO_18 = [
  "4329948742a7560ca654fdd0fe076aa2e503150cbc4835b099011e5a0209faa0",
  "5a7f1cb743c39557d94f6610c094727690476e96a288b5dc1c051456f48bd1ef",
  "00b4141acc8ed6d251aade3213c43eb4c818be57a1c1d31c03759cf2119bea3d",
  "a1570861e67748e877929be958c3a93d813d03a9fecef1e2f08d93c2854272da",
  "4c5d8a818963dc82fa6b64d4e0c2385ba3e5d25eb1acb8601026063cd22c5e86",
  "6b441582433a647c4fceffba33d7458f721f8e0880d4f3863a127c4bb6cd6561",
  "26ed19a4241ed604717918c29fa7dd3a11c8081eabaf289337463cbf79344474",
  "c41abf1deaee8be1a232f153fb31bdf4575a3368d27a127787bdc552d9083b8e",
  "6ef8c8f6bf6c952cc8bb60c9a88cc9f70d1e5a67bf75704e2e933d5e0ef02a72",
  "84e0b665bca0e45e3a7a1516d3f4543c97d3b7e910069dbd84848843a2ef741a",
  "f784679afa036d0600422df07c9902667eed026a8bff2586be3f259ea17d3c32",
  "84346d49c6c78e4c7fa9767061ca8fd29403aea0839686e625c6c4aa164f1713",
  "e56af9f18933939c25e46e569ff2cf5bfbd7b80166f8ea57ff5ce2c980e97ae9",
  "5b8ef8e0b538c4be1fe87091029d1396ce590e945b56309de331a53425876d7f",
  "393b251e9ca76c68b8d9e6399b049c58636d4c45c38afc948dfc14506e9d2cfb",
  "3ff48fe4ff900daba02f600cdd8ec420f2fd5290953aa415ce8f4854a9a50187",
  "913aedfc7a0d7bf65306d7c6b38ca1ee8cad963a8cd0402b2465cd452125b3b3",
  "230268288fd4eee541ec2d37b72f223ce8d4ee99613c5c88804107b75342aaec",
] as const;
const TUPLE_KEYS = ["domain", "hostId", "jobId", "requestId", "commandSequence", "idempotencyKey", "authorizationRequestDigest",
  "storedQueueDigest", "terminalState", "terminalRevision", "responseDigest", "responseByteLength", "evidenceKind", "holdClass"] as const;
const hash = (domain: string, value: Uint8Array | string) => createHash("sha256").update(domain, "utf8").update(value).digest("hex");

/** Test-only positive vector generated AND decoded by the accepted offline codec. */
function candidate(responsePadding = 0): SupplementalEvidenceInput {
  const request: CommandRequest = { requestId: "request-1", jobId: "job-1", hostId: "host-1", operation: "load",
    idempotencyKey: "idem-1", sequence: 4, deadline: NOW,
    capability: { operation: "model-load", targetKind: "model", targetId: "model-1", hostId: "host-1", modelId: "model-1",
      requestDigest: "", expiresAt: NOW }, params: { modelId: "model-1", providerId: "ollama-1", model: "model:1" } };
  (request.capability as { requestDigest: string }).requestDigest = commandAuthorizationDigest(request);
  const parsed = parseCommandRequest(request); assert.ok(parsed.ok);
  const response = { requestId: "request-1", jobId: "job-1", hostId: "host-1", sequence: 4, status: "failed",
    progress: null, observedAt: NOW, observation: { result: "synthetic failure evidence" }, errorCode: "ADAPTER_FAILED" };
  const json = Buffer.from(JSON.stringify(response), "utf8");
  const responseBytes = responsePadding ? Buffer.concat([json, Buffer.alloc(responsePadding, 0x20)]) : json;
  const snapshot = { storedRequest: parsed.value, storedQueueDigest: createHash("sha256").update(JSON.stringify(parsed.value), "utf8").digest("hex"),
    terminal: { hostId: "host-1", jobId: "job-1", requestId: "request-1", state: "timed-out" as const, revision: "history-1", occurredAt: NOW },
    native: { kind: "response" as const, responseBytes, authorizationDigest: request.capability.requestDigest, source: "synthetic" as const },
    runnerHold: "pending_uncertain" as const, currentTrust: { provenance: "unverified" as const, hostId: "host-1", bindingRevision: "binding-1" } };
  const encoded = encodeNativeTerminalEvidence(snapshot); assert.equal(encoded.ok, true);
  if (!encoded.ok) throw new Error("accepted codec rejected the positive test vector");
  const payloadBytes = Buffer.from(encoded.payloadBase64, "base64");
  const decoded = decodeNativeTerminalEvidence(payloadBytes, snapshot); assert.equal(decoded.ok, true);
  if (!decoded.ok) throw new Error("accepted codec failed to decode its generated vector");
  return { payloadBytes, responseBytes, tuple: encoded.payload.tuple, tupleDigest: encoded.tupleDigest,
    consent: { ownerId: "owner-1", sessionBindingDigest: "d".repeat(64), credentialVersion: 3,
      hostCertificateBindingDigest: "e".repeat(64), action: "append-supplemental-native-evidence", disposition: "evidence-only", consentedAt: NOW } };
}
function setup() {
  const db = new DatabaseSync(":memory:");
  const schema = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "supplemental-native-evidence-test-schema.sql"), "utf8");
  db.exec(schema);
  db.prepare("INSERT INTO jobs(job_id,payload_json) VALUES(?,?)").run("job-1", '{"state":"timed-out"}');
  db.prepare("INSERT INTO job_history(history_id,job_id,event_json) VALUES(?,?,?)").run(7, "job-1", '{"state":"timed-out","attempt":2}');
  db.prepare("INSERT INTO agent_commands(job_id,result_json) VALUES(?,?)").run("job-1", '{"status":"completed","result":"unchanged"}');
  return { db, repo: new SupplementalNativeEvidenceRepository(db, () => NOW) };
}

test("production migration 19 proves baseline compatibility, atomic rollback, duplicate/conflict behavior, and append-only guards", () => {
  const db = new DatabaseSync(":memory:");
  try {
    assert.equal(CONTROLLER_MIGRATIONS.length, 19);
    assert.deepEqual(CONTROLLER_MIGRATIONS.slice(0, 18).map(m => m.checksum), BASELINE_MIGRATION_CHECKSUMS_1_TO_18);
    const priorMigrations = CONTROLLER_MIGRATIONS.slice(0, 18);
    migrateControllerDatabase(db, priorMigrations);
    const priorLedger = db.prepare("SELECT version,name,checksum FROM schema_migrations ORDER BY version").all();
    assert.deepEqual(priorLedger.map(row => (row as { checksum: string }).checksum), BASELINE_MIGRATION_CHECKSUMS_1_TO_18);
    assert.equal((db.prepare("PRAGMA user_version").get() as { user_version: number }).user_version, 18);
    db.prepare("INSERT INTO hosts VALUES(?,?,?,?,?,?,?,?,?)").run("host-before-upgrade", "Synthetic", "linux", NOW, 0, "offline", "{}", NOW, NOW);
    const priorHost = db.prepare("SELECT * FROM hosts WHERE host_id=?").get("host-before-upgrade");

    migrateControllerDatabase(db, CONTROLLER_MIGRATIONS);
    assert.deepEqual(db.prepare("SELECT version,name,checksum FROM schema_migrations WHERE version<=18 ORDER BY version").all(), priorLedger);
    assert.equal((db.prepare("PRAGMA user_version").get() as { user_version: number }).user_version, 19);
    assert.deepEqual(db.prepare("SELECT * FROM hosts WHERE host_id=?").get("host-before-upgrade"), priorHost);
    const columns = (db.prepare("PRAGMA table_info(supplemental_native_evidence)").all() as Array<{ name: string }>).map(row => row.name);
    assert.deepEqual(columns, ["tuple_digest", "tuple_json", "payload_bytes", "payload_digest", "response_bytes", "response_digest",
      "response_byte_length", "owner_id", "session_binding_digest", "credential_version", "host_certificate_binding_digest",
      "consent_action", "consent_disposition", "consented_at", "consent_json", "consent_binding_digest", "receipt_core_json", "committed_at"]);
    assert.equal(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='evidence_commit_guard'").get(), undefined);

    const repo = new SupplementalNativeEvidenceRepository(db, () => NOW);
    seedProtectedProductionRows(db);
    const protectedBefore = lifecycleSnapshot(db);
    db.exec("PRAGMA recursive_triggers=OFF");
    assert.equal((db.prepare("PRAGMA recursive_triggers").get() as { recursive_triggers: number }).recursive_triggers, 0);

    // The audit append happens after evidence INSERT in the same repository transaction.
    // Force that second mutation to fail and prove neither mutation nor protected data survives.
    db.exec("CREATE TRIGGER reject_production_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit failure canary'); END;");
    assert.deepEqual(repo.append(candidate()), { ok: false, code: "ERR_SUPPLEMENTAL_EVIDENCE_DATABASE" });
    assert.deepEqual(counts(db), { evidence: 0, audit: 0 });
    assert.equal(lifecycleSnapshot(db), protectedBefore);
    db.exec("DROP TRIGGER reject_production_audit");

    const input = candidate();
    const first = repo.append(input);
    assert.equal(first.ok, true);
    if (!first.ok) return;
    assert.equal(first.duplicate, false);
    const evidenceAfterFirst = evidenceSnapshot(db), auditAfterFirst = JSON.stringify(db.prepare("SELECT * FROM audit_events ORDER BY seq").all());
    const duplicate = repo.append(input);
    assert.equal(duplicate.ok, true);
    if (!duplicate.ok) return;
    assert.equal(duplicate.duplicate, true);
    assert.deepEqual(duplicate.receiptCore, first.receiptCore);
    assert.deepEqual(counts(db), { evidence: 1, audit: 1 });
    assert.equal(evidenceSnapshot(db), evidenceAfterFirst);
    assert.equal(JSON.stringify(db.prepare("SELECT * FROM audit_events ORDER BY seq").all()), auditAfterFirst);
    const evidenceBeforeConflict = evidenceSnapshot(db), auditBeforeConflict = JSON.stringify(db.prepare("SELECT * FROM audit_events ORDER BY seq").all());
    assert.deepEqual(repo.append({ ...input, consent: { ...input.consent, sessionBindingDigest: "f".repeat(64) } }),
      { ok: false, code: "ERR_SUPPLEMENTAL_EVIDENCE_CONFLICT" });
    assert.deepEqual(counts(db), { evidence: 1, audit: 1 });
    assert.equal(evidenceSnapshot(db), evidenceBeforeConflict);
    assert.equal(JSON.stringify(db.prepare("SELECT * FROM audit_events ORDER BY seq").all()), auditBeforeConflict);
    assert.equal(lifecycleSnapshot(db), protectedBefore);

    const stored = evidenceSnapshot(db);
    assert.ok(stored);
    assert.throws(() => db.prepare("UPDATE supplemental_native_evidence SET committed_at=?").run(NOW));
    assert.throws(() => db.prepare("DELETE FROM supplemental_native_evidence").run());
    assert.throws(() => db.prepare("INSERT OR REPLACE INTO supplemental_native_evidence SELECT * FROM supplemental_native_evidence LIMIT 1").run());
    assert.equal(evidenceSnapshot(db), stored);
    assert.deepEqual(counts(db), { evidence: 1, audit: 1 });
    assert.equal(lifecycleSnapshot(db), protectedBefore);
  } finally { db.close(); }
});

test("production database retains evidence and audit across close/reopen with idempotent migration ledger", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-evidence-production-"));
  const path = join(dir, "controller.sqlite3");
  let db: DatabaseSync | undefined;
  try {
    db = openControllerDatabase(path);
    assert.deepEqual(CONTROLLER_MIGRATIONS.slice(0, 18).map(m => m.checksum), BASELINE_MIGRATION_CHECKSUMS_1_TO_18);
    seedProtectedProductionRows(db);
    const repo = new SupplementalNativeEvidenceRepository(db, () => NOW);
    const result = repo.append(candidate());
    assert.equal(result.ok, true);
    assert.deepEqual(counts(db), { evidence: 1, audit: 1 });
    const evidenceBefore = evidenceSnapshot(db);
    const auditBefore = JSON.stringify(db.prepare("SELECT * FROM audit_events ORDER BY seq").all());
    const protectedBefore = lifecycleSnapshot(db);
    const ledgerBefore = JSON.stringify(db.prepare("SELECT version,name,checksum,applied_at FROM schema_migrations ORDER BY version").all());
    db.close(); db = undefined;

    db = openControllerDatabase(path);
    assert.equal((db.prepare("PRAGMA user_version").get() as { user_version: number }).user_version, 19);
    assert.equal(evidenceSnapshot(db), evidenceBefore);
    assert.equal(JSON.stringify(db.prepare("SELECT * FROM audit_events ORDER BY seq").all()), auditBefore);
    assert.equal(lifecycleSnapshot(db), protectedBefore);
    assert.equal(JSON.stringify(db.prepare("SELECT version,name,checksum,applied_at FROM schema_migrations ORDER BY version").all()), ledgerBefore);
    assert.equal((db.prepare("PRAGMA integrity_check").get() as { integrity_check: string }).integrity_check, "ok");
    assert.deepEqual(db.prepare("PRAGMA foreign_key_check").all(), []);
    assert.deepEqual(CONTROLLER_MIGRATIONS.slice(0, 18).map(m => m.checksum), BASELINE_MIGRATION_CHECKSUMS_1_TO_18);
  } finally {
    db?.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

function seedProtectedProductionRows(db: DatabaseSync): void {
  db.prepare(`INSERT INTO jobs(job_id,state,host_id,submitted_at,updated_at,attempt,idempotency_key,payload_json,created_at)
    VALUES(?,?,?,?,?,?,?,?,?)`).run("protected-job", "timed-out", "host-1", NOW, NOW, 2, "protected-idem", '{"payload":"must remain byte-identical"}', NOW);
  db.prepare(`INSERT INTO job_history(job_id,from_state,to_state,attempt,occurred_at,created_at)
    VALUES(?,?,?,?,?,?)`).run("protected-job", "running", "timed-out", 2, NOW, NOW);
  db.prepare(`INSERT INTO agent_commands(job_id,host_id,request_json,request_digest,state,lease_until,result_json,created_at,updated_at)
    VALUES(?,?,?,?,?,?,?,?,?)`).run("protected-job", "host-1", '{"request":"protected"}', "a".repeat(64), "completed", null,
      '{"result":"must remain byte-identical"}', NOW, NOW);
}

test("open production database applies migration 19 and repository appends synthetic evidence", () => {
  const db = openControllerDatabase(":memory:");
  try {
    assert.equal((db.prepare("PRAGMA user_version").get() as { user_version: number }).user_version, 19);
    const repo = new SupplementalNativeEvidenceRepository(db, () => NOW);
    const result = repo.append(candidate());
    assert.equal(result.ok, true);
    assert.deepEqual(counts(db), { evidence: 1, audit: 1 });
  } finally { db.close(); }
});

function counts(db: DatabaseSync) {
  return { evidence: (db.prepare("SELECT count(*) AS n FROM supplemental_native_evidence").get() as {n:number}).n,
    audit: (db.prepare("SELECT count(*) AS n FROM audit_events").get() as {n:number}).n };
}
function lifecycleSnapshot(db: DatabaseSync): string {
  const jobs = db.prepare("SELECT * FROM jobs ORDER BY job_id").all();
  const history = db.prepare("SELECT * FROM job_history ORDER BY history_id").all();
  const commands = db.prepare("SELECT * FROM agent_commands ORDER BY job_id").all();
  return JSON.stringify([jobs, history, commands]);
}
function evidenceSnapshot(db: DatabaseSync): string {
  const row = db.prepare("SELECT * FROM supplemental_native_evidence ORDER BY tuple_digest").get() as Record<string, unknown> | undefined;
  if (!row) return "null";
  return JSON.stringify(Object.fromEntries(Object.entries(row).map(([k,v]) => [k, v instanceof Uint8Array ? Buffer.from(v).toString("base64") : v])));
}
function rebound(input: SupplementalEvidenceInput, responseBytes: Uint8Array): SupplementalEvidenceInput {
  const tuple = { ...input.tuple, responseDigest: hash("lanmm-native-response-bytes-v1\\0", responseBytes), responseByteLength: responseBytes.length } as EvidenceTuple;
  const tupleDigest = hash("lanmm-native-terminal-evidence-tuple-digest-v1\\0", Buffer.from(JSON.stringify(TUPLE_KEYS.map(k => tuple[k])), "utf8"));
  return { ...input, responseBytes, tuple, tupleDigest };
}

test("append couples one immutable evidence row and safe audit event; lifecycle history/result stay byte-identical", () => {
  const { db, repo } = setup();
  try {
    const before = lifecycleSnapshot(db);
    const input = candidate();
    const result = repo.append(input);
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.duplicate, false);
    assert.equal(result.receiptCore.disposition, "evidence-only");
    assert.equal(result.receiptCore.domain, "lanmm-native-evidence-storage-core-v1");
    assert.equal(counts(db).evidence, 1);
    assert.equal(counts(db).audit, 1);
    const stored = db.prepare("SELECT tuple_json,payload_bytes,response_bytes,response_digest FROM supplemental_native_evidence").get() as Record<string, unknown>;
    assert.deepEqual(Buffer.from(stored.payload_bytes as Uint8Array), input.payloadBytes);
    assert.deepEqual(Buffer.from(stored.response_bytes as Uint8Array), input.responseBytes);
    assert.equal(stored.response_digest, input.tuple.responseDigest);
    assert.deepEqual(JSON.parse(stored.tuple_json as string), TUPLE_KEYS.map(k => input.tuple[k]));
    assert.equal(lifecycleSnapshot(db), before);
    const audit = JSON.parse((db.prepare("SELECT event_json FROM audit_events").get() as {event_json:string}).event_json);
    assert.equal(audit.actorKind, "system");
    assert.deepEqual(audit.details, { tupleDigest: result.tupleDigest, receiptId: result.receiptCore.receiptId, disposition: "evidence-only",
      consentBindingDigest: result.receiptCore.consentBindingDigest });
    assert.equal(JSON.stringify(audit).includes("ADAPTER_FAILED"), false);
    assert.equal(JSON.stringify(audit).includes("caller-validated"), false);
  } finally { db.close(); }
});

test("exact same evidence and exact same consent are idempotent without extra row or audit", () => {
  const { db, repo } = setup();
  try {
    const input = candidate(), first = repo.append(input), second = repo.append(input);
    assert.equal(first.ok, true); assert.equal(second.ok, true);
    if (!first.ok || !second.ok) return;
    assert.equal(first.duplicate, false); assert.equal(second.duplicate, true);
    assert.deepEqual(second.receiptCore, first.receiptCore);
    assert.deepEqual(counts(db), { evidence: 1, audit: 1 });
  } finally { db.close(); }
});

test("same tuple with changed opaque payload bytes conflicts without another row/audit", () => {
  const { db, repo } = setup();
  try {
    const original = candidate(); assert.equal(repo.append(original).ok, true);
    const altered = { ...original, payloadBytes: Buffer.from("different raw payload") };
    assert.deepEqual(repo.append(altered), { ok: false, code: "ERR_SUPPLEMENTAL_EVIDENCE_CONFLICT" });
    assert.deepEqual(counts(db), { evidence: 1, audit: 1 });
  } finally { db.close(); }
});

test("same tuple conflicts on every mutable consent binding; fixed action/disposition tampering is rejected", () => {
  const { db, repo } = setup();
  try {
    const original = candidate(); assert.equal(repo.append(original).ok, true);
    const variants: SupplementalEvidenceInput[] = [
      { ...original, consent: { ...original.consent, ownerId: "owner-2" } },
      { ...original, consent: { ...original.consent, sessionBindingDigest: "f".repeat(64) } },
      { ...original, consent: { ...original.consent, credentialVersion: original.consent.credentialVersion + 1 } },
      { ...original, consent: { ...original.consent, hostCertificateBindingDigest: "0".repeat(64) } },
      { ...original, consent: { ...original.consent, consentedAt: "2026-11-11T19:00:01.000Z" } },
    ];
    for (const changed of variants) assert.deepEqual(repo.append(changed), { ok: false, code: "ERR_SUPPLEMENTAL_EVIDENCE_CONFLICT" });
    assert.deepEqual(repo.append({ ...original, consent: { ...original.consent, action: "wrong-action" as never } }),
      { ok: false, code: "ERR_SUPPLEMENTAL_EVIDENCE_INPUT" });
    assert.deepEqual(repo.append({ ...original, consent: { ...original.consent, disposition: "wrong-disposition" as never } }),
      { ok: false, code: "ERR_SUPPLEMENTAL_EVIDENCE_INPUT" });
    assert.deepEqual(counts(db), { evidence: 1, audit: 1 });
  } finally { db.close(); }
});

test("response mismatch, tuple tampering, and malformed consent reject before any persistence", () => {
  const { db, repo } = setup();
  try {
    const input = candidate();
    assert.deepEqual(repo.append({ ...input, responseBytes: Buffer.from("different") }), { ok: false, code: "ERR_SUPPLEMENTAL_EVIDENCE_INPUT" });
    assert.deepEqual(repo.append({ ...input, tuple: { ...input.tuple, storedQueueDigest: "bad" } }), { ok: false, code: "ERR_SUPPLEMENTAL_EVIDENCE_INPUT" });
    assert.deepEqual(repo.append({ ...input, tuple: { ...input.tuple, terminalRevision: "history-2" } }), { ok: false, code: "ERR_SUPPLEMENTAL_EVIDENCE_INPUT" });
    assert.deepEqual(repo.append({ ...input, tuple: { ...input.tuple, evidenceKind: "cancelled" } }), { ok: false, code: "ERR_SUPPLEMENTAL_EVIDENCE_INPUT" });
    assert.deepEqual(counts(db), { evidence: 0, audit: 0 });
  } finally { db.close(); }
});

test("audit insertion failure rolls back the evidence insert atomically", () => {
  const { db, repo } = setup();
  try {
    db.exec("CREATE TRIGGER reject_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit failure canary'); END;");
    const result = repo.append(candidate());
    assert.deepEqual(result, { ok: false, code: "ERR_SUPPLEMENTAL_EVIDENCE_DATABASE" });
    assert.deepEqual(counts(db), { evidence: 0, audit: 0 });
  } finally { db.close(); }
});

test("append-only guards reject UPDATE, DELETE, INSERT OR REPLACE, and UPSERT without changing stored bytes/audit", () => {
  const { db, repo } = setup();
  try {
    const result = repo.append(candidate()); assert.equal(result.ok, true);
    const before = evidenceSnapshot(db), auditBefore = counts(db).audit;
    assert.throws(() => db.prepare("UPDATE supplemental_native_evidence SET committed_at=?").run(NOW));
    assert.throws(() => db.prepare("DELETE FROM supplemental_native_evidence").run());
    assert.throws(() => db.prepare("INSERT OR REPLACE INTO supplemental_native_evidence SELECT * FROM supplemental_native_evidence WHERE tuple_digest=(SELECT tuple_digest FROM supplemental_native_evidence LIMIT 1)").run());
    assert.throws(() => db.prepare(`INSERT INTO supplemental_native_evidence SELECT * FROM supplemental_native_evidence WHERE tuple_digest=(SELECT tuple_digest FROM supplemental_native_evidence LIMIT 1)
      ON CONFLICT(tuple_digest) DO UPDATE SET payload_bytes=excluded.payload_bytes`).run());
    assert.equal(evidenceSnapshot(db), before);
    assert.deepEqual(counts(db), { evidence: 1, audit: auditBefore });
  } finally { db.close(); }
});

test("exact payload/response byte caps are accepted; each cap plus one rejects without extra writes", () => {
  const payloadDb = setup();
  try {
    const base = candidate();
    assert.equal(payloadDb.repo.append({ ...base, payloadBytes: Buffer.alloc(EVIDENCE_MAX_PAYLOAD_BYTES, 0x50) }).ok, true);
    const before = counts(payloadDb.db);
    assert.deepEqual(payloadDb.repo.append({ ...base, payloadBytes: Buffer.alloc(EVIDENCE_MAX_PAYLOAD_BYTES + 1, 0x50) }),
      { ok: false, code: "ERR_SUPPLEMENTAL_EVIDENCE_INPUT" });
    assert.deepEqual(counts(payloadDb.db), before);
  } finally { payloadDb.db.close(); }

  const responseDb = setup();
  try {
    const baseLength = candidate().responseBytes.length;
    const exactResponse = candidate(MAX_EVIDENCE_RESPONSE_BYTES - baseLength);
    assert.equal(exactResponse.responseBytes.length, EVIDENCE_MAX_RESPONSE_BYTES);
    assert.ok(exactResponse.payloadBytes.length <= EVIDENCE_MAX_PAYLOAD_BYTES);
    assert.equal(responseDb.repo.append(exactResponse).ok, true);
    const before = counts(responseDb.db);
    const plusOne = rebound(exactResponse, Buffer.concat([exactResponse.responseBytes, Buffer.from([0x20])]));
    assert.deepEqual(responseDb.repo.append(plusOne), { ok: false, code: "ERR_SUPPLEMENTAL_EVIDENCE_INPUT" });
    assert.deepEqual(counts(responseDb.db), before);
  } finally { responseDb.db.close(); }
});

test("intrinsic byte snapshots ignore shadowed accessors; proxies/accessors are never invoked", () => {
  const { db, repo } = setup();
  try {
    const calls = { n: 0 }, base = candidate();
    class HostileBytes extends Uint8Array {
      get buffer(): ArrayBuffer { calls.n++; throw new Error("buffer getter"); }
      get byteLength(): number { calls.n++; throw new Error("length getter"); }
      get byteOffset(): number { calls.n++; throw new Error("offset getter"); }
      [Symbol.iterator](): ReturnType<Uint8Array[typeof Symbol.iterator]> { calls.n++; throw new Error("iterator"); }
    }
    const hostileInput = { ...base, payloadBytes: new HostileBytes(base.payloadBytes), responseBytes: new HostileBytes(base.responseBytes) };
    assert.equal(repo.append(hostileInput).ok, true);
    assert.equal(calls.n, 0);
    const proxyBytes = new Proxy(new Uint8Array([1, 2, 3]), { get() { calls.n++; throw new Error("proxy byte getter"); } });
    assert.deepEqual(repo.append({ ...base, payloadBytes: proxyBytes }), { ok: false, code: "ERR_SUPPLEMENTAL_EVIDENCE_INPUT" });
    const hostile = Object.defineProperty({}, "payloadBytes", { enumerable: true, get() { calls.n++; return Buffer.from("secret"); } });
    const accessorResult = repo.append(hostile);
    assert.deepEqual(accessorResult, { ok: false, code: "ERR_SUPPLEMENTAL_EVIDENCE_INPUT" });
    assert.equal(calls.n, 0);
    assert.equal(JSON.stringify(accessorResult).includes("secret"), false);
  } finally { db.close(); }
});

test("caller mutation after append cannot change persisted payload, response, tuple, or audit", () => {
  const { db, repo } = setup();
  try {
    const base = candidate();
    const input = { ...base, payloadBytes: Buffer.from(base.payloadBytes), responseBytes: Buffer.from(base.responseBytes),
      tuple: { ...base.tuple } as { -readonly [K in keyof EvidenceTuple]: EvidenceTuple[K] } };
    assert.equal(repo.append(input).ok, true);
    const evidenceBefore = evidenceSnapshot(db), auditBefore = db.prepare("SELECT event_json FROM audit_events").get();
    input.payloadBytes.fill(0x58); input.responseBytes.fill(0x59); input.tuple.terminalRevision = "mutated";
    assert.equal(evidenceSnapshot(db), evidenceBefore);
    assert.deepEqual(db.prepare("SELECT event_json FROM audit_events").get(), auditBefore);
  } finally { db.close(); }
});

test("appendInTransaction commits evidence and one audit event only through exact live same-DB context", () => {
  const { db, repo } = setup();
  const stores = createJobStores(db, { now: () => NOW });
  try {
    const before = lifecycleSnapshot(db), input = candidate();
    const provisional: Array<ReturnType<typeof repo.appendInTransaction>> = [];
    stores.withAuditTransaction((tx) => {
      const result = repo.appendInTransaction(tx, input);
      provisional.push(result);
      assert.equal(result.ok, true);
      assert.deepEqual(counts(db), { evidence: 1, audit: 1 });
      assert.equal(lifecycleSnapshot(db), before);
    });
    assert.equal(provisional.length, 1);
    assert.equal(provisional[0]!.duplicate, false);
    assert.deepEqual(counts(db), { evidence: 1, audit: 1 });
    assert.equal(lifecycleSnapshot(db), before);
  } finally { db.close(); }
});

test("appendInTransaction rejects invalid contexts before evidence reads and malformed input throws", () => {
  const { db, repo } = setup();
  const stores = createJobStores(db, { now: () => NOW });
  const foreign = new DatabaseSync(":memory:");
  const foreignSchema = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "supplemental-native-evidence-test-schema.sql"), "utf8");
  foreign.exec(foreignSchema);
  const foreignStores = createJobStores(foreign, { now: () => NOW });
  try {
    let reads = 0;
    db.setAuthorizer((_action, arg1) => { if (arg1 === "supplemental_native_evidence") reads++; return 0; });
    const input = candidate();
    const forged = Object.freeze({ jobs: stores.jobs, audit: stores.audit }) as unknown as CoupledContext;
    assert.throws(() => repo.appendInTransaction(forged, input), /ERR_SUPPLEMENTAL_EVIDENCE_TRANSACTION/);
    assert.throws(() => repo.appendInTransaction({ ...forged }, input), /ERR_SUPPLEMENTAL_EVIDENCE_TRANSACTION/);
    assert.throws(() => repo.appendInTransaction(new Proxy(forged, {}), input), /ERR_SUPPLEMENTAL_EVIDENCE_TRANSACTION/);
    assert.throws(() => repo.appendInTransaction(forged, {}), /ERR_SUPPLEMENTAL_EVIDENCE_TRANSACTION/);
    assert.equal(reads, 0);
    db.setAuthorizer(null);

    let stale: CoupledContext | null = null;
    stores.withAuditTransaction((tx) => { stale = tx; });
    assert.ok(stale);
    assert.throws(() => repo.appendInTransaction(stale!, input), /ERR_SUPPLEMENTAL_EVIDENCE_TRANSACTION/);
    assert.throws(() => stores.withAuditTransaction((tx) => repo.appendInTransaction(tx, {})), /ERR_SUPPLEMENTAL_EVIDENCE_INPUT/);
    assert.deepEqual(counts(db), { evidence: 0, audit: 0 });
    assert.deepEqual(counts(foreign), { evidence: 0, audit: 0 });

    db.exec("BEGIN IMMEDIATE");
    try {
      assert.throws(() => repo.appendInTransaction(forged, input), /ERR_SUPPLEMENTAL_EVIDENCE_TRANSACTION/);
      assert.deepEqual(counts(db), { evidence: 0, audit: 0 });
    } finally { db.exec("ROLLBACK"); }

    foreignStores.withAuditTransaction((foreignTx) => {
      assert.throws(() => repo.appendInTransaction(foreignTx, input), /ERR_SUPPLEMENTAL_EVIDENCE_TRANSACTION/);
    });
    stores.withAuditTransaction((tx) => assert.equal(repo.appendInTransaction(tx, input).ok, true));
    assert.deepEqual(counts(db), { evidence: 1, audit: 1 });
  } finally { db.close(); foreign.close(); }
});

test("appendInTransaction accepts exact live context from another store on same connection", () => {
  const { db, repo } = setup();
  const stores = createJobStores(db, { now: () => NOW });
  const secondStores = createJobStores(db, { now: () => NOW });
  try {
    const before = lifecycleSnapshot(db);
    const result: Array<ReturnType<typeof repo.appendInTransaction>> = [];
    stores.withAuditTransaction((tx) => { result.push(repo.appendInTransaction(tx, candidate())); });
    assert.equal(result.length, 1);
    assert.equal(result[0]!.duplicate, false);
    // The validator is DB/issuance-bound, not tied to repository's private store instance.
    secondStores.withAuditTransaction((tx) => assert.equal(repo.appendInTransaction(tx, candidate()).duplicate, true));
    assert.deepEqual(counts(db), { evidence: 1, audit: 1 });
    assert.equal(lifecycleSnapshot(db), before);
  } finally { db.close(); }
});

test("exact in-transaction duplicate adds no audit; conflicting duplicate propagates and rolls back caller work", () => {
  const { db, repo } = setup();
  const stores = createJobStores(db, { now: () => NOW });
  try {
    const original = candidate();
    assert.equal(repo.append(original).ok, true);
    stores.withAuditTransaction((tx) => {
      const duplicate = repo.appendInTransaction(tx, original);
      assert.equal(duplicate.duplicate, true);
    });
    assert.deepEqual(counts(db), { evidence: 1, audit: 1 });

    const before = lifecycleSnapshot(db);
    const changed = { ...original, consent: { ...original.consent, ownerId: "owner-2" } };
    db.exec("CREATE TABLE caller_rollback_sentinel(value INTEGER NOT NULL)");
    assert.throws(() => stores.withAuditTransaction((tx) => {
      db.prepare("INSERT INTO caller_rollback_sentinel(value) VALUES(7)").run();
      repo.appendInTransaction(tx, changed);
    }), /ERR_SUPPLEMENTAL_EVIDENCE_CONFLICT/);
    assert.equal(db.prepare("SELECT count(*) AS n FROM caller_rollback_sentinel").get() &&
      (db.prepare("SELECT count(*) AS n FROM caller_rollback_sentinel").get() as {n:number}).n, 0);
    assert.deepEqual(counts(db), { evidence: 1, audit: 1 });
    assert.equal(lifecycleSnapshot(db), before);
  } finally { db.close(); }
});

test("in-transaction audit failure rolls back and deferred COMMIT failure is automatically cleaned up", () => {
  const { db, repo } = setup();
  const stores = createJobStores(db, { now: () => NOW });
  const before = lifecycleSnapshot(db);
  try {
    db.exec("CREATE TRIGGER reject_outer_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit failure canary'); END;");
    assert.throws(() => stores.withAuditTransaction((tx) => repo.appendInTransaction(tx, candidate())));
    assert.deepEqual(counts(db), { evidence: 0, audit: 0 });
    assert.equal(db.isTransaction, false);
    assert.equal(lifecycleSnapshot(db), before);
    db.exec("DROP TRIGGER reject_outer_audit");

    db.exec(`CREATE TRIGGER invalidate_commit_guard AFTER INSERT ON supplemental_native_evidence
      BEGIN DELETE FROM evidence_commit_guard WHERE guard_id=NEW.commit_guard_id; END;`);
    const tentative: Array<ReturnType<typeof repo.appendInTransaction>> = [];
    assert.throws(() => stores.withAuditTransaction((tx) => { tentative.push(repo.appendInTransaction(tx, candidate())); }));
    assert.equal(tentative.length, 1);
    assert.equal(tentative[0]!.duplicate, false);
    // A successful in-callback append is provisional; the deferred COMMIT fails,
    // and the transaction owner automatically rolls the evidence and audit back.
    assert.equal(db.isTransaction, false);
    assert.deepEqual(counts(db), { evidence: 0, audit: 0 });
    assert.equal(lifecycleSnapshot(db), before);

    db.exec("DROP TRIGGER invalidate_commit_guard");
    const recovered = repo.append(candidate());
    assert.equal(recovered.ok, true);
    assert.deepEqual(counts(db), { evidence: 1, audit: 1 });
    assert.equal(lifecycleSnapshot(db), before);
  } finally { if (db.isTransaction) db.exec("ROLLBACK"); db.close(); }
});

test("COMMIT failure from a deferred constraint rolls back evidence and audit", () => {
  const { db, repo } = setup();
  try {
    db.exec(`CREATE TRIGGER invalidate_commit_guard AFTER INSERT ON supplemental_native_evidence
      BEGIN DELETE FROM evidence_commit_guard WHERE guard_id=NEW.commit_guard_id; END;`);
    const result = repo.append(candidate());
    assert.deepEqual(result, { ok: false, code: "ERR_SUPPLEMENTAL_EVIDENCE_DATABASE" });
    assert.deepEqual(counts(db), { evidence: 0, audit: 0 });
  } finally { db.close(); }
});
