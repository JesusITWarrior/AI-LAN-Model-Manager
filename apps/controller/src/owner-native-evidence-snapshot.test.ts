import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import test from "node:test";
import { commandAuthorizationDigest, commandPolicyOperation, parseCommandRequest, type CommandRequest, type CommandResponse } from "@lan-model-manager/core";
import { AgentCommandStore } from "./agent-command-channel.js";
import { CommandDispatcher } from "./command-dispatch.js";
import { CertificateRepository } from "./certificate-repository.js";
import { OpenSslCertificateEngine } from "./certificate-adapter.js";
import type { PasswordCryptoEngine } from "./credentials.js";
import { openControllerDatabase } from "./database.js";
import { createAllowedOrigins } from "./origin.js";
import { createJobStores } from "./jobs-store.js";
import { createOwnerBootstrapService } from "./owner-service.js";
import { OwnerNativeEvidenceCandidateRegistry, OWNER_NATIVE_EVIDENCE_ACTION, OWNER_NATIVE_EVIDENCE_DISPOSITION, type NativeEvidenceCandidateInput } from "./owner-native-evidence-candidates.js";
import { OwnerNativeEvidenceMatchedAppendCoordinator, OwnerNativeEvidenceSnapshotReader, OwnerNativeEvidenceTransactionOwner } from "./owner-native-evidence-snapshot.js";
import { SessionManager } from "./session-manager.js";
import { guardManagementRequest } from "./guard.js";
import { computeTerminalRevision } from "./native-terminal-revision.js";

const START = "2026-09-27T10:00:00.000Z";
const ORIGINS = createAllowedOrigins(["https://manager.example"]);
const passwordCrypto: PasswordCryptoEngine = {
  random: n => Buffer.alloc(n, 3), async derive(password, salt, parameters) {
    const seed = createHash("sha256").update(password).update(salt).digest(); return Buffer.alloc(parameters.keyLength, seed[0]);
  }, equal: (a, b) => Buffer.from(a).equals(Buffer.from(b)),
};
const responsePrefix = Buffer.from("lanmm-native-response-bytes-v1\0", "utf8");
const tupleKeys = ["domain", "hostId", "jobId", "requestId", "commandSequence", "idempotencyKey", "authorizationRequestDigest", "storedQueueDigest", "terminalState", "terminalRevision", "responseDigest", "responseByteLength", "evidenceKind", "holdClass"] as const;
function makeInput(tuple: Record<string, unknown>, responseBytes: Uint8Array, cert: ReturnType<CertificateRepository["getById"]>): NativeEvidenceCandidateInput {
  assert.ok(cert);
  const exactTuple = tuple as unknown as NativeEvidenceCandidateInput["tuple"];
  const tupleDigest = createHash("sha256").update("lanmm-native-terminal-evidence-tuple-digest-v1\0", "utf8")
    .update(JSON.stringify(tupleKeys.map(k => exactTuple[k])), "utf8").digest("hex");
  return { tuple: exactTuple, tupleDigest, payloadBytes: new Uint8Array([0x50, 0x41, 0x59]), responseBytes,
    certificateBindingAssertion: { certificateId: cert.certificateId, serial: cert.serial, fingerprint: cert.fingerprint, version: cert.version,
      candidateId: cert.binding.candidateId, address: cert.binding.address, port: cert.binding.port, protocolMajor: cert.binding.protocolMajor,
      protocolMinor: cert.binding.protocolMinor, notBefore: cert.notBefore, notAfter: cert.notAfter, caId: cert.caId, caVersion: cert.caVersion, spiffeUri: cert.spiffeUri } };
}
async function fixture(largeRequest = false) {
  const db = openControllerDatabase(":memory:");
  const testSchema = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "supplemental-native-evidence-test-schema.sql"), "utf8");
  const marker = "CREATE TABLE evidence_commit_guard";
  assert.equal(testSchema.split(marker).length - 1, 1, "expected one opt-in evidence schema marker");
  // These synthetic transaction tests own the deferred-commit fixture schema;
  // discard the production migration table first to avoid conflating the two.
  db.exec("DROP TABLE supplemental_native_evidence");
  db.exec(testSchema.slice(testSchema.indexOf(marker)));
  let now = START, random = 0;
  const owners = createOwnerBootstrapService(db, { now: () => now, ownerId: () => "a".repeat(32), crypto: passwordCrypto });
  await owners.bootstrapOwner({ username: "Admin", password: "owner-password-123" });
  const sessions = new SessionManager(db, owners, { clock: () => now, random: n => Buffer.alloc(n, ++random), policy: { absoluteTtlMs: 3600000, idleTtlMs: 600000, touchAfterMs: 60000 } });
  const session = await sessions.create({ username: "admin", password: "owner-password-123" }); assert.ok(session);
  const guard = guardManagementRequest(sessions, ORIGINS, { method: "POST", cookieHeader: `__Host-lanmm_session=${session.sessionToken}`, originHeader: "https://manager.example", csrfHeader: session.csrfToken });
  assert.equal(guard.ok, true);
  const stores = createJobStores(db, { now: () => now });
  const certificates = new CertificateRepository(db), pem = "-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n";
  certificates.insertCa({ caId: "b".repeat(64), version: 1, serial: "10", fingerprint: "b".repeat(64), certificatePem: pem, notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2036-01-01T00:00:00.000Z", createdAt: START });
  certificates.insertHost({ certificateId: "c".repeat(64), serial: "ABCD", fingerprint: "d".repeat(64), certificatePem: pem, caId: "b".repeat(64), caVersion: 1,
    binding: { candidateId: "host-1", address: "192.0.2.10", port: 7443, protocolMajor: 1, protocolMinor: 0 }, spiffeUri: "spiffe://lanmodelmanager/host/host-1",
    challengeId: "e".repeat(64), transcriptDigest: "f".repeat(64), notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2036-01-01T00:00:00.000Z", status: "active", version: 1, issuedAt: START, revokedAt: null });
  const operation = largeRequest ? "inference.chat" : "probe";
  const capability = { operation: commandPolicyOperation(operation), targetKind: largeRequest ? "model" as const : "host" as const,
    targetId: largeRequest ? "model-1" : "host-1", hostId: "host-1", modelId: largeRequest ? "model-1" : null, requestDigest: "", expiresAt: "2026-09-27T10:05:00.000Z" };
  const params = largeRequest ? { providerId: "provider-1", modelId: "model-1", model: "model:latest", requestId: "request-1",
    maxRequestBytes: 524288, maxResponseBytes: 131072, messages: [60_000, 60_000, 60_000].map(() => ({ role: "user" as const, contentBase64: Buffer.alloc(60_000, 97).toString("base64") })), temperatureMilli: null, maxTokens: null }
    : { providerId: "provider-1", model: "model:latest" };
  const request: CommandRequest = { requestId: "request-1", jobId: "job-1", hostId: "host-1", operation, idempotencyKey: "idem-1", sequence: 1,
    deadline: "2026-09-27T10:05:00.000Z", capability, params };
  capability.requestDigest = commandAuthorizationDigest(request);
  const parsedRequest = parseCommandRequest(request); assert.ok(parsedRequest.ok, parsedRequest.ok ? "" : parsedRequest.error);
  const queue = new AgentCommandStore(db, () => now, 30000, stores);
  assert.equal(new CommandDispatcher(stores, queue, () => now).dispatch(request).ok, true);
  assert.ok(queue.poll(request.hostId).command);
  const response: CommandResponse = { requestId: request.requestId, jobId: request.jobId, hostId: request.hostId, sequence: request.sequence,
    status: "failed", progress: null, observedAt: "2026-09-27T10:00:05.000Z", observation: null, errorCode: "ADAPTER_FAILED" };
  now = "2026-09-27T10:00:06.000Z";
  assert.ok(queue.complete(request.hostId, response));
  const responseBytes = Buffer.from(JSON.stringify(response), "utf8");
  const job = stores.jobs.get(request.jobId)!;
  const h = db.prepare("SELECT history_id,job_id,from_state,to_state,attempt,occurred_at,created_at FROM job_history WHERE job_id=? ORDER BY history_id DESC LIMIT 1").get(request.jobId) as Record<string, unknown>;
  const q = db.prepare("SELECT request_digest FROM agent_commands WHERE job_id=?").get(request.jobId) as { request_digest: string };
  const authDigest = commandAuthorizationDigest(parsedRequest.value), storedDigest = q.request_digest;
  const rev = computeTerminalRevision({ job: { jobId: job.payload.operation.jobId, requestId: job.payload.operation.requestId, state: job.state as "failed", hostId: job.payload.operation.hostId,
      submittedAt: job.payload.operation.submittedAt, updatedAt: job.updatedAt, attempt: job.attempt, idempotencyKey: job.payload.operation.idempotencyKey },
    history: { historyId: Number(h.history_id), jobId: String(h.job_id), fromState: String(h.from_state), toState: String(h.to_state) as "failed", attempt: Number(h.attempt), occurredAt: String(h.occurred_at), createdAt: String(h.created_at) },
    binding: { jobId: request.jobId, hostId: request.hostId, requestId: request.requestId, operation: request.operation, idempotencyKey: request.idempotencyKey,
      sequence: request.sequence, deadline: request.deadline, storedQueueDigest: storedDigest, authorizationDigest: authDigest } });
  assert.ok(rev.ok);
  const tuple = { domain: "lanmm-native-terminal-evidence-v1", hostId: request.hostId, jobId: request.jobId, requestId: request.requestId,
    commandSequence: request.sequence, idempotencyKey: request.idempotencyKey, authorizationRequestDigest: authDigest, storedQueueDigest: storedDigest,
    terminalState: job.state as "failed", terminalRevision: rev.revision,
    responseDigest: createHash("sha256").update(responsePrefix).update(responseBytes).digest("hex"), responseByteLength: responseBytes.length,
    evidenceKind: "failed", holdClass: "unknown" };
  let candidate: NativeEvidenceCandidateInput = makeInput(tuple, responseBytes, certificates.getById("c".repeat(64)));
  let registryClockHook: () => void = () => undefined;
  const registry = new OwnerNativeEvidenceCandidateRegistry(sessions, { clock: () => { registryClockHook(); return now; }, prepareCandidate: () => candidate, consumeCandidate: () => undefined });
  const reader = new OwnerNativeEvidenceSnapshotReader(db, registry, { clock: () => now });
  return { db, now, guard, stores, registry, reader, candidate, setCandidate: (x: NativeEvidenceCandidateInput) => { candidate = x; }, tuple, responseBytes, sessions, session, certificates, setNow: (value: string) => { now = value; }, setRegistryClockHook: (hook: () => void) => { registryClockHook = hook; }, request };
}
async function verifiedTrustFixture() {
  const f = await fixture(), root = mkdtempSync(join(tmpdir(), "lanmm-trust-snapshot-")), caDir = join(root, "ca"), hostDir = join(root, "host");
  mkdirSync(hostDir, { mode: 0o700 });
  try {
    const engine = new OpenSslCertificateEngine(), issuedAt = new Date(Date.now() - 2_000).toISOString();
    const ca = engine.initializeCa({ directory: caDir, now: issuedAt });
    execFileSync("openssl", ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", join(hostDir, "key.pem")], { stdio: "ignore" });
    execFileSync("openssl", ["req", "-new", "-key", join(hostDir, "key.pem"), "-subj", "/CN=host-1", "-addext", "subjectAltName=IP:192.0.2.10,URI:spiffe://lanmodelmanager/host/host-1", "-out", join(hostDir, "request.pem")], { stdio: "ignore" });
    const currentTime = new Date().toISOString(), binding = { candidateId: "host-1", address: "192.0.2.10", port: 7443, protocolMajor: 1, protocolMinor: 0 };
    const issued = engine.issueHost({ directory: caDir, csrPem: readFileSync(join(hostDir, "request.pem"), "utf8"), binding, serial: "ABCDEF1234", now: currentTime });
    f.db.exec("PRAGMA foreign_keys=OFF; DELETE FROM host_certificates; DELETE FROM certificate_authorities;");
    const certs = new CertificateRepository(f.db); certs.insertCa(ca);
    certs.insertHost({ certificateId: issued.fingerprint, serial: issued.serial, fingerprint: issued.fingerprint, certificatePem: issued.certificatePem,
      caId: ca.caId, caVersion: ca.version, binding, spiffeUri: "spiffe://lanmodelmanager/host/host-1", challengeId: "e".repeat(64),
      transcriptDigest: "f".repeat(64), notBefore: issued.notBefore, notAfter: issued.notAfter, status: "active", version: 1, issuedAt: currentTime, revokedAt: null });
    f.setCandidate(makeInput(f.tuple, f.responseBytes, certs.getById(issued.fingerprint)));
    (f as unknown as { reader: OwnerNativeEvidenceSnapshotReader }).reader = new OwnerNativeEvidenceSnapshotReader(f.db, f.registry, { clock: () => currentTime });
    return { ...f, currentTime, root, caDir, leaf: new X509Certificate(issued.certificatePem), caCert: new X509Certificate(ca.certificatePem) };
  } catch (error) { f.db.close(); rmSync(root, { recursive: true, force: true }); throw error; }
}
function replaceTrustLeaf(f: Awaited<ReturnType<typeof verifiedTrustFixture>>, options: { cn: string; address: string; uri: string; eku: string; serial: string }): X509Certificate {
  const dir = join(f.root, `variant-${options.serial}`); mkdirSync(dir, { mode: 0o700 });
  execFileSync("openssl", ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", join(dir, "key.pem")], { stdio: "ignore" });
  execFileSync("openssl", ["req", "-new", "-key", join(dir, "key.pem"), "-subj", `/CN=${options.cn}`, "-out", join(dir, "request.pem")], { stdio: "ignore" });
  writeFileSync(join(dir, "ext"), `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n${options.eku ? `extendedKeyUsage=critical,${options.eku}\n` : ""}subjectAltName=IP:${options.address},URI:${options.uri}\n`);
  execFileSync("openssl", ["x509", "-req", "-sha256", "-in", join(dir, "request.pem"), "-CA", join(f.caDir, "ca-cert.pem"), "-CAkey", join(f.caDir, "ca-key.pem"), "-set_serial", `0x${options.serial}`, "-days", "30", "-extfile", join(dir, "ext"), "-out", join(dir, "cert.pem")], { stdio: "ignore" });
  const pem = readFileSync(join(dir, "cert.pem"), "utf8"), leaf = new X509Certificate(pem), fingerprint = createHash("sha256").update(leaf.raw).digest("hex");
  const serial = leaf.serialNumber.toUpperCase().replace(/^0+/, ""), notBefore = new Date(leaf.validFrom).toISOString(), notAfter = new Date(leaf.validTo).toISOString();
  f.db.prepare("UPDATE host_certificates SET cert_id=?,serial=?,fingerprint=?,certificate=?,not_before=?,not_after=? WHERE candidate_id=?")
    .run(fingerprint, serial, fingerprint, pem, notBefore, notAfter, "host-1");
  f.setCandidate(makeInput(f.tuple, f.responseBytes, f.certificates.getById(fingerprint)));
  return leaf;
}
function candidateWithResponse(f: Awaited<ReturnType<typeof fixture>>, raw: Uint8Array, patch: Record<string, unknown> = {}): NativeEvidenceCandidateInput {
  const parsed = (() => { try { return JSON.parse(Buffer.from(raw).toString("utf8")); } catch { return null; } })();
  const tuple = { ...f.tuple, ...patch, responseDigest: createHash("sha256").update(responsePrefix).update(raw).digest("hex"),
    responseByteLength: raw.byteLength, evidenceKind: patch.evidenceKind ?? parsed?.status ?? f.tuple.evidenceKind };
  return makeInput(tuple, raw, f.certificates.getById("c".repeat(64)));
}
function responseObject(f: Awaited<ReturnType<typeof fixture>>, observation: unknown = null, observedAt = "2026-09-27T10:00:05.000Z") {
  return { requestId: f.request.requestId, jobId: f.request.jobId, hostId: f.request.hostId, sequence: f.request.sequence,
    status: "failed", progress: null, observedAt, observation, errorCode: "ADAPTER_FAILED" };
}
function snapshotDatabase(db: import("node:sqlite").DatabaseSync): string {
  return JSON.stringify({ jobs: db.prepare("SELECT * FROM jobs ORDER BY job_id").all(), history: db.prepare("SELECT * FROM job_history ORDER BY history_id").all(),
    commands: db.prepare("SELECT * FROM agent_commands ORDER BY job_id").all(), audit: db.prepare("SELECT * FROM audit_events ORDER BY seq").all(),
    certificates: db.prepare("SELECT * FROM host_certificates ORDER BY cert_id").all(), authorities: db.prepare("SELECT * FROM certificate_authorities ORDER BY ca_id").all(),
    owners: db.prepare("SELECT * FROM owners ORDER BY owner_id").all(), sessions: db.prepare("SELECT * FROM sessions ORDER BY session_digest").all() });
}
function protectedState(db: import("node:sqlite").DatabaseSync): string {
  const { audit: _audit, ...protectedRows } = JSON.parse(snapshotDatabase(db)) as Record<string, unknown>;
  return JSON.stringify(protectedRows);
}
function readOnlyDatabaseSnapshot(db: import("node:sqlite").DatabaseSync): string {
  return JSON.stringify({ existingRows: JSON.parse(snapshotDatabase(db)), evidence: db.prepare("SELECT * FROM supplemental_native_evidence ORDER BY tuple_digest").all(),
    replay: db.prepare("SELECT * FROM transport_replay_state ORDER BY certificate_fingerprint").all() });
}
function withClaim(f: Awaited<ReturnType<typeof fixture>>, run: (token: object) => void) {
  const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
  const claimed = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(claimed.ok);
  const before = readOnlyDatabaseSnapshot(f.db);
  run(claimed.token);
  assert.equal(readOnlyDatabaseSnapshot(f.db), before, "reader or lease-view changed persisted state");
}

test("verified current-trust reader validates real CA/leaf, returns detached digest, preserves rows and leaves lease releasable", async () => {
  const f = await verifiedTrustFixture();
  try {
    withClaim(f, token => {
      let result: ReturnType<typeof f.reader.readVerified> | undefined;
      f.stores.withAuditTransaction(tx => { result = f.reader.readVerified(f.guard, tx, token); });
      assert.equal(result?.ok, true);
      if (!result?.ok || !result.match) return assert.fail("expected verified trust match");
      assert.equal(result.snapshot.verdict, "verified_current_trust");
      assert.equal(result.snapshot.verifiedAt, f.currentTime);
      assert.equal(result.snapshot.hostCertificateId, f.leaf.fingerprint256.replaceAll(":", "").toLowerCase());
      assert.match(result.snapshot.hostCertificateBindingDigest, /^[a-f0-9]{64}$/);
      assert.deepEqual(Object.keys(result.snapshot), ["verdict", "verifiedAt", "hostId", "jobId", "requestId", "terminalRevision", "hostCertificateId", "hostCertificateVersion", "certificateAuthorityId", "certificateAuthorityVersion", "hostCertificateBindingDigest"]);
      assert.deepEqual({ hostId: result.snapshot.hostId, jobId: result.snapshot.jobId, requestId: result.snapshot.requestId, terminalRevision: result.snapshot.terminalRevision },
        { hostId: f.tuple.hostId, jobId: f.tuple.jobId, requestId: f.tuple.requestId, terminalRevision: f.tuple.terminalRevision });
      const h = f.db.prepare("SELECT cert_id,serial,fingerprint,candidate_id,binding_address,binding_port,protocol_major,protocol_minor,spiffe_uri,not_before,not_after,status,version,ca_id,ca_version FROM host_certificates").get() as Record<string, unknown>;
      const c = f.db.prepare("SELECT ca_id,ca_version,serial,fingerprint,not_before,not_after FROM certificate_authorities").get() as Record<string, unknown>;
      const projection = { host: { id: h.cert_id, version: h.version, status: h.status, serial: String(h.serial).replace(/^0+/, ""), fingerprint: h.fingerprint,
          candidateId: h.candidate_id, address: h.binding_address, port: h.binding_port, protocolMajor: h.protocol_major, protocolMinor: h.protocol_minor,
          spiffeUri: h.spiffe_uri, notBefore: h.not_before, notAfter: h.not_after },
        ca: { id: c.ca_id, version: c.ca_version, serial: String(c.serial).replace(/^0+/, ""), fingerprint: c.fingerprint, notBefore: c.not_before, notAfter: c.not_after },
        crypto: { leafSubject: f.leaf.subject, leafIssuer: f.leaf.issuer, leafSubjectAltName: f.leaf.subjectAltName,
          leafKeyUsage: [...(f.leaf.keyUsage ?? [])].sort(), leafIsCa: f.leaf.ca, caSubject: f.caCert.subject, caIsCa: f.caCert.ca,
          caSelfSignatureVerified: true, leafSignatureVerified: true } };
      const expectedDigest = createHash("sha256").update("lanmm-owner-current-trust-snapshot-v1\0", "utf8").update(JSON.stringify(projection), "utf8").digest("hex");
      assert.equal(result.snapshot.hostCertificateBindingDigest, expectedDigest, `digest vector ${JSON.stringify(projection)}`);
      assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
    });
  } finally { f.db.close(); rmSync(f.root, { recursive: true, force: true }); }
});

test("verified current-trust rejects malformed PEM, raw fingerprint drift, revoked rows, and a valid but wrong CA", async () => {
  for (const mutation of ["malformed", "fingerprint", "revoked"] as const) {
    const f = await verifiedTrustFixture();
    try {
      if (mutation === "malformed") f.db.prepare("UPDATE host_certificates SET certificate=? WHERE candidate_id=?").run("-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n", "host-1");
      if (mutation === "fingerprint") f.db.prepare("UPDATE host_certificates SET fingerprint=? WHERE candidate_id=?").run("9".repeat(64), "host-1");
      if (mutation === "revoked") f.db.prepare("UPDATE host_certificates SET status='revoked',revoked_at=? WHERE candidate_id=?").run(f.currentTime, "host-1");
      withClaim(f, token => {
        let result: ReturnType<typeof f.reader.readVerified> | undefined;
        f.stores.withAuditTransaction(tx => { result = f.reader.readVerified(f.guard, tx, token); });
        assert.deepEqual(result, { ok: true, match: false }, mutation);
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
    } finally { f.db.close(); rmSync(f.root, { recursive: true, force: true }); }
  }
  const f = await verifiedTrustFixture(), other = await verifiedTrustFixture();
  try {
    const alternate = other.db.prepare("SELECT ca_id,ca_version,serial,fingerprint,subject,certificate,not_before,not_after,created_at FROM certificate_authorities").get() as Record<string, unknown>;
    f.db.exec("PRAGMA foreign_keys=OFF");
    f.db.prepare("INSERT INTO certificate_authorities(ca_id,ca_version,serial,fingerprint,subject,certificate,not_before,not_after,created_at) VALUES(?,?,?,?,?,?,?,?,?)")
      .run(String(alternate.ca_id), Number(alternate.ca_version), String(alternate.serial), String(alternate.fingerprint), String(alternate.subject), String(alternate.certificate), String(alternate.not_before), String(alternate.not_after), String(alternate.created_at));
    f.db.prepare("UPDATE host_certificates SET ca_id=?,ca_version=? WHERE candidate_id=?").run(String(alternate.ca_id), Number(alternate.ca_version), "host-1");
    const row = f.db.prepare("SELECT cert_id FROM host_certificates WHERE candidate_id=?").get("host-1") as { cert_id: string };
    f.setCandidate(makeInput(f.tuple, f.responseBytes, f.certificates.getById(row.cert_id)));
    withClaim(f, token => {
      let result: ReturnType<typeof f.reader.readVerified> | undefined;
      f.stores.withAuditTransaction(tx => { result = f.reader.readVerified(f.guard, tx, token); });
      assert.deepEqual(result, { ok: true, match: false }, "leaf signature must verify under the selected current CA");
      assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
    });
  } finally { f.db.close(); other.db.close(); rmSync(f.root, { recursive: true, force: true }); rmSync(other.root, { recursive: true, force: true }); }
});

test("verified current-trust path rejects invalid clock and candidate assertion drift without exposing a digest", async () => {
  const f = await verifiedTrustFixture();
  try {
    f.setCandidate({ ...f.candidate, certificateBindingAssertion: { ...f.candidate.certificateBindingAssertion, address: "192.0.2.99" } });
    const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
    const claimed = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(claimed.ok);
    let mismatch: ReturnType<typeof f.reader.readVerified> | undefined;
    f.stores.withAuditTransaction(tx => { mismatch = f.reader.readVerified(f.guard, tx, claimed.token); });
    assert.deepEqual(mismatch, { ok: true, match: false });
    assert.deepEqual(f.registry.releaseLease(f.guard, claimed.token), { ok: true, released: true });
    const badClock = new OwnerNativeEvidenceSnapshotReader(f.db, f.registry, { clock: () => "not-a-time" });
    const ready = f.registry.prepare(f.guard); assert.ok(ready.ok);
    const next = f.registry.claim(f.guard, { handle: ready.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(next.ok);
    let bad: ReturnType<typeof badClock.readVerified> | undefined;
    f.stores.withAuditTransaction(tx => { bad = badClock.readVerified(f.guard, tx, next.token); });
    assert.deepEqual(bad, { ok: true, match: false });
    assert.deepEqual(f.registry.releaseLease(f.guard, next.token), { ok: true, released: true });
  } finally { f.db.close(); rmSync(f.root, { recursive: true, force: true }); }
});

test("verified current-trust suppresses stale local facts after registry post-callback clock mutates host or CA rows", async () => {
  for (const authority of ["host", "ca"] as const) {
    const f = await verifiedTrustFixture();
    try {
      const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
      const claimed = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(claimed.ok);
      let registryClockCalls = 0;
      f.setRegistryClockHook(() => {
        registryClockCalls++;
        if (registryClockCalls !== 2) return;
        if (authority === "host") f.db.prepare("UPDATE host_certificates SET status='revoked',revoked_at=? WHERE candidate_id=?").run(f.currentTime, "host-1");
        else f.db.prepare("UPDATE certificate_authorities SET fingerprint=? WHERE ca_id=?").run("9".repeat(64), f.caCert.fingerprint256.replaceAll(":", "").toLowerCase());
      });
      let result: ReturnType<typeof f.reader.readVerified> | undefined;
      f.stores.withAuditTransaction(tx => { result = f.reader.readVerified(f.guard, tx, claimed.token); });
      assert.deepEqual(result, { ok: true, match: false }, `${authority} changed by post-callback clock`);
      assert.ok(registryClockCalls >= 2);
      assert.deepEqual(f.registry.releaseLease(f.guard, claimed.token), { ok: true, released: true });
    } finally { f.db.close(); rmSync(f.root, { recursive: true, force: true }); }
  }
});

test("verified current-trust rejects a parseable CA whose actual self-signature was corrupted", async () => {
  const f = await verifiedTrustFixture();
  try {
    const raw = Buffer.from(f.caCert.raw); raw[raw.length - 1] = raw[raw.length - 1]! ^ 1;
    const alteredPem = `-----BEGIN CERTIFICATE-----\n${raw.toString("base64").match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----\n`;
    const alteredCert = new X509Certificate(alteredPem);
    assert.equal(alteredCert.ca, true); assert.equal(alteredCert.issuer, alteredCert.subject); assert.equal(alteredCert.verify(alteredCert.publicKey), false);
    const fp = createHash("sha256").update(alteredCert.raw).digest("hex"), old = f.db.prepare("SELECT * FROM certificate_authorities").get() as Record<string, unknown>;
    f.db.prepare("INSERT INTO certificate_authorities(ca_id,ca_version,serial,fingerprint,subject,certificate,not_before,not_after,created_at) VALUES(?,?,?,?,?,?,?,?,?)")
      .run(fp, Number(old.ca_version), String(old.serial), fp, String(old.subject), alteredPem, String(old.not_before), String(old.not_after), String(old.created_at));
    f.db.prepare("UPDATE host_certificates SET ca_id=? WHERE candidate_id=?").run(fp, "host-1");
    const row = f.db.prepare("SELECT cert_id FROM host_certificates WHERE candidate_id=?").get("host-1") as { cert_id: string };
    f.setCandidate(makeInput(f.tuple, f.responseBytes, f.certificates.getById(row.cert_id)));
    withClaim(f, token => {
      let result: ReturnType<typeof f.reader.readVerified> | undefined;
      f.stores.withAuditTransaction(tx => { result = f.reader.readVerified(f.guard, tx, token); });
      assert.deepEqual(result, { ok: true, match: false }, "a matching stored raw fingerprint cannot replace CA self-signature verification");
      assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
    });
  } finally { f.db.close(); rmSync(f.root, { recursive: true, force: true }); }
});

test("verified current-trust rejects validly signed leaves with wrong CN, IP SAN, SPIFFE URI, or EKU", async () => {
  const cases = [
    { cn: "host-1", address: "192.0.2.10", uri: "spiffe://lanmodelmanager/host/host-1", eku: "clientAuth", serial: "4101" },
    { cn: "host-1", address: "192.0.2.10", uri: "spiffe://lanmodelmanager/host/host-1", eku: "serverAuth", serial: "4105" },
    { cn: "host-1", address: "192.0.2.10", uri: "spiffe://lanmodelmanager/host/host-1", eku: "", serial: "4106" },
    { cn: "other-host", address: "192.0.2.10", uri: "spiffe://lanmodelmanager/host/host-1", eku: "clientAuth,serverAuth", serial: "4102" },
    { cn: "host-1", address: "192.0.2.11", uri: "spiffe://lanmodelmanager/host/host-1", eku: "clientAuth,serverAuth", serial: "4103" },
    { cn: "host-1", address: "192.0.2.10", uri: "spiffe://lanmodelmanager/host/other-host", eku: "clientAuth,serverAuth", serial: "4104" },
  ];
  for (const options of cases) {
    const f = await verifiedTrustFixture();
    try {
      const leaf = replaceTrustLeaf(f, options);
      assert.equal(leaf.verify(f.caCert.publicKey), true);
      withClaim(f, token => {
        let result: ReturnType<typeof f.reader.readVerified> | undefined;
        f.stores.withAuditTransaction(tx => { result = f.reader.readVerified(f.guard, tx, token); });
        assert.deepEqual(result, { ok: true, match: false }, JSON.stringify(options));
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
    } finally { f.db.close(); rmSync(f.root, { recursive: true, force: true }); }
  }
});

test("verified current-trust rejects certificate validity-boundary and actual serial-to-row drift", async () => {
  for (const boundary of ["leaf-future", "leaf-expired", "ca-future", "ca-expired"] as const) {
    const f = await verifiedTrustFixture();
    try {
      const target = boundary.startsWith("ca-") ? f.caCert : f.leaf;
      const edge = boundary.endsWith("future") ? Date.parse(target.validFrom) - 1 : Date.parse(target.validTo) + 1;
      const reader = new OwnerNativeEvidenceSnapshotReader(f.db, f.registry, { clock: () => new Date(edge).toISOString() });
      withClaim(f, token => {
        let result: ReturnType<typeof reader.readVerified> | undefined;
        f.stores.withAuditTransaction(tx => { result = reader.readVerified(f.guard, tx, token); });
        assert.deepEqual(result, { ok: true, match: false }, boundary);
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
    } finally { f.db.close(); rmSync(f.root, { recursive: true, force: true }); }
  }
  for (const kind of ["host", "ca"] as const) {
    const f = await verifiedTrustFixture();
    try {
      if (kind === "host") {
        f.db.prepare("UPDATE host_certificates SET serial='ABCD' WHERE candidate_id=?").run("host-1");
        const row = f.db.prepare("SELECT cert_id FROM host_certificates WHERE candidate_id=?").get("host-1") as { cert_id: string };
        const candidate = makeInput(f.tuple, f.responseBytes, f.certificates.getById(row.cert_id));
        f.setCandidate({ ...candidate, certificateBindingAssertion: { ...candidate.certificateBindingAssertion, serial: "ABCD" } });
      } else f.db.prepare("UPDATE certificate_authorities SET serial='ABCD' WHERE ca_id=?").run(f.caCert.fingerprint256.replaceAll(":", "").toLowerCase());
      withClaim(f, token => {
        let result: ReturnType<typeof f.reader.readVerified> | undefined;
        f.stores.withAuditTransaction(tx => { result = f.reader.readVerified(f.guard, tx, token); });
        assert.deepEqual(result, { ok: true, match: false }, `${kind} serial must match parsed DER`);
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
    } finally { f.db.close(); rmSync(f.root, { recursive: true, force: true }); }
  }
});

test("verified current-trust rejects current-row CA subject/version, host version, and oversized PEM drift", async () => {
  for (const kind of ["ca-subject", "ca-version", "host-version", "oversized-pem"] as const) {
    const f = await verifiedTrustFixture();
    try {
      if (kind === "ca-subject") f.db.prepare("UPDATE certificate_authorities SET subject='CN=other authority' WHERE ca_id=?").run(f.caCert.fingerprint256.replaceAll(":", "").toLowerCase());
      if (kind === "ca-version") f.db.prepare("UPDATE certificate_authorities SET ca_version=ca_version+1 WHERE ca_id=?").run(f.caCert.fingerprint256.replaceAll(":", "").toLowerCase());
      if (kind === "host-version") f.db.prepare("UPDATE host_certificates SET version=version+1 WHERE candidate_id=?").run("host-1");
      if (kind === "oversized-pem") f.db.prepare("UPDATE host_certificates SET certificate=? WHERE candidate_id=?").run(`-----BEGIN CERTIFICATE-----\n${"A".repeat(16_400)}\n-----END CERTIFICATE-----\n`, "host-1");
      withClaim(f, token => {
        let result: ReturnType<typeof f.reader.readVerified> | undefined;
        f.stores.withAuditTransaction(tx => { result = f.reader.readVerified(f.guard, tx, token); });
        assert.deepEqual(result, { ok: true, match: false }, kind);
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
    } finally { f.db.close(); rmSync(f.root, { recursive: true, force: true }); }
  }
});

test("verified current-trust treats CA notBefore equality as valid and leaf notAfter equality as expired", async () => {
  const f = await verifiedTrustFixture();
  try {
    const starts = new OwnerNativeEvidenceSnapshotReader(f.db, f.registry, { clock: () => new Date(Date.parse(f.caCert.validFrom)).toISOString() });
    const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
    const claimed = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(claimed.ok);
    let atStart: ReturnType<typeof starts.readVerified> | undefined;
    f.stores.withAuditTransaction(tx => { atStart = starts.readVerified(f.guard, tx, claimed.token); });
    assert.equal(atStart?.ok, true); assert.equal(atStart?.match, true);
    assert.deepEqual(f.registry.releaseLease(f.guard, claimed.token), { ok: true, released: true });

    const ends = new OwnerNativeEvidenceSnapshotReader(f.db, f.registry, { clock: () => new Date(Date.parse(f.leaf.validTo)).toISOString() });
    const next = f.registry.prepare(f.guard); assert.ok(next.ok);
    const nextClaim = f.registry.claim(f.guard, { handle: next.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(nextClaim.ok);
    let atEnd: ReturnType<typeof ends.readVerified> | undefined;
    f.stores.withAuditTransaction(tx => { atEnd = ends.readVerified(f.guard, tx, nextClaim.token); });
    assert.deepEqual(atEnd, { ok: true, match: false });
    assert.deepEqual(f.registry.releaseLease(f.guard, nextClaim.token), { ok: true, released: true });
  } finally { f.db.close(); rmSync(f.root, { recursive: true, force: true }); }
});

test("verified current-trust returns no facts for foreign DB, denied guard, registry close, or stale credential postcheck", async () => {
  const f = await verifiedTrustFixture(), foreign = openControllerDatabase(":memory:");
  try {
    const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
    const claimed = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(claimed.ok);
    const wrongReader = new OwnerNativeEvidenceSnapshotReader(foreign, f.registry, { clock: () => f.currentTime });
    let result: ReturnType<typeof wrongReader.readVerified> | undefined;
    f.stores.withAuditTransaction(tx => { result = wrongReader.readVerified(f.guard, tx, claimed.token); });
    assert.deepEqual(result, { ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" });
    const denied = guardManagementRequest(f.sessions, ORIGINS, { method: "POST", cookieHeader: "", originHeader: "https://evil.example", csrfHeader: "" });
    let deniedResult: ReturnType<typeof f.reader.readVerified> | undefined;
    f.stores.withAuditTransaction(tx => { deniedResult = f.reader.readVerified(denied, tx, claimed.token); });
    assert.deepEqual(deniedResult, { ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" });
    assert.deepEqual(f.registry.releaseLease(f.guard, claimed.token), { ok: true, released: true });
  } finally { foreign.close(); f.db.close(); rmSync(f.root, { recursive: true, force: true }); }

  for (const invalidation of ["close", "credential"] as const) {
    const g = await verifiedTrustFixture();
    try {
      const prepared = g.registry.prepare(g.guard); assert.ok(prepared.ok);
      const claimed = g.registry.claim(g.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(claimed.ok);
      let clocks = 0;
      g.setRegistryClockHook(() => {
        if (++clocks !== 2) return;
        if (invalidation === "close") g.registry.close();
        else g.db.prepare("UPDATE owners SET credential_version=credential_version+1").run();
      });
      let result: ReturnType<typeof g.reader.readVerified> | undefined;
      g.stores.withAuditTransaction(tx => { result = g.reader.readVerified(g.guard, tx, claimed.token); });
      assert.deepEqual(result, { ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" }, invalidation);
      assert.ok(clocks >= 2);
    } finally { g.db.close(); rmSync(g.root, { recursive: true, force: true }); }
  }
});

test("same migrated DB, authentic guard and caller transaction produce fixed match without writes", async () => {
  const f = await fixture();
  try {
    const before = JSON.stringify({ jobs: f.db.prepare("SELECT * FROM jobs").all(), history: f.db.prepare("SELECT * FROM job_history").all(), commands: f.db.prepare("SELECT * FROM agent_commands").all(), audit: f.db.prepare("SELECT * FROM audit_events").all(), cert: f.db.prepare("SELECT * FROM host_certificates").all(), ca: f.db.prepare("SELECT * FROM certificate_authorities").all(), owners: f.db.prepare("SELECT * FROM owners").all(), sessions: f.db.prepare("SELECT * FROM sessions").all() });
    const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
    const claimed = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(claimed.ok);
    let verdict: ReturnType<typeof f.reader.read> | undefined;
    f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, claimed.token); });
    assert.deepEqual(verdict, { ok: true, match: true });
    const after = JSON.stringify({ jobs: f.db.prepare("SELECT * FROM jobs").all(), history: f.db.prepare("SELECT * FROM job_history").all(), commands: f.db.prepare("SELECT * FROM agent_commands").all(), audit: f.db.prepare("SELECT * FROM audit_events").all(), cert: f.db.prepare("SELECT * FROM host_certificates").all(), ca: f.db.prepare("SELECT * FROM certificate_authorities").all(), owners: f.db.prepare("SELECT * FROM owners").all(), sessions: f.db.prepare("SELECT * FROM sessions").all() });
    assert.equal(after, before);
    assert.deepEqual(f.registry.releaseLease(f.guard, claimed.token), { ok: true, released: true });
  } finally { f.db.close(); }
});

test("valid maximum-size inference request and exact serialized request byte cap are accepted", async () => {
  const large = await fixture(true);
  try {
    const requestJson = (large.db.prepare("SELECT request_json FROM agent_commands WHERE job_id=?").get("job-1") as { request_json: string }).request_json;
    assert.ok(Buffer.byteLength(requestJson, "utf8") > 128 * 1024);
    withClaim(large, token => {
      let verdict: ReturnType<typeof large.reader.read> | undefined;
      large.stores.withAuditTransaction(tx => { verdict = large.reader.read(large.guard, tx, token); });
      assert.deepEqual(verdict, { ok: true, match: true });
      assert.deepEqual(large.registry.releaseLease(large.guard, token), { ok: true, released: true });
    });
  } finally { large.db.close(); }

  for (const size of [550_000, 550_001]) {
    const f = await fixture();
    try {
      const original = (f.db.prepare("SELECT request_json FROM agent_commands WHERE job_id=?").get("job-1") as { request_json: string }).request_json;
      const bytes = Buffer.byteLength(original, "utf8");
      f.db.prepare("UPDATE agent_commands SET request_json=? WHERE job_id=?").run(original + " ".repeat(size - bytes), "job-1");
      withClaim(f, token => {
        let verdict: ReturnType<typeof f.reader.read> | undefined;
        f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, token); });
        assert.deepEqual(verdict, size === 550_000 ? { ok: true, match: true } : { ok: true, match: false });
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
    } finally { f.db.close(); }
  }
});

test("terminal stored result comparison ignores JSON object key order but detects semantic change", async () => {
  for (const changed of [false, true]) {
    const f = await fixture();
    try {
      const candidateResponse = responseObject(f, { z: { y: 2, x: 1 }, a: true });
      const raw = Buffer.from(JSON.stringify(candidateResponse));
      f.setCandidate(candidateWithResponse(f, raw));
      const stored = responseObject(f, changed ? { a: true, z: { x: 1, y: 999 } } : { a: true, z: { x: 1, y: 2 } });
      f.db.prepare("UPDATE agent_commands SET result_json=? WHERE job_id=?").run(JSON.stringify(stored), "job-1");
      withClaim(f, token => {
        let verdict: ReturnType<typeof f.reader.read> | undefined;
        f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, token); });
        assert.deepEqual(verdict, changed ? { ok: true, match: false } : { ok: true, match: true });
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
    } finally { f.db.close(); }
  }
});

test("every captured certificate assertion field independently mismatches current metadata", async () => {
  const changes: Array<Record<string, unknown>> = [
    { certificateId: "9".repeat(64) }, { serial: "ABCE" }, { fingerprint: "9".repeat(64) }, { version: 2 }, { candidateId: "host-2" },
    { address: "192.0.2.99" }, { port: 7444 }, { protocolMajor: 2 }, { protocolMinor: 1 }, { notBefore: "2026-01-02T00:00:00.000Z" },
    { notAfter: "2035-01-01T00:00:00.000Z" }, { caId: "9".repeat(64) }, { caVersion: 2 }, { spiffeUri: "spiffe://lanmodelmanager/host/other" },
  ];
  for (const patch of changes) {
    const f = await fixture();
    try {
      f.setCandidate({ ...f.candidate, certificateBindingAssertion: { ...f.candidate.certificateBindingAssertion, ...patch } });
      withClaim(f, token => {
        let verdict: ReturnType<typeof f.reader.read> | undefined;
        f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, token); });
        assert.deepEqual(verdict, { ok: true, match: false }, Object.keys(patch)[0]);
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
    } finally { f.db.close(); }
  }
});

test("each current host-certificate selector and asserted field drift fails closed", async () => {
  const mutations: Array<(f: Awaited<ReturnType<typeof fixture>>) => void> = [
    f => { f.db.prepare("UPDATE host_certificates SET cert_id=? WHERE cert_id=?").run("9".repeat(64), "c".repeat(64)); },
    f => { f.db.prepare("UPDATE host_certificates SET serial='ABCE' WHERE cert_id=?").run("c".repeat(64)); },
    f => { f.db.prepare("UPDATE host_certificates SET fingerprint=? WHERE cert_id=?").run("9".repeat(64), "c".repeat(64)); },
    f => { f.db.prepare("UPDATE host_certificates SET version=version+1 WHERE cert_id=?").run("c".repeat(64)); },
    f => { f.db.prepare("UPDATE host_certificates SET candidate_id='host-2' WHERE cert_id=?").run("c".repeat(64)); },
    f => { f.db.prepare("UPDATE host_certificates SET binding_address='192.0.2.99' WHERE cert_id=?").run("c".repeat(64)); },
    f => { f.db.prepare("UPDATE host_certificates SET binding_port=7444 WHERE cert_id=?").run("c".repeat(64)); },
    f => { f.db.prepare("UPDATE host_certificates SET protocol_major=2 WHERE cert_id=?").run("c".repeat(64)); },
    f => { f.db.prepare("UPDATE host_certificates SET protocol_minor=1 WHERE cert_id=?").run("c".repeat(64)); },
    f => { f.db.prepare("UPDATE host_certificates SET not_before='2026-01-02T00:00:00.000Z' WHERE cert_id=?").run("c".repeat(64)); },
    f => { f.db.prepare("UPDATE host_certificates SET not_after='2035-01-01T00:00:00.000Z' WHERE cert_id=?").run("c".repeat(64)); },
    f => { f.db.prepare("UPDATE host_certificates SET spiffe_uri='spiffe://lanmodelmanager/host/other' WHERE cert_id=?").run("c".repeat(64)); },
    f => {
      const pem = "-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n";
      f.certificates.insertCa({ caId: "9".repeat(64), version: 1, serial: "20", fingerprint: "8".repeat(64), certificatePem: pem,
        notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2036-01-01T00:00:00.000Z", createdAt: START });
      f.db.prepare("UPDATE host_certificates SET ca_id=?,ca_version=1 WHERE cert_id=?").run("9".repeat(64), "c".repeat(64));
    },
  ];
  for (const mutate of mutations) {
    const f = await fixture();
    try {
      mutate(f);
      withClaim(f, token => {
        let verdict: ReturnType<typeof f.reader.read> | undefined;
        f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, token); });
        assert.deepEqual(verdict, { ok: true, match: false });
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
    } finally { f.db.close(); }
  }
});

test("missing current host certificate or CA fails closed", async () => {
  for (const kind of ["host", "ca"] as const) {
    const f = await fixture();
    try {
      f.db.exec("PRAGMA foreign_keys=OFF");
      if (kind === "host") f.db.prepare("DELETE FROM host_certificates WHERE cert_id=?").run("c".repeat(64));
      if (kind === "ca") f.db.prepare("DELETE FROM certificate_authorities WHERE ca_id=?").run("b".repeat(64));
      f.db.exec("PRAGMA foreign_keys=ON");
      withClaim(f, token => {
        let verdict: ReturnType<typeof f.reader.read> | undefined;
        f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, token); });
        assert.deepEqual(verdict, { ok: true, match: false });
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
    } finally { f.db.close(); }
  }
});

test("latest-history drift and certificate assertion drift mismatch without spending the lease", async () => {
  for (const kind of ["history", "certificate"] as const) {
    const f = await fixture();
    try {
      if (kind === "certificate") f.setCandidate({ ...f.candidate, certificateBindingAssertion: { ...f.candidate.certificateBindingAssertion, address: "192.0.2.99" } });
      const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
      const claimed = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(claimed.ok);
      if (kind === "history") f.db.prepare("UPDATE job_history SET created_at=? WHERE job_id=?").run("2026-09-27T10:00:07.000Z", "job-1");
      let verdict: ReturnType<typeof f.reader.read> | undefined;
      f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, claimed.token); });
      assert.deepEqual(verdict, { ok: true, match: false });
      assert.deepEqual(f.registry.releaseLease(f.guard, claimed.token), { ok: true, released: true });
    } finally { f.db.close(); }
  }
});

test("queue/result state matrix preserves every valid retained intermediate and rejects contradictions", async () => {
  const valid: Array<{ state: string; result: "null" | "accepted" | "running" | "failed"; lease: string | null }> = [
    { state: "queued", result: "null", lease: null }, { state: "queued", result: "accepted", lease: null }, { state: "queued", result: "running", lease: null },
    { state: "leased", result: "null", lease: "2026-09-27T10:00:30.000Z" }, { state: "leased", result: "accepted", lease: "2026-09-27T10:00:30.000Z" }, { state: "leased", result: "running", lease: "2026-09-27T10:00:30.000Z" },
    { state: "completed", result: "failed", lease: null }, { state: "cancelled", result: "null", lease: null }, { state: "cancelled", result: "accepted", lease: null }, { state: "cancelled", result: "running", lease: null },
    { state: "expired", result: "null", lease: null }, { state: "expired", result: "accepted", lease: null }, { state: "expired", result: "running", lease: null },
  ];
  const invalid: Array<{ state: string; result: "null" | "accepted" | "running" | "failed"; lease: string | null }> = [
    { state: "completed", result: "null", lease: null }, { state: "completed", result: "accepted", lease: null }, { state: "completed", result: "running", lease: null },
    { state: "queued", result: "failed", lease: null }, { state: "leased", result: "failed", lease: "2026-09-27T10:00:30.000Z" },
    { state: "cancelled", result: "failed", lease: null }, { state: "expired", result: "failed", lease: null },
    { state: "leased", result: "null", lease: null }, { state: "queued", result: "null", lease: "2026-09-27T10:00:30.000Z" },
  ];
  for (const [cases, expected] of [[valid, true], [invalid, false]] as const) for (const item of cases) {
    const f = await fixture();
    try {
      let result: unknown = null;
      if (item.result === "failed") result = JSON.parse(Buffer.from(f.responseBytes).toString("utf8"));
      else if (item.result === "accepted" || item.result === "running") result = { ...responseObject(f), status: item.result, errorCode: null };
      f.db.prepare("UPDATE agent_commands SET state=?,lease_until=?,result_json=? WHERE job_id=?").run(item.state, item.lease, result === null ? null : JSON.stringify(result), "job-1");
      const before = JSON.stringify({ jobs: f.db.prepare("SELECT * FROM jobs").all(), history: f.db.prepare("SELECT * FROM job_history").all(), commands: f.db.prepare("SELECT * FROM agent_commands").all(), audit: f.db.prepare("SELECT * FROM audit_events").all(), cert: f.db.prepare("SELECT * FROM host_certificates").all(), ca: f.db.prepare("SELECT * FROM certificate_authorities").all(), owners: f.db.prepare("SELECT * FROM owners").all(), sessions: f.db.prepare("SELECT * FROM sessions").all() });
      withClaim(f, token => {
        let verdict: ReturnType<typeof f.reader.read> | undefined;
        f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, token); });
        assert.deepEqual(verdict, { ok: true, match: expected }, `${item.state}/${item.result}/${item.lease}`);
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
      const after = JSON.stringify({ jobs: f.db.prepare("SELECT * FROM jobs").all(), history: f.db.prepare("SELECT * FROM job_history").all(), commands: f.db.prepare("SELECT * FROM agent_commands").all(), audit: f.db.prepare("SELECT * FROM audit_events").all(), cert: f.db.prepare("SELECT * FROM host_certificates").all(), ca: f.db.prepare("SELECT * FROM certificate_authorities").all(), owners: f.db.prepare("SELECT * FROM owners").all(), sessions: f.db.prepare("SELECT * FROM sessions").all() });
      assert.equal(after, before, `${item.state}/${item.result} changed DB`);
    } finally { f.db.close(); }
  }
});

test("bounded strict JSON rejects duplicate keys, unsafe integers, invalid UTF-8, noncanonical times and deep nesting", async () => {
  const valid = { requestId: "request-1", jobId: "job-1", hostId: "host-1", sequence: 1, status: "failed", progress: null,
    observedAt: "2026-09-27T10:00:05.000Z", observation: null, errorCode: "ADAPTER_FAILED" };
  const duplicate = Buffer.from(JSON.stringify(valid).replace('"status":"failed"', '"status":"failed","status":"failed"'));
  const unsafe = Buffer.from(JSON.stringify(valid).replace('"observation":null', '"observation":9007199254740993'));
  const invalidUtf8 = Buffer.from([0xff, 0xfe, 0xfd]);
  const badTime = Buffer.from(JSON.stringify({ ...valid, observedAt: "2026-02-31T10:00:05.000Z" }));
  let nested: unknown = 1; for (let i = 0; i < 20; i++) nested = [nested];
  const deep = Buffer.from(JSON.stringify({ ...valid, observation: nested }));
  for (const raw of [duplicate, unsafe, invalidUtf8, badTime, deep]) {
    const f = await fixture();
    try {
      f.setCandidate(candidateWithResponse(f, raw));
      withClaim(f, token => {
        let verdict: ReturnType<typeof f.reader.read> | undefined;
        f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, token); });
        assert.deepEqual(verdict, { ok: true, match: false });
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
    } finally { f.db.close(); }
  }
  const f = await fixture();
  try {
    const badClockReader = new OwnerNativeEvidenceSnapshotReader(f.db, f.registry, { clock: () => "2026-09-27T10:00:06.1Z" });
    const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
    const claimed = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(claimed.ok);
    let verdict: ReturnType<typeof badClockReader.read> | undefined;
    f.stores.withAuditTransaction(tx => { verdict = badClockReader.read(f.guard, tx, claimed.token); });
    assert.deepEqual(verdict, { ok: true, match: false });
    assert.deepEqual(f.registry.releaseLease(f.guard, claimed.token), { ok: true, released: true });
  } finally { f.db.close(); }
});

test("job row, payload and every latest-history projection field are revalidated", async () => {
  const mutations: Array<(f: Awaited<ReturnType<typeof fixture>>) => void> = [
    f => { f.db.prepare("UPDATE jobs SET state='succeeded' WHERE job_id=?").run("job-1"); },
    f => { f.db.prepare("UPDATE jobs SET host_id='host-2' WHERE job_id=?").run("job-1"); },
    f => { f.db.prepare("UPDATE jobs SET submitted_at=? WHERE job_id=?").run("2026-09-27T09:59:59.000Z", "job-1"); },
    f => { f.db.prepare("UPDATE jobs SET updated_at=? WHERE job_id=?").run("2026-09-27T10:00:07.000Z", "job-1"); },
    f => { f.db.prepare("UPDATE jobs SET attempt=2 WHERE job_id=?").run("job-1"); },
    f => { f.db.prepare("UPDATE jobs SET idempotency_key='idem-2' WHERE job_id=?").run("job-1"); },
    f => { f.db.prepare("UPDATE job_history SET from_state='submitted' WHERE job_id=?").run("job-1"); },
    f => { f.db.prepare("UPDATE job_history SET to_state='cancelled' WHERE job_id=?").run("job-1"); },
    f => { f.db.prepare("UPDATE job_history SET attempt=2 WHERE job_id=?").run("job-1"); },
    f => { f.db.prepare("UPDATE job_history SET occurred_at=? WHERE job_id=?").run("2026-09-27T10:00:05.000Z", "job-1"); },
    f => { f.db.prepare("UPDATE job_history SET created_at=? WHERE job_id=?").run("2026-09-27T10:00:07.000Z", "job-1"); },
  ];
  for (const mutate of mutations) {
    const f = await fixture();
    try {
      mutate(f);
      withClaim(f, token => {
        let verdict: ReturnType<typeof f.reader.read> | undefined;
        f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, token); });
        assert.deepEqual(verdict, { ok: true, match: false });
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
    } finally { f.db.close(); }
  }
});

test("job payload duplicate keys and latest-history removal or revision change mismatch", async () => {
  for (const mutation of ["duplicate-payload", "missing-history", "new-history-id"] as const) {
    const f = await fixture();
    try {
      if (mutation === "duplicate-payload") {
        const row = f.db.prepare("SELECT payload_json FROM jobs WHERE job_id=?").get("job-1") as { payload_json: string };
        f.db.prepare("UPDATE jobs SET payload_json=? WHERE job_id=?").run(row.payload_json.replace('"state":"failed"', '"state":"running","state":"failed"'), "job-1");
      } else if (mutation === "missing-history") f.db.prepare("DELETE FROM job_history WHERE job_id=?").run("job-1");
      else f.db.prepare("UPDATE job_history SET history_id=history_id+10 WHERE job_id=?").run("job-1");
      withClaim(f, token => {
        let verdict: ReturnType<typeof f.reader.read> | undefined;
        f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, token); });
        assert.deepEqual(verdict, { ok: true, match: false }, mutation);
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
    } finally { f.db.close(); }
  }
});

test("certificate and CA current-record drift, revocation and expiry fail closed", async () => {
  const cases: Array<(f: Awaited<ReturnType<typeof fixture>>) => void> = [
    f => { f.db.prepare("UPDATE host_certificates SET binding_address=? WHERE cert_id=?").run("192.0.2.99", "c".repeat(64)); },
    f => { f.db.prepare("UPDATE host_certificates SET status='revoked',revoked_at=? WHERE cert_id=?").run(START, "c".repeat(64)); },
    f => { f.db.prepare("UPDATE host_certificates SET not_after=? WHERE cert_id=?").run("2026-09-27T09:59:59.000Z", "c".repeat(64)); },
    f => { f.db.prepare("UPDATE certificate_authorities SET not_before=? WHERE ca_id=?").run("2026-09-27T10:00:07.000Z", "b".repeat(64)); },
    f => { f.db.prepare("UPDATE certificate_authorities SET not_after=? WHERE ca_id=?").run("2026-09-27T09:59:59.000Z", "b".repeat(64)); },
    f => { f.db.prepare("UPDATE host_certificates SET ca_version=2 WHERE cert_id=?").run("c".repeat(64)); },
  ];
  for (const mutate of cases) {
    const f = await fixture();
    try {
      mutate(f);
      withClaim(f, token => {
        let verdict: ReturnType<typeof f.reader.read> | undefined;
        f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, token); });
        assert.deepEqual(verdict, { ok: true, match: false });
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
    } finally { f.db.close(); }
  }
});

test("tuple domain and candidate byte digest/length constraints fail at the intended boundary", async () => {
  const f = await fixture();
  try {
    for (const patch of [{ responseDigest: "0".repeat(64) }, { responseByteLength: f.responseBytes.length + 1 }]) {
      f.setCandidate({ ...f.candidate, tuple: { ...f.candidate.tuple, ...patch } as NativeEvidenceCandidateInput["tuple"] });
      assert.deepEqual(f.registry.prepare(f.guard).ok, false);
    }
    const exactCap = Buffer.concat([Buffer.from(f.responseBytes), Buffer.alloc(512 * 1024 - f.responseBytes.length, 0x20)]);
    f.setCandidate(candidateWithResponse(f, exactCap));
    withClaim(f, token => {
      let verdict: ReturnType<typeof f.reader.read> | undefined;
      f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, token); });
      assert.deepEqual(verdict, { ok: true, match: true });
      assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
    });
    const oversize = new Uint8Array(512 * 1024 + 1);
    f.setCandidate(candidateWithResponse(f, oversize));
    assert.deepEqual(f.registry.prepare(f.guard).ok, false);
    f.setCandidate(candidateWithResponse(f, f.responseBytes, { domain: "other-domain" }));
    withClaim(f, token => {
      let verdict: ReturnType<typeof f.reader.read> | undefined;
      f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, token); });
      assert.deepEqual(verdict, { ok: true, match: false });
      assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
    });
  } finally { f.db.close(); }
});

test("request bindings, the two digests and evidence-kind assertion are independent", async () => {
  const patches: Array<(request: any) => void> = [
    r => { r.jobId = "job-2"; }, r => { r.hostId = "host-2"; r.capability.hostId = "host-2"; r.capability.targetId = "host-2"; }, r => { r.requestId = "request-2"; },
    r => { r.idempotencyKey = "idem-2"; }, r => { r.sequence = 2; }, r => { r.deadline = "2026-09-27T10:04:00.000Z"; },
  ];
  for (const patch of patches) {
    const f = await fixture();
    try {
      const row = f.db.prepare("SELECT request_json FROM agent_commands WHERE job_id=?").get("job-1") as { request_json: string };
      const request = JSON.parse(row.request_json); patch(request); request.capability.requestDigest = "";
      request.capability.requestDigest = commandAuthorizationDigest(request);
      const parsed = parseCommandRequest(request); assert.ok(parsed.ok);
      f.db.prepare("UPDATE agent_commands SET request_json=?,request_digest=? WHERE job_id=?").run(JSON.stringify(parsed.value), createHash("sha256").update(JSON.stringify(parsed.value)).digest("hex"), "job-1");
      withClaim(f, token => {
        let verdict: ReturnType<typeof f.reader.read> | undefined;
        f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, token); });
        assert.deepEqual(verdict, { ok: true, match: false });
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
    } finally { f.db.close(); }
  }
  for (const tuplePatch of [{ authorizationRequestDigest: "0".repeat(64) }, { evidenceKind: "cancelled" }]) {
    const f = await fixture();
    try {
      f.setCandidate(candidateWithResponse(f, f.responseBytes, tuplePatch));
      withClaim(f, token => {
        let verdict: ReturnType<typeof f.reader.read> | undefined;
        f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, token); });
        assert.deepEqual(verdict, { ok: true, match: false });
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
    } finally { f.db.close(); }
  }
  const f = await fixture();
  try {
    f.db.prepare("UPDATE agent_commands SET request_digest=? WHERE job_id=?").run("0".repeat(64), "job-1");
    withClaim(f, token => {
      let verdict: ReturnType<typeof f.reader.read> | undefined;
      f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, token); });
      assert.deepEqual(verdict, { ok: true, match: false });
      assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
    });
  } finally { f.db.close(); }
});

test("each terminal response field mismatch is rejected and stored response JSON is strict", async () => {
  const base = { requestId: "request-1", jobId: "job-1", hostId: "host-1", sequence: 1, status: "failed", progress: null,
    observedAt: "2026-09-27T10:00:05.000Z", observation: { a: 1 }, errorCode: "ADAPTER_FAILED" };
  const storedChanges = [
    { ...base, status: "cancelled", errorCode: null }, { ...base, progress: 5 }, { ...base, observedAt: "2026-09-27T10:00:06.000Z" },
    { ...base, errorCode: "OTHER_FAILURE" }, { ...base, observation: { a: 2 } },
  ];
  for (const stored of storedChanges) {
    const f = await fixture();
    try {
      f.setCandidate(candidateWithResponse(f, Buffer.from(JSON.stringify(base))));
      f.db.prepare("UPDATE agent_commands SET result_json=? WHERE job_id=?").run(JSON.stringify(stored), "job-1");
      withClaim(f, token => {
        let verdict: ReturnType<typeof f.reader.read> | undefined;
        f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, token); });
        assert.deepEqual(verdict, { ok: true, match: false });
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
    } finally { f.db.close(); }
  }
  const malformedStored = [
    JSON.stringify(base).replace('"status":"failed"', '"status":"failed","status":"failed"'),
    JSON.stringify(base).replace('"observation":{"a":1}', '"observation":9007199254740993'),
    JSON.stringify({ ...base, observedAt: "2026-02-31T10:00:05.000Z" }),
  ];
  for (const raw of malformedStored) {
    const f = await fixture();
    try {
      f.setCandidate(candidateWithResponse(f, Buffer.from(JSON.stringify(base))));
      f.db.prepare("UPDATE agent_commands SET result_json=? WHERE job_id=?").run(raw, "job-1");
      withClaim(f, token => {
        let verdict: ReturnType<typeof f.reader.read> | undefined;
        f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, token); });
        assert.deepEqual(verdict, { ok: true, match: false });
        assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
      });
    } finally { f.db.close(); }
  }
});

test("reader authority requires the exact active DB transaction and authentic live guard", async () => {
  const f = await fixture(), foreignDb = openControllerDatabase(":memory:");
  try {
    const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
    const claimed = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(claimed.ok);
    const invalidGuard = guardManagementRequest(f.sessions, ORIGINS, { method: "POST", cookieHeader: "", originHeader: "https://manager.example", csrfHeader: f.session.csrfToken });
    const foreignStores = createJobStores(foreignDb);
    let foreignResult: ReturnType<typeof f.reader.read> | undefined;
    foreignStores.withAuditTransaction(tx => { foreignResult = f.reader.read(f.guard, tx, claimed.token); });
    assert.deepEqual(foreignResult, { ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" });
    let guardResult: ReturnType<typeof f.reader.read> | undefined;
    f.stores.withAuditTransaction(tx => { guardResult = f.reader.read(invalidGuard, tx, claimed.token); });
    assert.deepEqual(guardResult, { ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" });
    let goodResult: ReturnType<typeof f.reader.read> | undefined;
    f.stores.withAuditTransaction(tx => { goodResult = f.reader.read(f.guard, tx, claimed.token); });
    assert.deepEqual(goodResult, { ok: true, match: true });
    assert.deepEqual(f.registry.releaseLease(f.guard, claimed.token), { ok: true, released: true });
  } finally { foreignDb.close(); f.db.close(); }
});

test("revoke, owner disablement, credential/session rotation, and expiry fail closed", async () => {
  for (const change of ["revoke", "disable", "credential", "session-version", "idle-expiry", "absolute-expiry"] as const) {
    const f = await fixture();
    try {
      const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
      const claimed = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(claimed.ok);
      const ownerId = f.db.prepare("SELECT owner_id FROM owners").get() as { owner_id: string };
      if (change === "revoke") assert.equal(f.sessions.revoke(f.session.sessionToken), true);
      else if (change === "disable") f.db.prepare("UPDATE owners SET disabled=1 WHERE owner_id=?").run(ownerId.owner_id);
      else if (change === "credential") f.db.prepare("UPDATE owners SET credential_version=credential_version+1 WHERE owner_id=?").run(ownerId.owner_id);
      else if (change === "session-version") f.db.prepare("UPDATE sessions SET session_version=session_version+1 WHERE owner_id=?").run(ownerId.owner_id);
      else {
        f.db.prepare(`UPDATE sessions SET ${change === "idle-expiry" ? "idle_expires_at" : "absolute_expires_at"}=? WHERE owner_id=?`).run("2026-09-27T09:59:59.000Z", ownerId.owner_id);
      }
      let result: ReturnType<typeof f.reader.read> | undefined;
      f.stores.withAuditTransaction(tx => { result = f.reader.read(f.guard, tx, claimed.token); });
      assert.deepEqual(result, { ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" }, change);
    } finally { f.db.close(); }
  }
});

test("mismatch is fixed and does not settle the lease; invalid transaction fails before SQL", async () => {
  const f = await fixture();
  try {
    const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
    const claimed = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(claimed.ok);
    const before = f.db.prepare("SELECT COUNT(*) AS n FROM jobs").get() as { n: number };
    assert.deepEqual(f.reader.read(f.guard, {}, claimed.token), { ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" });
    f.db.prepare("UPDATE agent_commands SET request_digest=? WHERE job_id=?").run("0".repeat(64), "job-1");
    let verdict: ReturnType<typeof f.reader.read> | undefined;
    f.stores.withAuditTransaction(tx => { verdict = f.reader.read(f.guard, tx, claimed.token); });
    assert.deepEqual(verdict, { ok: true, match: false });
    assert.equal((f.db.prepare("SELECT COUNT(*) AS n FROM jobs").get() as { n: number }).n, before.n);
    assert.deepEqual(f.registry.releaseLease(f.guard, claimed.token), { ok: true, released: true });
  } finally { f.db.close(); }
});


test("reader clock callbacks run before authoritative snapshot reads", async t => {
  for (const change of ["certificate-revocation", "job-revision", "queue-integrity", "ca-expiry"] as const) {
    await t.test(change, async () => {
      const f = await fixture();
      try {
        const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
        const lease = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(lease.ok);
        let clockCalls = 0;
        const reader = new OwnerNativeEvidenceSnapshotReader(f.db, f.registry, { clock: () => {
          clockCalls++;
          // Deliberate external callback mutations: the reader must observe them,
          // not claim that rows selected before this callback are still current.
          if (change === "certificate-revocation") f.db.prepare("UPDATE host_certificates SET status='revoked',revoked_at=? WHERE candidate_id=?").run(START, "host-1");
          if (change === "job-revision") f.db.prepare("UPDATE jobs SET updated_at=? WHERE job_id=?").run("2026-09-27T10:00:07.000Z", "job-1");
          if (change === "queue-integrity") f.db.prepare("UPDATE agent_commands SET request_digest=? WHERE job_id=?").run("0".repeat(64), "job-1");
          if (change === "ca-expiry") f.db.prepare("UPDATE certificate_authorities SET not_after=?").run("2026-09-27T09:59:59.000Z");
          return "2026-09-27T10:00:06.000Z";
        } });
        let result: ReturnType<typeof reader.read> | undefined;
        f.stores.withAuditTransaction(tx => { result = reader.read(f.guard, tx, lease.token); });
        assert.equal(clockCalls, 1);
        assert.deepEqual(result, { ok: true, match: false }, "clock callback invalidation must precede every authoritative read");
        assert.deepEqual(f.registry.releaseLease(f.guard, lease.token), { ok: true, released: true });
      } finally { f.db.close(); }
    });
  }
});

test("reader converts a throwing clock callback to fixed mismatch and leaves lease unsettled", async () => {
  const f = await fixture();
  try {
    const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
    const claimed = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(claimed.ok);
    const reader = new OwnerNativeEvidenceSnapshotReader(f.db, f.registry, { clock: () => { throw new Error("synthetic clock failure"); } });
    let verdict: ReturnType<typeof reader.read> | undefined;
    f.stores.withAuditTransaction(tx => { verdict = reader.read(f.guard, tx, claimed.token); });
    assert.deepEqual(verdict, { ok: true, match: false });
    assert.deepEqual(f.registry.releaseLease(f.guard, claimed.token), { ok: true, released: true });
  } finally { f.db.close(); }
});

test("matched append couples one evidence row and audit while leaving the lease provisional", async () => {
  const f = await fixture();
  const foreignDb = openControllerDatabase(":memory:");
  try {
    const auditBefore = (f.db.prepare("SELECT count(*) AS n FROM audit_events").get() as { n: number }).n;
    const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
    const claimed = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(claimed.ok);
    const coordinator = new OwnerNativeEvidenceMatchedAppendCoordinator(f.db, f.registry);
    let foreign: ReturnType<typeof coordinator.append> | undefined;
    createJobStores(foreignDb).withAuditTransaction(tx => { foreign = coordinator.append(f.guard, tx, claimed.token,
      { hostCertificateBindingDigest: "e".repeat(64), consentedAt: START }); });
    assert.deepEqual(foreign, { ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" });
    const protectedBefore = protectedState(f.db);
    let result: ReturnType<typeof coordinator.append> | undefined;
    let expectedSessionId: string | undefined;
    f.stores.withAuditTransaction(tx => {
      expectedSessionId = f.sessions.bindingInTransaction(tx, f.guard.session)?.id;
      result = coordinator.append(f.guard, tx, claimed.token, { hostCertificateBindingDigest: "e".repeat(64), consentedAt: START });
    });
    assert.equal(result?.ok, true);
    if (result?.ok) { assert.equal(result.match, true); assert.equal(result.append?.ok, true); }
    assert.equal((f.db.prepare("SELECT count(*) AS n FROM supplemental_native_evidence").get() as { n: number }).n, 1);
    assert.equal((f.db.prepare("SELECT count(*) AS n FROM audit_events").get() as { n: number }).n, auditBefore + 1);
    assert.equal(protectedState(f.db), protectedBefore, "matched append must preserve lifecycle, certificate, owner and session rows");
    const stored = f.db.prepare("SELECT tuple_digest,owner_id,session_binding_digest,credential_version,host_certificate_binding_digest,consented_at FROM supplemental_native_evidence").get() as Record<string, unknown>;
    assert.equal(stored.tuple_digest, f.candidate.tupleDigest);
    assert.equal(stored.owner_id, "a".repeat(32));
    assert.equal(stored.session_binding_digest, expectedSessionId, "session binding must be copied directly from the live server binding");
    assert.equal(stored.credential_version, 1);
    assert.equal(stored.host_certificate_binding_digest, "e".repeat(64));
    assert.equal(stored.consented_at, START);
    assert.deepEqual(f.registry.releaseLease(f.guard, claimed.token), { ok: true, released: true });
  } finally { foreignDb.close(); f.db.close(); }
});

test("matched append exact duplicate is idempotent and changed assertion conflicts atomically", async () => {
  const f = await fixture();
  try {
    const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
    const claimed = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(claimed.ok);
    const coordinator = new OwnerNativeEvidenceMatchedAppendCoordinator(f.db, f.registry);
    const assertion = { hostCertificateBindingDigest: "e".repeat(64), consentedAt: START };
    let first: ReturnType<typeof coordinator.append> | undefined;
    f.stores.withAuditTransaction(tx => { first = coordinator.append(f.guard, tx, claimed.token, assertion); });
    let duplicate: ReturnType<typeof coordinator.append> | undefined;
    f.stores.withAuditTransaction(tx => { duplicate = coordinator.append(f.guard, tx, claimed.token, assertion); });
    assert.equal(first?.ok, true); assert.equal(duplicate?.ok, true);
    if (duplicate?.ok) assert.equal(duplicate.append?.ok && duplicate.append.duplicate, true);
    const evidenceCount = (f.db.prepare("SELECT count(*) AS n FROM supplemental_native_evidence").get() as { n: number }).n;
    const auditCount = (f.db.prepare("SELECT count(*) AS n FROM audit_events").get() as { n: number }).n;
    assert.equal(evidenceCount, 1);
    assert.throws(() => f.stores.withAuditTransaction(tx => coordinator.append(f.guard, tx, claimed.token,
      { ...assertion, consentedAt: "2026-09-27T10:00:01.000Z" })), { message: "ERR_NATIVE_EVIDENCE_MATCHED_APPEND_ABORT" });
    assert.equal((f.db.prepare("SELECT count(*) AS n FROM supplemental_native_evidence").get() as { n: number }).n, evidenceCount);
    assert.equal((f.db.prepare("SELECT count(*) AS n FROM audit_events").get() as { n: number }).n, auditCount);
    assert.deepEqual(f.registry.releaseLease(f.guard, claimed.token), { ok: true, released: true });
  } finally { f.db.close(); }
});

test("matched append mismatch and hostile consent descriptors do not append or invoke getters", async () => {
  const f = await fixture();
  try {
    const auditBefore = (f.db.prepare("SELECT count(*) AS n FROM audit_events").get() as { n: number }).n;
    const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
    const claimed = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(claimed.ok);
    const coordinator = new OwnerNativeEvidenceMatchedAppendCoordinator(f.db, f.registry);
    let getterCalls = 0;
    const accessor = Object.defineProperties({}, { hostCertificateBindingDigest: { get() { getterCalls++; return "e".repeat(64); }, enumerable: true }, consentedAt: { value: START, enumerable: true } });
    let bad: ReturnType<typeof coordinator.append> | undefined;
    f.stores.withAuditTransaction(tx => { bad = coordinator.append(f.guard, tx, claimed.token, accessor); });
    assert.deepEqual(bad, { ok: true, match: false, append: null });
    assert.equal(getterCalls, 0);
    let proxyTraps = 0;
    let proxied: ReturnType<typeof coordinator.append> | undefined;
    f.stores.withAuditTransaction(tx => { proxied = coordinator.append(f.guard, tx, claimed.token, new Proxy({}, { ownKeys() { proxyTraps++; return []; } })); });
    assert.deepEqual(proxied, { ok: true, match: false, append: null });
    assert.equal(proxyTraps, 0);
    f.db.prepare("UPDATE agent_commands SET request_digest=? WHERE job_id=?").run("0".repeat(64), "job-1");
    let mismatch: ReturnType<typeof coordinator.append> | undefined;
    f.stores.withAuditTransaction(tx => { mismatch = coordinator.append(f.guard, tx, claimed.token, { hostCertificateBindingDigest: "e".repeat(64), consentedAt: START }); });
    assert.deepEqual(mismatch, { ok: true, match: false, append: null });
    assert.equal((f.db.prepare("SELECT count(*) AS n FROM supplemental_native_evidence").get() as { n: number }).n, 0);
    assert.equal((f.db.prepare("SELECT count(*) AS n FROM audit_events").get() as { n: number }).n, auditBefore);
    assert.deepEqual(f.registry.releaseLease(f.guard, claimed.token), { ok: true, released: true });
  } finally { f.db.close(); }
});

test("real post-callback registry recheck failure forces fixed abort and rolls back evidence", async () => {
  const f = await fixture();
  try {
    const auditBefore = (f.db.prepare("SELECT count(*) AS n FROM audit_events").get() as { n: number }).n;
    const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
    const claimed = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(claimed.ok);
    const coordinator = new OwnerNativeEvidenceMatchedAppendCoordinator(f.db, f.registry);
    let invalidated = false;
    f.setRegistryClockHook(() => {
      const rows = (f.db.prepare("SELECT count(*) AS n FROM supplemental_native_evidence").get() as { n: number }).n;
      if (rows === 1 && !invalidated) {
        invalidated = true;
        f.db.prepare("UPDATE owners SET credential_version=credential_version+1").run();
      }
    });
    assert.throws(() => f.stores.withAuditTransaction(tx => coordinator.append(f.guard, tx, claimed.token,
      { hostCertificateBindingDigest: "e".repeat(64), consentedAt: START })), { message: "ERR_NATIVE_EVIDENCE_MATCHED_APPEND_ABORT" });
    assert.equal(invalidated, true, "clock hook must run after the callback's evidence INSERT");
    assert.equal((f.db.prepare("SELECT count(*) AS n FROM supplemental_native_evidence").get() as { n: number }).n, 0);
    assert.equal((f.db.prepare("SELECT count(*) AS n FROM audit_events").get() as { n: number }).n, auditBefore);
    assert.equal((f.db.prepare("SELECT credential_version FROM owners").get() as { credential_version: number }).credential_version, 1);
    f.setRegistryClockHook(() => undefined);
    assert.deepEqual(f.registry.releaseLease(f.guard, claimed.token), { ok: true, released: true });
  } finally { f.db.close(); }
});

test("audit insertion and deferred COMMIT failures roll back evidence without settling the lease", async () => {
  for (const failure of ["audit", "commit"] as const) {
    const f = await fixture();
    try {
      const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
      const claimed = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }); assert.ok(claimed.ok);
      const coordinator = new OwnerNativeEvidenceMatchedAppendCoordinator(f.db, f.registry);
      const auditBefore = (f.db.prepare("SELECT count(*) AS n FROM audit_events").get() as { n: number }).n;
      if (failure === "audit") f.db.exec("CREATE TRIGGER reject_matched_append_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END");
      assert.throws(() => f.stores.withAuditTransaction(tx => {
        coordinator.append(f.guard, tx, claimed.token, { hostCertificateBindingDigest: "e".repeat(64), consentedAt: START });
        if (failure === "commit") f.db.prepare("DELETE FROM evidence_commit_guard WHERE guard_id=1").run();
      }));
      if (f.db.isTransaction) f.db.exec("ROLLBACK");
      assert.equal((f.db.prepare("SELECT count(*) AS n FROM supplemental_native_evidence").get() as { n: number }).n, 0, failure);
      assert.equal((f.db.prepare("SELECT count(*) AS n FROM audit_events").get() as { n: number }).n, auditBefore, failure);
      assert.deepEqual(f.registry.releaseLease(f.guard, claimed.token), { ok: true, released: true }, failure);
    } finally { f.db.close(); }
  }
});

function newLease(f: Awaited<ReturnType<typeof fixture>>) {
  const prepared = f.registry.prepare(f.guard); assert.ok(prepared.ok);
  const claimed = f.registry.claim(f.guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION });
  assert.ok(claimed.ok); return claimed.token;
}
const ASSERTION = Object.freeze({ hostCertificateBindingDigest: "e".repeat(64), consentedAt: START });
function evidenceCount(f: Awaited<ReturnType<typeof fixture>>) {
  return (f.db.prepare("SELECT count(*) AS n FROM supplemental_native_evidence").get() as { n: number }).n;
}
function auditCount(f: Awaited<ReturnType<typeof fixture>>) {
  return (f.db.prepare("SELECT count(*) AS n FROM audit_events").get() as { n: number }).n;
}

test("transaction owner commits one evidence/audit pair before settling the exact lease", async () => {
  const f = await fixture();
  try {
    const auditBefore = auditCount(f), beforeProtected = protectedState(f.db), token = newLease(f), owner = new OwnerNativeEvidenceTransactionOwner(f.db, f.registry);
    let sawCommitBeforeSettlement = false;
    f.setRegistryClockHook(() => {
      if (evidenceCount(f) === 1 && !f.db.isTransaction) sawCommitBeforeSettlement = true;
    });
    assert.deepEqual(owner.append(f.guard, token, ASSERTION), { outcome: "committed_append_settled" });
    assert.equal(sawCommitBeforeSettlement, true);
    assert.equal(evidenceCount(f), 1); assert.equal(auditCount(f), auditBefore + 1);
    const stored = f.db.prepare("SELECT tuple_digest,owner_id,session_binding_digest,credential_version,host_certificate_binding_digest,consented_at,receipt_core_json FROM supplemental_native_evidence").get() as Record<string, unknown>;
    assert.equal(stored.tuple_digest, f.candidate.tupleDigest); assert.equal(stored.owner_id, "a".repeat(32));
    assert.equal(stored.credential_version, 1); assert.equal(stored.host_certificate_binding_digest, ASSERTION.hostCertificateBindingDigest);
    assert.equal(stored.consented_at, START);
    const core = JSON.parse(String(stored.receipt_core_json)) as Record<string, unknown>;
    assert.equal(core.domain, "lanmm-native-evidence-storage-core-v1");
    assert.equal(core.disposition, "evidence-only"); assert.equal(core.tupleDigest, stored.tuple_digest);
    assert.equal(typeof core.receiptId, "string"); assert.equal(typeof core.consentBindingDigest, "string");
    assert.equal(protectedState(f.db), beforeProtected, "append preserves lifecycle and authority rows");
    assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" });
  } finally { f.db.close(); }
});

test("transaction owner rolls back after the real post-view session recheck fails", async () => {
  const f = await fixture();
  try {
    const beforeAudit = auditCount(f), token = newLease(f), owner = new OwnerNativeEvidenceTransactionOwner(f.db, f.registry);
    let invalidated = false;
    f.setRegistryClockHook(() => {
      if (evidenceCount(f) === 1 && !invalidated) {
        invalidated = true;
        f.db.prepare("UPDATE owners SET credential_version=credential_version+1").run();
      }
    });
    assert.deepEqual(owner.append(f.guard, token, ASSERTION), { outcome: "transaction_unknown" });
    assert.equal(invalidated, true); assert.equal(evidenceCount(f), 0); assert.equal(auditCount(f), beforeAudit);
    f.setRegistryClockHook(() => undefined);
    assert.equal((f.db.prepare("SELECT credential_version FROM owners").get() as { credential_version: number }).credential_version, 1, "session mutation rolled back with the append transaction");
    assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true }, "lease remains unsettled after rollback");
  } finally { f.db.close(); }
});

test("transaction owner treats audit and deferred foreign-key COMMIT failures as unknown and unsettled", async () => {
  for (const kind of ["audit", "commit"] as const) {
    const f = await fixture();
    try {
      const beforeAudit = auditCount(f), token = newLease(f), owner = new OwnerNativeEvidenceTransactionOwner(f.db, f.registry);
      if (kind === "audit") f.db.exec("CREATE TRIGGER reject_owner_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END");
      else f.db.exec("CREATE TABLE owner_commit_parent(id INTEGER PRIMARY KEY); CREATE TABLE owner_commit_child(parent_id INTEGER REFERENCES owner_commit_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER owner_deferred_failure AFTER INSERT ON supplemental_native_evidence BEGIN INSERT INTO owner_commit_child(parent_id) VALUES(987654); END");
      assert.deepEqual(owner.append(f.guard, token, ASSERTION), { outcome: "transaction_unknown" }, kind);
      assert.equal(evidenceCount(f), 0, kind); assert.equal(auditCount(f), beforeAudit, kind);
      assert.equal(f.db.isTransaction, false, "owner cleanup completes the real failed transaction");
      assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true }, "no settlement on transaction failure");
    } finally { f.db.close(); }
  }
});

test("transaction owner returns committed no-append for malformed, proxy, and mismatched assertions", async () => {
  const f = await fixture();
  try {
    const beforeAudit = auditCount(f), token = newLease(f), owner = new OwnerNativeEvidenceTransactionOwner(f.db, f.registry);
    let getterCalls = 0;
    const accessor = Object.defineProperties({}, { hostCertificateBindingDigest: { get() { getterCalls++; return ASSERTION.hostCertificateBindingDigest; }, enumerable: true }, consentedAt: { value: START, enumerable: true } });
    assert.deepEqual(owner.append(f.guard, token, accessor), { outcome: "committed_no_append" });
    assert.deepEqual(owner.append(f.guard, token, new Proxy({}, { ownKeys() { throw new Error("must not inspect proxy"); } })), { outcome: "committed_no_append" });
    assert.equal(getterCalls, 0);
    f.db.prepare("UPDATE agent_commands SET request_digest=? WHERE job_id=?").run("0".repeat(64), "job-1");
    const beforeMismatch = protectedState(f.db);
    assert.deepEqual(owner.append(f.guard, token, ASSERTION), { outcome: "committed_no_append" });
    assert.equal(evidenceCount(f), 0); assert.equal(auditCount(f), beforeAudit);
    assert.equal(protectedState(f.db), beforeMismatch, "mismatch operation preserves all protected rows");
    assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: true, released: true });
  } finally { f.db.close(); }
});

test("transaction owner uses fresh leases for exact duplicate and conflicting assertion", async () => {
  const f = await fixture();
  try {
    const owner = new OwnerNativeEvidenceTransactionOwner(f.db, f.registry), beforeAudit = auditCount(f);
    assert.deepEqual(owner.append(f.guard, newLease(f), ASSERTION), { outcome: "committed_append_settled" });
    const original = JSON.stringify(f.db.prepare("SELECT * FROM supplemental_native_evidence").get());
    assert.deepEqual(owner.append(f.guard, newLease(f), ASSERTION), { outcome: "committed_append_settled" });
    assert.equal(evidenceCount(f), 1); assert.equal(auditCount(f), beforeAudit + 1);
    const conflict = { hostCertificateBindingDigest: ASSERTION.hostCertificateBindingDigest, consentedAt: "2026-09-27T10:00:01.000Z" }, conflictToken = newLease(f);
    assert.deepEqual(owner.append(f.guard, conflictToken, conflict), { outcome: "transaction_unknown" });
    assert.equal(JSON.stringify(f.db.prepare("SELECT * FROM supplemental_native_evidence").get()), original);
    assert.equal(auditCount(f), beforeAudit + 1);
    assert.deepEqual(f.registry.releaseLease(f.guard, conflictToken), { ok: true, released: true }, "conflict does not settle the fresh lease");
  } finally { f.db.close(); }
});

test("post-commit settlement unavailable preserves the known DB commit without retry", async () => {
  const f = await fixture();
  try {
    const token = newLease(f), beforeAudit = auditCount(f), owner = new OwnerNativeEvidenceTransactionOwner(f.db, f.registry);
    let registryClosedAfterCommit = false;
    f.setRegistryClockHook(() => {
      if (!registryClosedAfterCommit && evidenceCount(f) === 1 && !f.db.isTransaction) {
        registryClosedAfterCommit = true;
        f.registry.close();
      }
    });
    assert.deepEqual(owner.append(f.guard, token, ASSERTION), { outcome: "committed_append_unsettled" });
    assert.equal(registryClosedAfterCommit, true); assert.equal(f.db.isTransaction, false);
    assert.equal(evidenceCount(f), 1); assert.equal(auditCount(f), beforeAudit + 1);
    assert.deepEqual(f.registry.releaseLease(f.guard, token), { ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" }, "failed settlement did not release/retry the lease");
  } finally { f.db.close(); }
});
