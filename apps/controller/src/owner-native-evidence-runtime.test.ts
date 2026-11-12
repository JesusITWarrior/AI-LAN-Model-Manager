import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { commandAuthorizationDigest, commandPolicyOperation, type CommandRequest, type CommandResponse } from "@lan-model-manager/core";
import { openControllerDatabase } from "./database.js";
import { createOwnerBootstrapService } from "./owner-service.js";
import type { PasswordCryptoEngine } from "./credentials.js";
import { SessionManager } from "./session-manager.js";
import { OwnerNativeEvidenceCandidateRegistry } from "./owner-native-evidence-candidates.js";
import { createOwnerNativeEvidenceRuntime } from "./owner-native-evidence-runtime.js";
import { CertificateRepository } from "./certificate-repository.js";
import { OpenSslCertificateEngine } from "./certificate-adapter.js";
import { AgentCommandStore } from "./agent-command-channel.js";
import { CommandDispatcher } from "./command-dispatch.js";
import { createJobStores } from "./jobs-store.js";
import { buildOwnerNativeEvidenceSnapshot } from "./owner-native-evidence-snapshot.js";
import { encodeNativeTerminalEvidence } from "./native-terminal-evidence-codec.js";

const clock = () => "2026-09-27T10:00:00.000Z";
const crypto: PasswordCryptoEngine = {
  random: n => Buffer.alloc(n, 3),
  async derive(password, salt, parameters) {
    const seed = createHash("sha256").update(password).update(salt).digest();
    return Buffer.alloc(parameters.keyLength, seed[0]);
  },
  equal: (a, b) => Buffer.from(a).equals(Buffer.from(b)),
};
async function fixture() {
  const db = openControllerDatabase(":memory:");
  const owners = createOwnerBootstrapService(db, { now: clock, ownerId: () => "a".repeat(32), crypto });
  await owners.bootstrapOwner({ username: "Owner", password: "owner-password-123" });
  const sessions = new SessionManager(db, owners, { clock, random: n => Buffer.alloc(n, 4), policy: { absoluteTtlMs: 3600000, idleTtlMs: 600000, touchAfterMs: 60000 } });
  const session = await sessions.create({ username: "owner", password: "owner-password-123" });
  assert.ok(session);
  return { db, sessions, session };
}
async function trustedEvidenceFixture() {
  const db = openControllerDatabase(":memory:"), root = mkdtempSync(join(tmpdir(), "lanmm-runtime-evidence-"));
  const caDir = join(root, "ca"), hostDir = join(root, "host"); mkdirSync(hostDir, { mode: 0o700 });
  let now = new Date(Date.now() - 10_000).toISOString(), random = 0;
  try {
    const owners = createOwnerBootstrapService(db, { now: () => now, ownerId: () => "a".repeat(32), crypto });
    await owners.bootstrapOwner({ username: "Owner", password: "owner-password-123" });
    const stores = createJobStores(db, { now: () => now });
    const operation = "probe", requestId = "request-1", jobId = "job-1", hostId = "host-1";
    const request: CommandRequest = { requestId, jobId, hostId, operation, idempotencyKey: "idem-1", sequence: 1,
      deadline: new Date(Date.parse(now) + 300_000).toISOString(), capability: { operation: commandPolicyOperation(operation),
        targetKind: "host", targetId: hostId, hostId, modelId: null, requestDigest: "", expiresAt: new Date(Date.parse(now) + 300_000).toISOString() },
      params: { providerId: "provider-1", model: "model:latest" } };
    (request.capability as { requestDigest: string }).requestDigest = commandAuthorizationDigest(request);
    const commandStore = new AgentCommandStore(db, () => now, 30_000, stores);
    assert.equal(new CommandDispatcher(stores, commandStore, () => now).dispatch(request).ok, true);
    assert.ok(commandStore.poll(hostId).command);
    const response: CommandResponse = { requestId, jobId, hostId, sequence: 1, status: "failed", progress: null,
      observedAt: new Date(Date.parse(now) + 1000).toISOString(), observation: null, errorCode: "ADAPTER_FAILED" };
    now = response.observedAt;
    assert.ok(commandStore.complete(hostId, response));
    const engine = new OpenSslCertificateEngine();
    const ca = engine.initializeCa({ directory: caDir, now: new Date(Date.now() - 2_000).toISOString() });
    execFileSync("openssl", ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", join(hostDir, "key.pem")], { stdio: "ignore" });
    execFileSync("openssl", ["req", "-new", "-key", join(hostDir, "key.pem"), "-subj", `/CN=${hostId}`,
      "-addext", `subjectAltName=IP:192.0.2.10,URI:spiffe://lanmodelmanager/host/${hostId}`, "-out", join(hostDir, "request.pem")], { stdio: "ignore" });
    const certNow = new Date().toISOString(), binding = { candidateId: hostId, address: "192.0.2.10", port: 7443, protocolMajor: 1, protocolMinor: 0 };
    const issued = engine.issueHost({ directory: caDir, csrPem: readFileSync(join(hostDir, "request.pem"), "utf8"), binding, serial: "ABCDEF1234", now: certNow });
    const certs = new CertificateRepository(db); certs.insertCa(ca);
    certs.insertHost({ certificateId: issued.fingerprint, serial: issued.serial, fingerprint: issued.fingerprint, certificatePem: issued.certificatePem,
      caId: ca.caId, caVersion: ca.version, binding, spiffeUri: `spiffe://lanmodelmanager/host/${hostId}`, challengeId: "e".repeat(64),
      transcriptDigest: "f".repeat(64), notBefore: issued.notBefore, notAfter: issued.notAfter, status: "active", version: 1,
      issuedAt: certNow, revokedAt: null });
    now = new Date().toISOString();
    const currentOwners = createOwnerBootstrapService(db, { now: () => now, ownerId: () => "a".repeat(32), crypto });
    const sessions = new SessionManager(db, currentOwners, { clock: () => now, random: n => Buffer.alloc(n, ++random),
      policy: { absoluteTtlMs: 3600000, idleTtlMs: 600000, touchAfterMs: 60000 } });
    const session = await sessions.create({ username: "owner", password: "owner-password-123" }); assert.ok(session);
    const builtResult: { value: ReturnType<typeof buildOwnerNativeEvidenceSnapshot> } = { value: null };
    stores.withAuditTransaction(tx => { builtResult.value = buildOwnerNativeEvidenceSnapshot(db, tx, jobId, Buffer.from(JSON.stringify(response)), "synthetic", now); });
    const built = builtResult.value;
    assert.ok(built);
    const encoded = encodeNativeTerminalEvidence(built.snapshot); assert.ok(encoded.ok);
    return { db, root, sessions, session, raw: Buffer.from(encoded.payloadBase64, "base64"), clock: () => now };
  } catch (error) { db.close(); rmSync(root, { recursive: true, force: true }); throw error; }
}
function observingSessions(real: SessionManager) {
  const counts = { authenticate: 0, authenticateCsrf: 0 };
  const sessions = new Proxy(real, { get(target, property) {
    const value = Reflect.get(target, property, target);
    if (property === "authenticate" || property === "authenticateCsrf") return (...args: unknown[]) => {
      counts[property]++;
      return (value as (...values: unknown[]) => unknown).apply(target, args);
    };
    return typeof value === "function" ? value.bind(target) : value;
  } });
  return { sessions: sessions as SessionManager, counts };
}
const prepareRequest = (session: NonNullable<Awaited<ReturnType<typeof fixture>>["session"]>, origin: string) => ({
  method: "POST", path: "/api/v1/native-evidence/prepare", cookieHeader: `__Host-lanmm_session=${session.sessionToken}`,
  originHeader: origin, csrfHeader: session.csrfToken, jobSelector: "job-1", rawPayloadBytes: Uint8Array.of(0x7b),
});
const confirmRequest = (session: NonNullable<Awaited<ReturnType<typeof fixture>>["session"]>, origin: string) => ({
  method: "POST", path: "/api/v1/native-evidence/confirm", cookieHeader: `__Host-lanmm_session=${session.sessionToken}`,
  originHeader: origin, csrfHeader: session.csrfToken, body: JSON.stringify({ candidateHandle: "A", expectedTupleDigest: "a".repeat(64),
    action: "append-supplemental-native-evidence", disposition: "evidence-only" }),
});

test("runtime preserves HTTPS defaults and reaches real intake and confirm guards with shared loopback opt-in", async () => {
  const f = await fixture(), observed = observingSessions(f.sessions);
  try {
    const httpsRuntime = createOwnerNativeEvidenceRuntime({ db: f.db, sessions: observed.sessions, allowedOrigins: ["https://manager.example"], clock });
    assert.equal(httpsRuntime.prepare(prepareRequest(f.session!, "https://manager.example")).ok, false);
    assert.deepEqual(observed.counts, { authenticate: 1, authenticateCsrf: 1 }, "HTTPS remains the default origin policy");
    httpsRuntime.close(); observed.counts.authenticate = 0; observed.counts.authenticateCsrf = 0;
    assert.throws(() => createOwnerNativeEvidenceRuntime({ db: f.db, sessions: observed.sessions, allowedOrigins: ["http://127.0.0.1:7340"], clock }), /ERR_ORIGIN_POLICY/);
    const origins = ["http://127.0.0.1:7340"], options = { allowLoopbackHttpDevelopment: true };
    const runtime = createOwnerNativeEvidenceRuntime({ db: f.db, sessions: observed.sessions, allowedOrigins: origins, clock, originOptions: options });
    origins[0] = "https://evil.example";
    options.allowLoopbackHttpDevelopment = false;
    assert.equal(runtime.prepare(prepareRequest(f.session!, "http://127.0.0.1:7340")).ok, false);
    assert.deepEqual(observed.counts, { authenticate: 1, authenticateCsrf: 1 }, "intake guard accepted the explicit loopback origin before payload validation");
    assert.deepEqual(runtime.confirm(confirmRequest(f.session!, "http://127.0.0.1:7340")), { outcome: "stale" });
    assert.deepEqual(observed.counts, { authenticate: 2, authenticateCsrf: 2 }, "confirm guard accepted the same loopback origin policy");
    assert.deepEqual(runtime.confirm(confirmRequest(f.session!, "https://evil.example")), { outcome: "denied" });
    assert.deepEqual(observed.counts, { authenticate: 3, authenticateCsrf: 2 }, "unlisted origin is rejected before CSRF authentication");
    const auditBeforeDenials = Number((f.db.prepare("SELECT COUNT(*) AS n FROM audit_events").get() as { n: number }).n);
    assert.equal(runtime.prepare({ ...prepareRequest(f.session!, "http://127.0.0.1:7340"), csrfHeader: "bad" }).ok, false);
    assert.deepEqual(runtime.confirm({ ...confirmRequest(f.session!, "http://127.0.0.1:7340"), cookieHeader: "__Host-lanmm_session=invalid" }), { outcome: "denied" });
    assert.deepEqual(observed.counts, { authenticate: 4, authenticateCsrf: 3 }, "bad CSRF and invalid session fail in the actual service guards");
    assert.equal(Number((f.db.prepare("SELECT COUNT(*) AS n FROM audit_events").get() as { n: number }).n), auditBeforeDenials);
    assert.equal(Number((f.db.prepare("SELECT COUNT(*) AS n FROM supplemental_native_evidence").get() as { n: number }).n), 0);
    runtime.close();
  } finally { f.db.close(); }
});

test("runtime is a frozen narrow facade; close is reentrant/idempotent and post-close denials avoid DB/session access", async () => {
  const f = await fixture(), observed = observingSessions(f.sessions);
  const runtime = createOwnerNativeEvidenceRuntime({ db: f.db, sessions: observed.sessions, allowedOrigins: ["https://manager.example"], clock });
  assert.deepEqual(Object.keys(runtime).sort(), ["close", "confirm", "prepare"]);
  assert.equal(Object.isFrozen(runtime), true);
  const prototype = OwnerNativeEvidenceCandidateRegistry.prototype as unknown as { close: () => void };
  const original = prototype.close;
  let closes = 0;
  let dbClosed = false;
  prototype.close = function () { closes++; runtime.close(); return original.call(this); };
  try {
    runtime.close(); runtime.close();
    assert.equal(closes, 1, "reentrant close reaches the registry once");
    const before = { ...observed.counts };
    f.db.close(); dbClosed = true;
    assert.deepEqual(runtime.prepare(prepareRequest(f.session!, "https://manager.example")), { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" });
    assert.deepEqual(runtime.confirm(confirmRequest(f.session!, "https://manager.example")), { outcome: "denied" });
    assert.deepEqual(observed.counts, before, "closed facade denies before touching sessions or the already-closed DB");
  } finally { prototype.close = original; if (!dbClosed) f.db.close(); }
});

test("confirm-construction failure closes the partially created intake registry", async () => {
  const f = await fixture();
  const prototype = OwnerNativeEvidenceCandidateRegistry.prototype as unknown as { close: () => void };
  const originalClose = prototype.close;
  let closes = 0, auditReads = 0;
  prototype.close = function () { closes++; return originalClose.call(this); };
  const db = new Proxy(f.db, { get(target, property) {
    if (property === "prepare") return (sql: string) => {
      if (sql === "SELECT * FROM audit_events ORDER BY seq LIMIT ?" && ++auditReads === 2) throw new Error("injected second-store construction failure");
      return target.prepare(sql);
    };
    const value = Reflect.get(target, property, target);
    return typeof value === "function" ? value.bind(target) : value;
  } });
  try {
    assert.throws(() => createOwnerNativeEvidenceRuntime({ db: db as unknown as typeof f.db, sessions: f.sessions, allowedOrigins: ["https://manager.example"], clock }));
    assert.equal(auditReads, 2);
    assert.equal(closes, 1, "the intake's sole registry is closed when confirm construction fails");
  } finally { prototype.close = originalClose; f.db.close(); }
});

test("facade prepares and confirms current-trust unsigned evidence once through its shared registry", async () => {
  const f = await trustedEvidenceFixture();
  try {
    const allowedOrigins = ["https://manager.example"], options = { allowLoopbackHttpDevelopment: false };
    const runtime = createOwnerNativeEvidenceRuntime({ db: f.db, sessions: f.sessions, allowedOrigins, clock: f.clock, originOptions: options });
    allowedOrigins[0] = "https://evil.example"; options.allowLoopbackHttpDevelopment = true;
    const original = f.raw.slice();
    const prepare = (bytes: Uint8Array) => runtime.prepare({ ...prepareRequest(f.session, "https://manager.example"), rawPayloadBytes: bytes });
    const confirm = (preview: { candidateHandle: string; expectedTupleDigest: string }) => runtime.confirm({
      method: "POST", path: "/api/v1/native-evidence/confirm", cookieHeader: `__Host-lanmm_session=${f.session.sessionToken}`,
      originHeader: "https://manager.example", csrfHeader: f.session.csrfToken,
      body: JSON.stringify({ candidateHandle: preview.candidateHandle, expectedTupleDigest: preview.expectedTupleDigest,
        action: "append-supplemental-native-evidence", disposition: "evidence-only" }),
    });
    const protectedState = () => JSON.stringify({
      jobs: f.db.prepare("SELECT * FROM jobs ORDER BY job_id").all(), histories: f.db.prepare("SELECT * FROM job_history ORDER BY history_id").all(),
      commands: f.db.prepare("SELECT * FROM agent_commands ORDER BY job_id").all(), owners: f.db.prepare("SELECT * FROM owners").all(),
      sessions: f.db.prepare("SELECT * FROM sessions").all(), hosts: f.db.prepare("SELECT * FROM host_certificates").all(),
      authorities: f.db.prepare("SELECT * FROM certificate_authorities").all(), replay: f.db.prepare("SELECT * FROM transport_replay_state").all(),
    });
    const beforeProtected = protectedState(), beforeAudit = Number((f.db.prepare("SELECT COUNT(*) AS n FROM audit_events").get() as { n: number }).n);
    const preview = prepare(f.raw); assert.equal(preview.ok, true);
    if (!preview.ok) return;
    assert.deepEqual(f.raw, original);
    assert.equal(confirm(preview.preview).outcome, "stored");
    assert.equal(Number((f.db.prepare("SELECT COUNT(*) AS n FROM supplemental_native_evidence").get() as { n: number }).n), 1);
    assert.equal(Number((f.db.prepare("SELECT COUNT(*) AS n FROM audit_events").get() as { n: number }).n), beforeAudit + 1);
    assert.equal(protectedState(), beforeProtected, "no job, command, credential, trust, or replay state changes");
    const duplicate = prepare(f.raw); assert.equal(duplicate.ok, true);
    if (!duplicate.ok) return;
    assert.equal(confirm(duplicate.preview).outcome, "already_stored");
    assert.equal(Number((f.db.prepare("SELECT COUNT(*) AS n FROM supplemental_native_evidence").get() as { n: number }).n), 1);
    assert.equal(Number((f.db.prepare("SELECT COUNT(*) AS n FROM audit_events").get() as { n: number }).n), beforeAudit + 1);
    const altered = Buffer.from(f.raw.toString("utf8").replace('"evidenceSource":"synthetic"', '"evidenceSource":"explicit_snapshot"'), "utf8");
    const conflict = prepare(altered); assert.equal(conflict.ok, true);
    if (!conflict.ok) return;
    assert.equal(confirm(conflict.preview).outcome, "conflict");
    assert.equal(Number((f.db.prepare("SELECT COUNT(*) AS n FROM supplemental_native_evidence").get() as { n: number }).n), 1);
    assert.equal(Number((f.db.prepare("SELECT COUNT(*) AS n FROM audit_events").get() as { n: number }).n), beforeAudit + 1);
    assert.equal(protectedState(), beforeProtected);
    runtime.close(); runtime.close();
  } finally { f.db.close(); rmSync(f.root, { recursive: true, force: true }); }
});
