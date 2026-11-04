import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";
import { commandAuthorizationDigest, commandPolicyOperation, signTransportSignedEnvelope, transportBodyDigest, parseTransportParsedCertificate, type CommandRequest, type OperationPolicy } from "@lan-model-manager/core";
import { createRuntimeInferenceHandler } from "./inference-runtime.js";
import { createAdmissionController } from "./admission-accounting.js";
import { CommandDispatcher } from "./command-dispatch.js";
import { createControllerApplication, type ControllerApplicationOptions } from "./controller-application.js";
import { createManagementDependencies } from "./management-runtime.js";
import { CertificateRepository } from "./certificate-repository.js";
import { FleetService } from "./fleet-service.js";
import { ControllerTransport } from "./transport/controller-transport.js";
import { PersistentReplayStore } from "./transport/replay-store.js";
import { buildTransportNativeSigner, buildTransportNativeVerifier, generateTransportNativeKeyPair } from "./transport/transport-signer.js";

const T0 = "2026-09-29T10:00:00.000Z";
const policy: OperationPolicy = { version: 1, allowedOperations: ["model-load", "model-drain", "model-unload"], approvalOperations: [], allowArtifactAcquisition: false, allowArtifactRemoval: false, allowSubstitution: false, allowPublicExposure: false, minimumMemoryHeadroomBytes: 1, minimumVramHeadroomBytes: 0, minimumStorageHeadroomBytes: 1, maxConcurrentOperations: 10, maxOperationsPerMinute: 100 };
async function fixture(closeTimeoutMs = 5000) {
  const probe = createServer();
  await new Promise<void>(resolve => probe.listen(0, "127.0.0.1", resolve));
  const address = probe.address(); assert.ok(address && typeof address === "object");
  const port = address.port;
  await new Promise<void>(resolve => probe.close(() => resolve()));
  const root = mkdtempSync(join(tmpdir(), "lanmm-lifecycle-http-"));
  let now = T0, random = 1;
  const options: ControllerApplicationOptions = {
    closeTimeoutMs,
    config: { bindHost: "127.0.0.1", port, inferenceHost: "127.0.0.1", inferencePort: port + 1, dataDir: root, logLevel: "info", discoveryEnabled: false, publicInferenceEnabled: false, tlsRequired: true, mutualTlsRequired: true },
    plan: { rootDir: root, databasePath: join(root, "controller.sqlite3"), artifactDir: join(root, "artifacts"), cacheDir: join(root, "cache"), stagingDir: join(root, "staging"), quarantineDir: join(root, "quarantine"), auditDir: join(root, "audit"), certificateDir: join(root, "certificates") },
    runtimeDependencies: { now: () => now, random: n => Buffer.alloc(n, random++), ownerId: () => "a".repeat(32), passwordCrypto: { random: n => Buffer.alloc(n, 3), async derive(password, salt, parameters) { return Buffer.alloc(parameters.keyLength, createHash("sha256").update(password).update(salt).digest()[0]); }, equal: (a, b) => Buffer.from(a).equals(Buffer.from(b)) } },
  };
  const app = createControllerApplication(options);
  await app.start();
  const base = `http://127.0.0.1:${port}`;
  const post = (path: string, value: unknown, headers: Record<string, string> = {}) => fetch(base + path, { method: "POST", headers: { "content-type": "application/json", origin: base, connection: "close", ...headers }, body: JSON.stringify(value) });
  const credentials = { username: "Owner", password: "synthetic-password-for-http-tests" };
  assert.equal((await post("/auth/v1/bootstrap", credentials)).status, 200);
  const login = await post("/auth/v1/login", credentials); assert.equal(login.status, 200);
  const cookie = login.headers.get("set-cookie")!.split(";", 1)[0]!;
  const csrf = (await login.json() as any).value.csrfToken;
  const headers = { cookie, "x-csrf-token": csrf };
  const repos = app.runtime.repositories, pem = "-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n", fp = "b".repeat(64), certs = new CertificateRepository(repos.db);
  certs.insertCa({ caId: "c".repeat(64), version: 1, serial: "10", fingerprint: "c".repeat(64), certificatePem: pem, notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2036-01-01T00:00:00.000Z", createdAt: T0 });
  certs.insertHost({ certificateId: fp, serial: "ABCD", fingerprint: fp, certificatePem: pem, caId: "c".repeat(64), caVersion: 1, binding: { candidateId: "host-1", address: "192.0.2.10", port: 7443, protocolMajor: 1, protocolMinor: 0 }, spiffeUri: "spiffe://lanmodelmanager/host/host-1", challengeId: "d".repeat(64), transcriptDigest: "e".repeat(64), notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2027-01-01T00:00:00.000Z", status: "active", version: 1, issuedAt: T0, revokedAt: null });
  repos.hosts.upsert({ hostId: "host-1", displayName: "Synthetic host", platform: "linux", observedAt: T0, online: true, freshness: "fresh", snapshot: { resource: { hostId: "host-1", platform: "linux", observedAt: T0, cpuLogicalCores: 4, cpuUtilizationPercent: 0, memory: { totalBytes: 100, usedBytes: 10, availableBytes: 90 }, storage: { totalBytes: 100, usedBytes: 10, availableBytes: 90 }, accelerators: [] } } });
  repos.providers.upsert({ providerId: "provider-1", hostId: "host-1", kind: "ollama", endpoint: "http://127.0.0.1:11434", health: "ready", version: "", versionKnown: false, observedAt: T0, snapshot: {} });
  repos.models.upsert({ modelId: "model-1", providerId: "provider-1", hostId: "host-1", canonicalName: "example/model:latest", state: "installed", type: "llm", digest: "", digestKnown: false, observedAt: T0, snapshot: { runtimeState: "unloaded", activeRequests: 0 } });
  repos.db.prepare("INSERT INTO fleet_liveness(host_id,certificate_fingerprint,protocol_minor,last_sequence,last_observed_at,last_request_id,idle,updated_at) VALUES(?,?,?,?,?,?,?,?)").run("host-1", fp, 0, 1, T0, "heartbeat-1", 1, T0);
  // Synthetic paired leaf and real signature/replay/inventory pipeline. No
  // provider, model process, external host or inference listener is involved.
  const parsedCertificate = parseTransportParsedCertificate({ fingerprint: fp, serial: "ABCD", commonName: "host-1", address: "192.0.2.10", spiffe: "spiffe://lanmodelmanager/host/host-1", notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2027-01-01T00:00:00.000Z", issuerFingerprint: "c".repeat(64), isCa: false });
  assert.ok(parsedCertificate.ok);
  const pair = generateTransportNativeKeyPair(), signer = buildTransportNativeSigner(pair.keyPem, parsedCertificate.value), verifier = buildTransportNativeVerifier(pair.publicPem, parsedCertificate.value);
  assert.ok(signer.ok && verifier.ok);
  const heartbeatSigner = signer.value;
  const transport = new ControllerTransport({ certificateRepository: certs, replayStore: new PersistentReplayStore(repos.db), verifier: () => verifier.value, clock: () => now });
  const fleet = new FleetService(repos.db, transport, certs, repos, { clock: () => now });
  let heartbeatSequence = 1;
  function heartbeat(second: number, runtimeState = "loaded-idle", activeRequests: unknown = 0, overrides: Record<string, unknown> = {}, sourceAddress = "192.0.2.10") {
    now = `2026-09-29T10:00:${String(second).padStart(2, "0")}.000Z`;
    const sequence = ++heartbeatSequence;
    const payload = { platform: "linux", protocolMinor: 0, idle: runtimeState === "loaded-idle", sequence, observedAt: now,
      resource: { ...(repos.hosts.get("host-1")!.snapshot as any).resource, observedAt: now },
      providers: [{ providerId: "provider-1", kind: "ollama", displayName: "Synthetic Ollama", endpoint: "http://127.0.0.1:11434", health: "ready", version: null, observedAt: now }],
      models: [{ modelId: "model-1", providerId: "provider-1", displayName: "example/model:latest", artifactState: "installed", runtimeState, activeRequests, sizeBytes: 123, managedTemporary: false, pinned: false, capability: { tools: false, vision: false, reasoning: false, modalities: ["text"], contextWindow: 4096 }, observedAt: now, ...overrides }] };
    const signed = signTransportSignedEnvelope({ protocolVersion: { major: 1, minor: 0 }, messageType: "transport.heartbeat", hostId: "host-1", requestId: `heartbeat-${sequence}`, sequence, sentAt: now, nonce: `heartbeat-nonce-${sequence}`, bodyDigest: transportBodyDigest(payload as never), certFingerprint: fp, certSerial: "ABCD", signature: "0".repeat(16), payload } as never, heartbeatSigner);
    assert.ok(signed.ok);
    return fleet.ingest(signed.value, sourceAddress);
  }
  function command(operation: "load" | "drain" | "unload", n: number): CommandRequest {
    const value = { requestId: String(n).padStart(64, "0"), jobId: `job-${n}`, hostId: "host-1", operation, idempotencyKey: `idem-${n}`, sequence: 1, deadline: "2026-09-29T10:04:00.000Z", capability: { operation: commandPolicyOperation(operation), targetKind: "model", targetId: "model-1", hostId: "host-1", modelId: "model-1", requestDigest: "0".repeat(64), expiresAt: "2026-09-29T10:04:00.000Z" }, params: { providerId: "provider-1", model: "example/model:latest" } };
    value.capability.requestDigest = commandAuthorizationDigest(value as CommandRequest);
    return value as CommandRequest;
  }
  async function poll() {
    for (let i = 0; i < 100; i++) {
      const command = app.runtime.services.commands.poll("host-1").command;
      if (command) return command;
      await new Promise(resolve => setTimeout(resolve, 5));
    }
    assert.fail("HTTP submission did not reach runtime-owned agent queue");
  }
  async function complete(request: CommandRequest, second: number) {
    now = `2026-09-29T10:00:${String(second).padStart(2, "0")}.000Z`;
    assert.ok(app.runtime.services.commands.complete("host-1", { requestId: request.requestId, jobId: request.jobId, hostId: request.hostId, sequence: request.sequence, status: "succeeded", progress: 100, observedAt: now, observation: { action: request.operation, providerId: "provider-1", canonicalModelName: "example/model:latest", outcome: "succeeded", runtimeState: request.operation === "unload" ? "unloaded" : "loaded", ...(request.operation === "drain" ? { activeRequests: 0 } : {}), observedAt: now }, errorCode: null }));
  }
  return { app, repos, post, rawPost:(path:string,body:string,headers:Record<string,string>)=>fetch(base+path,{method:"POST",headers:{"content-type":"application/json",origin:base,connection:"close",...headers},body}), headers, cookie, command, poll, complete, heartbeat, certs, fp, reopen: () => createControllerApplication(options), setNow: (value: string) => now = value, async close() { await app.close(); rmSync(root, { recursive: true, force: true }); } };
}

// Real production application, real auth/CSRF/origin guard, real policy and
// durable typed queue. Only the host observations/results are synthetic.
test("production lifecycle HTTP fails closed for auth, CSRF, origin, policy, trust and malformed commands", { timeout: 15_000 }, async () => {
  const x = await fixture();
  try {
    for (const path of ["/api/v1/lifecycle/operations", "/api/v1/lifecycle/cancel"]) {
      assert.equal((await x.post(path, {})).status, 401);
      assert.equal((await x.post(path, {}, { cookie: x.cookie })).status, 403);
      assert.equal((await x.post(path, {}, { ...x.headers, origin: "https://evil.example" })).status, 403);
      assert.equal((await x.post(path, {}, { ...x.headers, authorization: "Bearer synthetic" })).status, 401);
    }
    const command = x.command("load", 1);
    assert.equal((await x.post("/api/v1/lifecycle/operations", { request: command }, x.headers)).status, 409);
    assert.equal(x.app.runtime.services.commands.poll("host-1").command, null);
    assert.equal(x.app.runtime.jobStores.jobs.get(command.jobId), null);
    const audit = x.app.runtime.jobStores.audit.list().find(row => row.action === "policy-model-load");
    assert.equal(audit?.actorKind, "owner"); assert.equal(audit?.actorId, "a".repeat(32)); assert.equal(audit?.outcome, "denied");
    assert.equal((await x.post("/api/v1/policy/install", policy, x.headers)).status, 200);
    assert.equal((await x.post("/api/v1/lifecycle/operations", { request: command, intent: { observationFresh: true } }, x.headers)).status, 400);
    assert.equal((await x.post("/api/v1/lifecycle/operations", { request: { ...command, params: { endpoint: "http://evil.example" } } }, x.headers)).status, 400);
    assert.equal((await x.post("/api/v1/lifecycle/cancel", { jobId: "absent" }, x.headers)).status, 409);
    assert.ok(x.certs.revoke(x.fp, T0));
    assert.equal((await x.post("/api/v1/lifecycle/operations", { request: x.command("load", 2) }, x.headers)).status, 409);
    assert.equal(x.app.runtime.services.commands.poll("host-1").command, null);
  } finally { await x.close(); }
});

test("production owner HTTP remotely loads, cancels, drains idle safely, unloads and resumes on reload", { timeout: 15_000 }, async () => {
  const x = await fixture();
  try {
    assert.equal((await x.post("/api/v1/policy/install", policy, x.headers)).status, 200);
    const pending = x.post("/api/v1/lifecycle/operations", { request: x.command("load", 1) }, x.headers);
    const first = await x.poll(); assert.equal(first.operation, "load");
    assert.equal(x.app.runtime.jobStores.jobs.get(first.jobId)?.state, "accepted");
    assert.equal((await x.post("/api/v1/lifecycle/cancel", { jobId: first.jobId }, x.headers)).status, 200);
    assert.equal((await pending).status, 200);
    assert.equal(x.app.runtime.jobStores.jobs.get(first.jobId)?.state, "cancelled");
    assert.ok(x.app.runtime.services.commands.poll("host-1").cancelledJobIds.includes(first.jobId));
    assert.equal(x.repos.models.get("model-1")?.state, "installed");
    async function run(operation: "load" | "drain" | "unload", n: number) {
      const pending = x.post("/api/v1/lifecycle/operations", { request: x.command(operation, n) }, x.headers);
      const request = await x.poll(); assert.equal(request.operation, operation);
      await x.complete(request, n);
      const response = await pending, body = await response.json() as any;
      assert.equal(response.status, 200, JSON.stringify(body)); assert.equal(body.value.state, "succeeded");
      assert.equal(x.app.runtime.jobStores.jobs.get(request.jobId)?.state, "succeeded");
    }
    await run("load", 2);
    const admissions = x.app.runtime.services.admissions;
    const lease = admissions.acquire("model-1", "synthetic-chat-lease");
    assert.equal((await x.post("/api/v1/lifecycle/operations", { request: x.command("drain", 3) }, x.headers)).status, 409);
    assert.equal((await x.post("/api/v1/lifecycle/operations", { request: x.command("unload", 4) }, x.headers)).status, 409);
    assert.equal(x.app.runtime.services.commands.poll("host-1").command, null);
    assert.equal(admissions.snapshot("model-1").active, 1);
    assert.throws(() => admissions.acquire("model-1", "late-lease"));
    lease.release();
    await run("drain", 3);
    assert.equal(admissions.snapshot("model-1").draining, true);
    await run("unload", 6);
    assert.equal(x.repos.models.get("model-1")?.state, "installed");
    await run("load", 7);
    assert.equal(admissions.snapshot("model-1").draining, false);
    const next = admissions.acquire("model-1", "next-lease"); next.release();
    assert.equal(x.app.runtime.jobStores.audit.list().filter(row => row.action === "lifecycle-observation-applied").length, 4);
  } finally { await x.close(); }
});

test("production lifecycle enforces observed resource headroom and staleness without browser guard assertions", { timeout: 15_000 }, async () => {
  const x = await fixture();
  try {
    assert.equal((await x.post("/api/v1/policy/install", { ...policy, minimumMemoryHeadroomBytes: 91 }, x.headers)).status, 200);
    assert.equal((await x.post("/api/v1/lifecycle/operations", { request: x.command("load", 8) }, x.headers)).status, 409);
    assert.equal(x.app.runtime.services.commands.poll("host-1").command, null);
    assert.equal((await x.post("/api/v1/policy/install", { ...policy, version: 2 }, x.headers)).status, 200);
    x.setNow("2026-09-29T10:01:01.000Z");
    assert.equal((await x.post("/api/v1/lifecycle/operations", { request: x.command("load", 9) }, x.headers)).status, 409);
    assert.equal(x.app.runtime.services.commands.poll("host-1").command, null);
    assert.ok(x.app.runtime.jobStores.audit.list().some(row => row.outcome === "denied"));
    x.repos.db.exec("DROP TABLE policy_documents");
    const failed = await x.post("/api/v1/lifecycle/operations", { request: x.command("load", 10) }, x.headers);
    assert.equal(failed.status, 409);
    assert.equal(JSON.stringify(await failed.json()).includes("policy_documents"), false);
    assert.equal(x.app.runtime.services.commands.poll("host-1").command, null);
  } finally { await x.close(); }
});

test("production lifecycle requires an exact owner approval when policy requests one", { timeout: 15_000 }, async () => {
  const x = await fixture();
  try {
    assert.equal((await x.post("/api/v1/policy/install", { ...policy, approvalOperations: ["model-load"] }, x.headers)).status, 200);
    const request = x.command("load", 11);
    assert.equal((await x.post("/api/v1/lifecycle/operations", { request }, x.headers)).status, 409);
    assert.equal(x.app.runtime.services.commands.poll("host-1").command, null);
    const approved = await x.post("/api/v1/policy/approve", { requestId: request.requestId }, x.headers);
    assert.equal(approved.status, 200);
    const approvalId = (await approved.json() as any).value.approvalId;
    assert.equal((await x.post("/api/v1/lifecycle/operations", { request, approvalId: "f".repeat(64) }, x.headers)).status, 409);
    const pending = x.post("/api/v1/lifecycle/operations", { request, approvalId }, x.headers);
    const command = await x.poll(); assert.equal(command.jobId, request.jobId);
    await x.complete(command, 11);
    assert.equal((await pending).status, 200);
    assert.equal(x.app.runtime.jobStores.jobs.get(command.jobId)?.state, "succeeded");
    assert.equal((await x.post("/api/v1/lifecycle/operations", { request, approvalId }, x.headers)).status, 409);
  } finally { await x.close(); }
});

test("rejected load against a serving model preserves unknown admission accounting", { timeout: 15_000 }, async () => {
  const x = await fixture();
  try {
    assert.equal((await x.post("/api/v1/policy/install", policy, x.headers)).status, 200);
    x.setNow("2026-09-29T10:00:01.000Z");
    const model = x.repos.models.get("model-1")!;
    x.repos.models.upsert({ ...model, state: "running", observedAt: "2026-09-29T10:00:01.000Z", snapshot: { runtimeState: "loaded-idle", activeRequests: 0 } });
    assert.throws(() => x.app.runtime.services.admissions.snapshot(model.modelId));
    assert.equal((await x.post("/api/v1/lifecycle/operations", { request: x.command("load", 12) }, x.headers)).status, 409);
    assert.throws(() => x.app.runtime.services.admissions.snapshot(model.modelId));
    assert.equal((await x.post("/api/v1/lifecycle/operations", { request: x.command("drain", 13) }, x.headers)).status, 409);
    assert.equal(x.app.runtime.services.commands.poll("host-1").command, null);
  } finally { await x.close(); }
});

test("production runtime restart cancels interrupted lifecycle work or reconciles a persisted verified result", { timeout: 15_000 }, async () => {
  for (const completed of [false, true]) {
    const x = await fixture(); let reopened: ReturnType<typeof x.reopen> | null = null;
    try {
      // Seed the durable dispatch boundary without a surviving HTTP waiter,
      // exactly the state left by interruption before/after result persistence.
      const request = x.command("load", completed ? 15 : 14);
      const dispatcher = new CommandDispatcher(x.app.runtime.jobStores, x.app.runtime.services.commands, () => T0);
      assert.ok(dispatcher.dispatch(request).ok);
      assert.equal((await x.poll()).jobId, request.jobId);
      if (completed) await x.complete(request, 15);
      assert.equal(x.app.runtime.jobStores.jobs.get(request.jobId)?.state, "accepted");
      await x.app.close();
      reopened = x.reopen(); await reopened.start();
      assert.equal(reopened.runtime.jobStores.jobs.get(request.jobId)?.state, completed ? "succeeded" : "cancelled");
      assert.equal(reopened.runtime.repositories.models.get("model-1")?.state, completed ? "running" : "installed");
      if (!completed) assert.ok(reopened.runtime.services.commands.poll("host-1").cancelledJobIds.includes(request.jobId));
      await reopened.stop(); await reopened.start();
      assert.equal(reopened.runtime.jobStores.audit.list().filter(row => row.action === "lifecycle-observation-applied").length, completed ? 1 : 0);
    } finally { await reopened?.close(); await x.close(); }
  }
});

test("injected chat adapters cannot use absent or independent admission accounting", { timeout: 15_000 }, async () => {
  const x = await fixture();
  try {
    const chat = { resolve: async () => null, acquireLease: async () => ({ release() {} }), transport: async () => ({ kind: "json" as const, value: {} }) };
    assert.throws(() => createRuntimeInferenceHandler(x.app.runtime, { chat }), /ERR_INFERENCE_CONFIG/);
    assert.throws(() => createRuntimeInferenceHandler(x.app.runtime, { chat: { ...chat, admissions: createAdmissionController() } }), /ERR_INFERENCE_CONFIG/);
    assert.doesNotThrow(() => createRuntimeInferenceHandler(x.app.runtime, { chat: { ...chat, admissions: x.app.runtime.services.admissions } }));
  } finally { await x.close(); }
});

test("graceful application stop owns pending HTTP lifecycle waits before SQLite closes", { timeout: 15_000 }, async () => {
  for (const leased of [false, true]) {
    const x = await fixture(1000); let reopened: ReturnType<typeof x.reopen> | null = null;
    try {
      assert.equal((await x.post("/api/v1/policy/install", policy, x.headers)).status, 200);
      const request = x.command("load", leased ? 17 : 16);
      const pending = x.post("/api/v1/lifecycle/operations", { request }, x.headers);
      // Do not lease the first variant: both queued and leased work must cancel.
      for (let i = 0; !x.app.runtime.jobStores.jobs.get(request.jobId) && i < 100; i++) await new Promise(resolve => setTimeout(resolve, 5));
      assert.equal(x.app.runtime.jobStores.jobs.get(request.jobId)?.state, "accepted");
      if (leased) assert.equal((await x.poll()).jobId, request.jobId);
      const before = Date.now();
      await Promise.all([x.app.stop(), x.app.stop()]);
      assert.ok(Date.now() - before < 1000, "shutdown exceeded configured bound");
      const response = await pending, body = await response.json() as any;
      assert.equal(response.status, 200); assert.equal(body.value.state, "cancelled");
      assert.equal(x.app.runtime.jobStores.jobs.get(request.jobId)?.state, "cancelled");
      assert.equal(x.app.runtime.services.lifecycle.acceptsSubmissions, false);
      assert.equal(x.app.runtime.services.admissions.snapshot("model-1").draining, true);
      assert.equal(x.repos.models.get("model-1")?.state, "installed");
      assert.equal(x.app.runtime.services.commands.complete("host-1", { requestId: request.requestId, jobId: request.jobId, hostId: request.hostId, sequence: 1, status: "succeeded", progress: 100, observedAt: "2026-09-29T10:00:01.000Z", observation: { action: "load", outcome: "succeeded", providerId: "provider-1", canonicalModelName: "example/model:latest", runtimeState: "loaded", observedAt: "2026-09-29T10:00:01.000Z" }, errorCode: null }), null);
      // Service-level rejection proves the stopping gate precedes all policy or
      // DB writes even when a parsed HTTP body arrives during shutdown.
      const count = x.app.runtime.jobStores.audit.list().length;
      const deps = createManagementDependencies(x.app.runtime, ["http://127.0.0.1"], {}, {}, () => T0);
      const session = x.app.runtime.services.sessions.authenticate(x.cookie.split("=", 2)[1]!); assert.ok(session);
      assert.deepEqual(await deps.lifecycle!.submit({ request: x.command("load", 18) }, { ok: true, session }), { ok: false, error: "ERR_LIFECYCLE_STATE" });
      assert.equal(x.app.runtime.jobStores.audit.list().length, count);
      await x.app.close();
      // Wait past the queue polling interval: no waiter may touch the closed DB.
      await new Promise(resolve => setTimeout(resolve, 50));
      reopened = x.reopen(); await reopened.start();
      assert.equal(reopened.runtime.jobStores.jobs.get(request.jobId)?.state, "cancelled");
      assert.equal(reopened.runtime.repositories.models.get("model-1")?.state, "installed");
    } finally { await reopened?.close(); await x.close(); }
  }
});

test("close preserves a verified result racing shutdown and settles its HTTP waiter before database close", { timeout: 15_000 }, async () => {
  const x = await fixture(1000); let reopened: ReturnType<typeof x.reopen> | null = null;
  try {
    assert.equal((await x.post("/api/v1/policy/install", policy, x.headers)).status, 200);
    const request = x.command("load", 19);
    const pending = x.post("/api/v1/lifecycle/operations", { request }, x.headers);
    await x.poll();
    await x.complete(request, 19);
    // Result is durable; the HTTP poller has not necessarily consumed it.
    const before = Date.now();
    await x.app.close();
    assert.ok(Date.now() - before < 1000);
    const response = await pending, body = await response.json() as any;
    assert.equal(response.status, 200); assert.equal(body.value.state, "succeeded");
    await new Promise(resolve => setTimeout(resolve, 50));
    reopened = x.reopen(); await reopened.start();
    assert.equal(reopened.runtime.jobStores.jobs.get(request.jobId)?.state, "succeeded");
    assert.equal(reopened.runtime.repositories.models.get("model-1")?.state, "running");
    assert.equal(reopened.runtime.jobStores.audit.list().filter(row => row.action === "lifecycle-observation-applied").length, 1);
  } finally { await reopened?.close(); await x.close(); }
});

test("HTTP lifecycle submissions arriving during stop are rejected before policy or dispatch", { timeout: 15_000 }, async () => {
  const x = await fixture(1000);
  let release!: () => void;
  const barrier = new Promise<void>(resolve => release = resolve);
  const lifecycle = x.app.runtime.services.lifecycle;
  const shutdown = lifecycle.shutdown.bind(lifecycle);
  // Hold the listener-open cleanup boundary after the real stopping gate and
  // owned-wait cleanup, so a concurrent HTTP request exercises the race.
  lifecycle.shutdown = async () => { await shutdown(); await barrier; };
  try {
    assert.equal((await x.post("/api/v1/policy/install", policy, x.headers)).status, 200);
    const count = x.app.runtime.jobStores.audit.list().length;
    const stopping = x.app.stop();
    assert.equal(lifecycle.acceptsSubmissions, false);
    try {
      const denied = await x.post("/api/v1/lifecycle/operations", { request: x.command("load", 20) }, x.headers);
      assert.equal(denied.status, 409);
      assert.equal(x.app.runtime.jobStores.audit.list().length, count);
      assert.equal(x.app.runtime.services.commands.poll("host-1").command, null);
    } finally { release(); await stopping; }
  } finally { release(); lifecycle.shutdown = shutdown; await x.close(); }
});

test("consumed approval cannot authorize a different execution after cancel, aged counters, refreshed inventory or restart", { timeout: 15_000 }, async () => {
  const x = await fixture(); let reopened: ReturnType<typeof x.reopen> | null = null;
  try {
    assert.equal((await x.post("/api/v1/policy/install", { ...policy, approvalOperations: ["model-load"] }, x.headers)).status, 200);
    const request = x.command("load", 21);
    assert.equal((await x.post("/api/v1/lifecycle/operations", { request }, x.headers)).status, 409);
    const grant = await x.post("/api/v1/policy/approve", { requestId: request.requestId }, x.headers);
    assert.equal(grant.status, 200); const approvalId = (await grant.json() as any).value.approvalId;
    const pending = x.post("/api/v1/lifecycle/operations", { request, approvalId }, x.headers);
    await x.poll();
    assert.equal((await x.post("/api/v1/lifecycle/cancel", { jobId: request.jobId }, x.headers)).status, 200);
    assert.equal((await pending).status, 200);
    // Reproduce the reviewer's conditions: the previous job ages out of the
    // rolling rate count, inventory is fresh, and all policy intent facts match.
    const now = "2026-09-29T10:01:01.000Z"; x.setNow(now);
    const host = x.repos.hosts.get("host-1")!, provider = x.repos.providers.get("provider-1")!, model = x.repos.models.get("model-1")!;
    x.repos.hosts.upsert({ ...host, observedAt: now, snapshot: { ...(host.snapshot as object), resource: { ...(host.snapshot as any).resource, observedAt: now } } });
    x.repos.providers.upsert({ ...provider, observedAt: now });
    x.repos.models.upsert({ ...model, observedAt: now });
    x.repos.db.prepare("UPDATE fleet_liveness SET last_observed_at=?,updated_at=? WHERE host_id=?").run(now, now, host.hostId);
    const rebound: CommandRequest = { ...request, jobId: "distinct-replay-job", idempotencyKey: "distinct-replay-idem", capability: { ...request.capability } };
    (rebound.capability as { requestDigest: string }).requestDigest = commandAuthorizationDigest(rebound);
    for (const extra of [{}, { approvalId }]) {
      assert.equal((await x.post("/api/v1/lifecycle/operations", { request: rebound, ...extra }, x.headers)).status, 409);
      assert.equal(x.app.runtime.jobStores.jobs.get(rebound.jobId), null);
      assert.equal(x.app.runtime.services.commands.poll("host-1").command, null);
    }
    // Exact execution retries may only report the original terminal outcome;
    // they cannot create or dispatch another job.
    const retry = await x.post("/api/v1/lifecycle/operations", { request }, x.headers);
    assert.equal(retry.status, 200); assert.equal((await retry.json() as any).value.state, "cancelled");
    const bound = x.repos.db.prepare("SELECT consumed_command_digest FROM approvals WHERE approval_id=?").get(approvalId) as { consumed_command_digest: string };
    assert.equal(bound.consumed_command_digest, commandAuthorizationDigest(request));
    await x.app.close(); reopened = x.reopen(); await reopened.start();
    assert.equal((await x.post("/api/v1/lifecycle/operations", { request: rebound }, x.headers)).status, 409);
    assert.equal(reopened.runtime.jobStores.jobs.get(rebound.jobId), null);
    assert.equal(reopened.runtime.services.commands.poll("host-1").command, null);
    const again = await x.post("/api/v1/lifecycle/operations", { request }, x.headers);
    assert.equal(again.status, 200); assert.equal((await again.json() as any).value.state, "cancelled");
  } finally { await reopened?.close(); await x.close(); }
});


async function runOwnerOperation(x: Awaited<ReturnType<typeof fixture>>, operation: "load" | "drain" | "unload", n: number, second: number) {
  const request = x.command(operation, n);
  const pending = x.post("/api/v1/lifecycle/operations", { request }, x.headers);
  assert.equal((await x.poll()).jobId, request.jobId);
  await x.complete(request, second);
  const response = await pending, body = await response.json() as any;
  assert.equal(response.status, 200, JSON.stringify(body));
  assert.equal(body.value.state, "succeeded");
  return request;
}

const inferencePolicy: OperationPolicy = { ...policy, allowedOperations: [...policy.allowedOperations, "model-inference"] };
async function inferenceContext(x: Awaited<ReturnType<typeof fixture>>) {
  const issued = await x.app.runtime.services.inferenceTokens.issue(x.cookie.split("=", 2)[1]!, { label: "synthetic-reconciliation", ttlMs: 120000 });
  assert.ok(issued);
  return { token: issued.metadata };
}

test("paired loaded-idle heartbeat persists running but cannot manufacture runtime admission or inference authority", { timeout: 15_000 }, async () => {
  const x = await fixture();
  try {
    assert.ok(x.heartbeat(1).ok);
    const model = x.repos.models.get("model-1")!;
    assert.equal(model.state, "running"); assert.equal((model.snapshot as any).activeRequests, 0);
    assert.equal((model.snapshot as any).observedAt, model.observedAt);
    const context = await inferenceContext(x), inference = x.app.runtime.services.inference;
    assert.throws(() => inference.select(context, model.canonicalName)); // closed default policy
    assert.equal((await x.post("/api/v1/policy/install", inferencePolicy, x.headers)).status, 200);
    assert.throws(() => x.app.runtime.services.admissions.snapshot(model.modelId));
    assert.throws(() => inference.select(context, model.canonicalName));
    for (const [index, operation] of (["load", "drain", "unload"] as const).entries()) {
      assert.equal((await x.post("/api/v1/lifecycle/operations", { request: x.command(operation, 40 + index) }, x.headers)).status, 409);
      assert.throws(() => x.app.runtime.services.admissions.snapshot(model.modelId));
    }
    assert.equal(x.app.runtime.services.commands.poll("host-1").command, null);
  } finally { await x.close(); }
});

test("owner HTTP recovers cancellation uncertainty only through fresh drain across paired draining heartbeats and immutable replay", { timeout: 15_000 }, async () => {
  const x = await fixture();
  try {
    assert.equal((await x.post("/api/v1/policy/install", inferencePolicy, x.headers)).status, 200);
    await runOwnerOperation(x, "load", 50, 1); // sole legitimate registration path
    assert.ok(x.heartbeat(2).ok);
    const { admissions, inference } = x.app.runtime.services, context = await inferenceContext(x);
    assert.equal(x.repos.models.get("model-1")?.state, "running");
    const selected = inference.select(context, "example/model:latest");
    assert.throws(() => inference.select(context, "other/model"));
    const handle = inference.open(context, selected, { model: selected.model, messages: [{ role: "user", content: "synthetic local relay cancellation" }] }, new AbortController().signal);
    assert.equal(admissions.snapshot("model-1").active, 1);
    // Real runtime cancellation is not a remote provider idle proof.
    handle.cancel(); await handle.outcome;
    assert.equal(admissions.snapshot("model-1").active, 0);
    assert.equal(admissions.snapshot("model-1").uncertain, true);
    assert.ok(x.heartbeat(3, "draining").ok);
    assert.equal((await x.post("/api/v1/lifecycle/operations", { request: x.command("unload", 51) }, x.headers)).status, 409);
    assert.equal(admissions.snapshot("model-1").uncertain, true);
    const drain = await runOwnerOperation(x, "drain", 52, 4);
    assert.equal(admissions.snapshot("model-1").uncertain, undefined);
    assert.equal(admissions.snapshot("model-1").draining, true);
    assert.equal((x.repos.models.get("model-1")?.snapshot as any).observedAt, "2026-09-29T10:00:04.000Z");
    assert.ok(x.heartbeat(5, "draining").ok);
    const count = x.app.runtime.jobStores.audit.list().filter(row => row.action === "lifecycle-observation-applied").length;
    const retry = await x.post("/api/v1/lifecycle/operations", { request: drain }, x.headers);
    assert.equal(retry.status, 200); assert.equal((await retry.json() as any).value.state, "succeeded");
    assert.equal(x.repos.models.get("model-1")?.observedAt, "2026-09-29T10:00:05.000Z");
    assert.equal((x.repos.models.get("model-1")?.snapshot as any).runtimeState, "draining");
    assert.equal(x.app.runtime.jobStores.audit.list().filter(row => row.action === "lifecycle-observation-applied").length, count);
    // Even exact previously successful drain replay is not a NEW idle proof.
    admissions.markUncertain("model-1");
    assert.equal((await x.post("/api/v1/lifecycle/operations", { request: drain }, x.headers)).status, 200);
    assert.equal(admissions.snapshot("model-1").uncertain, true);
    assert.equal((await x.post("/api/v1/lifecycle/operations", { request: x.command("unload", 53) }, x.headers)).status, 409);
    assert.throws(() => admissions.acquire("model-1"));
    await runOwnerOperation(x, "drain", 54, 6);
    assert.ok(x.heartbeat(7, "draining").ok);
    await runOwnerOperation(x, "unload", 55, 8);
    assert.equal(x.repos.models.get("model-1")?.state, "installed");
    assert.equal(admissions.snapshot("model-1").draining, true);
    assert.equal(admissions.snapshot("model-1").uncertain, undefined);
    assert.throws(() => inference.select(context, selected.model));
  } finally { await x.close(); }
});

test("draining unload remains closed for missing malformed unknown positive foreign stale or untrusted proof and active shared leases", { timeout: 30_000 }, async () => {
  for (const mutation of ["missing-active", "malformed-active", "unbounded-active", "unknown", "positive", "foreign-model", "foreign-provider", "foreign-name", "unbound-time", "stale-model", "stale-liveness", "revoked", "policy", "shared-active"] as const) {
    const x = await fixture();
    try {
      assert.equal((await x.post("/api/v1/policy/install", policy, x.headers)).status, 200);
      await runOwnerOperation(x, "load", 60, 1);
      const admissions = x.app.runtime.services.admissions;
      const lease = mutation === "shared-active" ? admissions.acquire("model-1") : null;
      void admissions.stopAdmission("model-1");
      assert.ok(x.heartbeat(2, mutation === "unknown" ? "unknown" : "draining", mutation === "positive" ? 1 : 0).ok);
      const model = x.repos.models.get("model-1")!, snapshot = { ...(model.snapshot as Record<string, unknown>) };
      // Malformed legacy/corrupt durable facts must not bypass the heartbeat parser.
      if (mutation === "missing-active") delete snapshot.activeRequests;
      if (mutation === "malformed-active") snapshot.activeRequests = "0";
      if (mutation === "unbounded-active") snapshot.activeRequests = 1_000_001;
      if (mutation === "foreign-model") snapshot.modelId = "other-model";
      if (mutation === "foreign-provider") snapshot.providerId = "other-provider";
      if (mutation === "foreign-name") snapshot.displayName = "other/model";
      if (mutation === "unbound-time") snapshot.observedAt = T0;
      x.repos.db.prepare("UPDATE models SET snapshot_json=? WHERE model_id=?").run(JSON.stringify(snapshot), model.modelId);
      if (mutation === "stale-model") x.repos.db.prepare("UPDATE models SET observed_at=? WHERE model_id=?").run("2026-09-29T09:58:00.000Z", model.modelId);
      if (mutation === "stale-liveness") x.repos.db.prepare("UPDATE fleet_liveness SET last_observed_at=?").run("2026-09-29T09:58:00.000Z");
      if (mutation === "revoked") assert.ok(x.certs.revoke(x.fp, "2026-09-29T10:00:02.000Z"));
      if (mutation === "policy") assert.equal((await x.post("/api/v1/policy/install", { ...policy, version: 2, allowedOperations: [] }, x.headers)).status, 200);
      assert.equal((await x.post("/api/v1/lifecycle/operations", { request: x.command("unload", 61) }, x.headers)).status, 409, mutation);
      assert.equal(x.app.runtime.services.commands.poll("host-1").command, null, mutation);
      assert.throws(() => admissions.acquire("model-1"), mutation);
      lease?.release();
    } finally { await x.close(); }
  }
});

test("paired ingestion rejects missing or malformed active counts and foreign source without overwriting running proof", { timeout: 15_000 }, async () => {
  const x = await fixture();
  try {
    assert.ok(x.heartbeat(1).ok);
    for (const [index, value] of [undefined, "0", -1, 1_000_001, 1].entries()) {
      assert.equal(x.heartbeat(2 + index, "loaded-idle", value, value === undefined ? { activeRequests: undefined } : {}).ok, false);
      assert.equal(x.repos.models.get("model-1")?.observedAt, "2026-09-29T10:00:01.000Z");
    }
    assert.equal(x.heartbeat(8, "loaded-idle", 0, {}, "192.0.2.99").ok, false);
    assert.equal(x.repos.models.get("model-1")?.state, "running");
  } finally { await x.close(); }
});

test("remote drain rejects unbound missing positive stale superseded or cancelled idle results without clearing uncertainty", { timeout: 30_000 }, async () => {
  for (const mutation of ["foreign-provider", "foreign-name", "missing-active", "positive-active", "stale", "aged", "superseded", "cancelled"] as const) {
    const x = await fixture();
    try {
      assert.equal((await x.post("/api/v1/policy/install", policy, x.headers)).status, 200);
      await runOwnerOperation(x, "load", 70, 1);
      const admissions = x.app.runtime.services.admissions;
      admissions.markUncertain("model-1"); void admissions.stopAdmission("model-1");
      assert.ok(x.heartbeat(2, "draining").ok);
      const request = x.command("drain", 71);
      const pending = x.post("/api/v1/lifecycle/operations", { request }, x.headers);
      await x.poll();
      const at = "2026-09-29T10:00:03.000Z";
      const observation: Record<string, unknown> = { action: "drain", outcome: "succeeded", providerId: "provider-1", canonicalModelName: "example/model:latest", runtimeState: "loaded", activeRequests: 0, observedAt: at };
      if (mutation === "foreign-provider") observation.providerId = "other-provider";
      if (mutation === "foreign-name") observation.canonicalModelName = "other/model";
      if (mutation === "missing-active") delete observation.activeRequests;
      if (mutation === "positive-active") observation.activeRequests = 1;
      if (mutation === "stale") observation.observedAt = T0;
      x.setNow(at);
      if (mutation === "cancelled") assert.equal((await x.post("/api/v1/lifecycle/cancel", { jobId: request.jobId }, x.headers)).status, 200);
      const result = x.app.runtime.services.commands.complete("host-1", { requestId: request.requestId, jobId: request.jobId, hostId: request.hostId, sequence: request.sequence, status: "succeeded", progress: 100, observedAt: at, observation, errorCode: null });
      if (mutation === "aged" || mutation === "superseded") {
        assert.ok(result);
        if (mutation === "aged") x.setNow("2026-09-29T10:01:04.000Z");
        else assert.ok(x.heartbeat(4, "draining").ok);
        // Existing HTTP mapping exposes observation rejection as INTERNAL_ERROR;
        // durable failure and unchanged uncertainty are the safety boundary.
        assert.equal((await pending).status, 500, mutation);
        assert.equal(x.app.runtime.jobStores.jobs.get(request.jobId)?.state, "failed");
      } else {
        assert.equal(result, null, mutation);
        if (mutation !== "cancelled") assert.equal((await x.post("/api/v1/lifecycle/cancel", { jobId: request.jobId }, x.headers)).status, 200);
        assert.equal((await pending).status, 200);
        assert.equal(x.app.runtime.jobStores.jobs.get(request.jobId)?.state, "cancelled");
      }
      assert.equal(admissions.snapshot("model-1").uncertain, true, mutation);
      assert.equal(admissions.snapshot("model-1").draining, true, mutation);
      assert.equal(admissions.snapshot("model-1").active, 0, mutation);
      assert.equal((x.repos.models.get("model-1")?.snapshot as any).runtimeState, "draining");
      assert.throws(() => admissions.acquire("model-1"), mutation);
      assert.equal(x.app.runtime.jobStores.audit.list().filter(row => row.action === "lifecycle-observation-applied").length, 1, mutation);
    } finally { await x.close(); }
  }
});

const proposalPath = (action: string) => `/api/v1/lifecycle/proposals/${action}`;
async function proposal(x: Awaited<ReturnType<typeof fixture>>, operation: "load"|"drain"|"unload" = "load") {
  const response=await x.post(proposalPath("prepare"),{operation,modelId:"model-1"},x.headers);
  assert.equal(response.status,200);return (await response.json() as any).value;
}
async function proposalAction(x: Awaited<ReturnType<typeof fixture>>, action:string, p:any, headers=x.headers) {
  return x.post(proposalPath(action),{proposalId:p.proposalId},headers);
}
test("opaque proposal HTTP enforces auth, origin, CSRF, bearer rejection and strict claim-free input",{timeout:15_000},async()=>{
 const x=await fixture();try{
  for(const action of ["prepare","approve","submit","cancel","status"]){
   assert.equal((await x.post(proposalPath(action),{})).status,401);
   assert.equal((await x.post(proposalPath(action),{},{cookie:x.cookie})).status,403);
   assert.equal((await x.post(proposalPath(action),{},{...x.headers,origin:"https://evil.example"})).status,403);
   assert.equal((await x.post(proposalPath(action),{},{...x.headers,authorization:"Bearer synthetic"})).status,401);
   assert.equal((await x.post(proposalPath(action),{},x.headers)).status,400);
  }
  for(const extra of [{intent:{observationFresh:true}},{capability:{}},{approvalId:"a".repeat(64)},{request:{}},{operation:"install"},{operation:{toString:"load"}}])assert.equal((await x.post(proposalPath("prepare"),{operation:"load",modelId:"model-1",...extra},x.headers)).status,400);
  const denied=await proposal(x);assert.ok(denied.reasons.includes("operation-disabled"));
  assert.equal((await proposalAction(x,"submit",denied)).status,200);assert.equal(x.app.runtime.services.commands.poll("host-1").command,null);
  assert.equal((await x.post(proposalPath("status"),{proposalId:denied.proposalId,jobId:"forged"},x.headers)).status,400);
  const duplicate=await x.rawPost(proposalPath("prepare"),' {"operation":"load","operation":"unload","modelId":"model-1"}',x.headers);assert.equal(duplicate.status,400);
  assert.equal((await x.rawPost(proposalPath("status"),`{"proposalId":"${denied.proposalId}","proposalId":"${denied.proposalId}"}`,x.headers)).status,400);
 }finally{await x.close();}
});
test("server-owned approval is exact-session and exact-execution bound; approve never executes, concurrent submit executes once",{timeout:15_000},async()=>{
 const x=await fixture();try{
  assert.equal((await x.post("/api/v1/policy/install",{...policy,approvalOperations:["model-load"]},x.headers)).status,200);
  const p=await proposal(x);assert.equal(p.state,"approval-required");assert.equal(p.jobId,null);
  const wire=JSON.stringify(p);for(const secret of ["capability","requestDigest","approvalId","endpoint","session_binding","requestId","snapshot"])assert.equal(wire.includes(secret),false,secret);
  const request=x.repos.db.prepare("SELECT request_id FROM lifecycle_proposal_authorizations").get() as any;
  assert.equal((await x.post("/api/v1/policy/approve",{requestId:request.request_id},x.headers)).status,409);
  const second=await x.post("/auth/v1/login",{username:"Owner",password:"synthetic-password-for-http-tests"});assert.equal(second.status,200);
  const cookie=second.headers.get("set-cookie")!.split(";",1)[0]!,csrf=(await second.json() as any).value.csrfToken,other={cookie,"x-csrf-token":csrf};
  assert.equal((await proposalAction(x,"approve",p,other)).status,409);
  assert.equal((await proposalAction(x,"approve",p)).status,200);
  assert.equal(x.app.runtime.services.commands.poll("host-1").command,null);
  assert.equal((await proposalAction(x,"submit",p,other)).status,409);
  const grant=x.repos.db.prepare("SELECT * FROM approvals WHERE request_id=?").get(request.request_id) as any;
  const reserved=x.repos.db.prepare("SELECT * FROM lifecycle_proposal_authorizations").get() as any;
  assert.equal(grant.granting_session_binding,reserved.session_binding);assert.equal(grant.granted_command_digest,reserved.command_digest);assert.equal(grant.consumed_at,null);
  const [a,b]=await Promise.all([proposalAction(x,"submit",p),proposalAction(x,"submit",p)]);assert.equal(a.status,200);assert.equal(b.status,200);
  const first=(await a.json() as any).value,again=(await b.json() as any).value;assert.equal(first.jobId,again.jobId);
  const command=await x.poll();assert.equal(commandAuthorizationDigest(command),reserved.command_digest);
  assert.equal((await x.post("/api/v1/lifecycle/operations",{request:command},other)).status,409,"legacy route cannot replay an exact proposal command from another session");
  assert.equal((await x.post("/api/v1/lifecycle/operations",{request:command},x.headers)).status,409,"proposal dispatch has exactly one owner even for the same session");
  assert.equal((x.repos.db.prepare("SELECT COUNT(*) n FROM jobs").get() as any).n,1);
  await x.complete(command,1);
  let finished:any;for(let i=0;i<100;i++){finished=(await (await proposalAction(x,"status",p)).json() as any).value;if(finished.state==="terminal")break;await new Promise(r=>setTimeout(r,5));}
  assert.equal(finished.state,"terminal");assert.equal(finished.jobState,"succeeded");
  assert.equal((await proposalAction(x,"submit",p)).status,200);assert.equal(x.app.runtime.services.commands.poll("host-1").command,null);
  assert.equal((x.repos.db.prepare("SELECT COUNT(*) n FROM jobs").get() as any).n,1);
 }finally{await x.close();}
});
test("proposal semantic policy, target, resource, trust, admission and global inference count drift require a new request",{timeout:30_000},async()=>{
 for(const drift of ["policy","target","resource","trust","admission","inference","job"]){const x=await fixture();try{
  assert.equal((await x.post("/api/v1/policy/install",policy,x.headers)).status,200);const p=await proposal(x);x.setNow("2026-09-29T10:00:01.000Z");
  if(drift==="policy")assert.equal((await x.post("/api/v1/policy/install",{...policy,version:2},x.headers)).status,200);
  if(drift==="target"){const m=x.repos.models.get("model-1")!;x.repos.models.upsert({...m,observedAt:"2026-09-29T10:00:01.000Z",canonicalName:"other:model"});}
  if(drift==="resource"){const h=x.repos.hosts.get("host-1")!,s=h.snapshot as any;x.repos.hosts.upsert({...h,observedAt:"2026-09-29T10:00:01.000Z",snapshot:{...s,resource:{...s.resource,memory:{totalBytes:100,usedBytes:11,availableBytes:89}}}});}
  if(drift==="trust")x.certs.revoke(x.fp,T0);
  if(drift==="admission")x.app.runtime.services.admissions.register("model-1");
  if(drift==="job")x.app.runtime.jobStores.withAuditTransaction(tx=>tx.jobs.create({operation:{jobId:"fixture-active-job",requestId:"fixture-active-request",action:"load",hostId:"host-1",submittedAt:T0,manifestRevision:null,idempotencyKey:"fixture-active-idem",idempotent:true},state:"submitted",updatedAt:T0,progressPercent:null,attempt:1,terminalCode:null,terminalMessage:null}));
  if(drift==="inference")x.repos.db.prepare("INSERT INTO inference_executions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)").run("synthetic-inference","synthetic-job","synthetic-token","a".repeat(32),"host-1","provider-1","model-1","0".repeat(64),1,"0".repeat(64),"2026-09-29T10:04:00.000Z",T0,null,"running");
  const response=await proposalAction(x,"submit",p);assert.equal(response.status,200,drift);assert.equal((await response.json() as any).value.state,"stale",drift);
  assert.equal(x.app.runtime.services.commands.poll("host-1").command,null);
  const first=(x.repos.db.prepare("SELECT request_id FROM lifecycle_proposal_authorizations").get() as any).request_id;
  const next=await proposal(x);assert.notEqual(next.proposalId,p.proposalId);const rows=x.repos.db.prepare("SELECT request_id FROM lifecycle_proposal_authorizations").all() as any[];assert.equal(rows.length,2);assert.ok(rows.some(r=>r.request_id!==first));
 }finally{await x.close();}}
});
test("proposal expiry, cancellation, credential revocation, shutdown and restart close unsubmitted authority",{timeout:30_000},async()=>{
 const x=await fixture();let reopened:ReturnType<typeof x.reopen>|null=null;try{
  assert.equal((await x.post("/api/v1/policy/install",{...policy,approvalOperations:["model-load"]},x.headers)).status,200);
  const cancelled=await proposal(x);await proposalAction(x,"approve",cancelled);const c=await proposalAction(x,"cancel",cancelled);assert.equal((await c.json() as any).value.state,"cancelled");await proposalAction(x,"submit",cancelled);assert.equal(x.app.runtime.services.commands.poll("host-1").command,null);
  const expired=await proposal(x);x.setNow("2026-09-29T10:05:00.000Z");assert.equal((await (await proposalAction(x,"submit",expired)).json() as any).value.state,"expired");x.setNow(T0);
  const p=await proposal(x);await proposalAction(x,"approve",p);await x.app.stop();assert.equal((x.repos.db.prepare("SELECT COUNT(*) n FROM lifecycle_proposal_authorizations WHERE revoked_at IS NULL").get() as any).n,0);await x.app.start();assert.equal((await proposalAction(x,"submit",p)).status,409);
  const revoked=await proposal(x);x.repos.db.exec("UPDATE owners SET credential_version=credential_version+1");assert.equal((await proposalAction(x,"submit",revoked)).status,401);
  await x.app.close();reopened=x.reopen();await reopened.start();assert.equal(reopened.runtime.services.commands.poll("host-1").command,null);
 }finally{await reopened?.close();await x.close();}
});
test("submitted proposal cancellation and graceful close settle the existing owned durable job without redispatch",{timeout:15_000},async()=>{
 for(const finishFirst of [false,true]){const x=await fixture();try{
  assert.equal((await x.post("/api/v1/policy/install",policy,x.headers)).status,200);const p=await proposal(x);await proposalAction(x,"submit",p);const command=await x.poll();
  if(finishFirst)await x.complete(command,1);else assert.equal((await proposalAction(x,"cancel",p)).status,200);
  await x.app.stop();assert.equal(x.app.runtime.jobStores.jobs.get(command.jobId)?.state,finishFirst?"succeeded":"cancelled");
  assert.equal(x.app.runtime.services.lifecycle.acceptsSubmissions,false);
  assert.equal((x.repos.db.prepare("SELECT COUNT(*) n FROM jobs").get() as any).n,1);
 }finally{await x.close();}}
});

test("opaque proposal load, explicit drain and explicit unload page sequence uses only server commands",{timeout:15_000},async()=>{
 const x=await fixture();try{
  assert.equal((await x.post("/api/v1/policy/install",{...policy,approvalOperations:["model-load","model-drain","model-unload"]},x.headers)).status,200);
  for(const [index,operation] of (["load","drain","unload"] as const).entries()){
   const p=await proposal(x,operation);assert.equal(p.operation,operation);
   const approved=(await (await proposalAction(x,"approve",p)).json() as any).value;assert.equal(approved.state,"approved");assert.equal(approved.jobId,null);
   const submitted=(await (await proposalAction(x,"submit",p)).json() as any).value;assert.ok(submitted.jobId);
   const command=await x.poll();assert.equal(command.operation,operation);assert.equal(command.params && (command.params as any).model,"example/model:latest");
   await x.complete(command,index+1);
   let terminal:any;for(let i=0;i<100;i++){terminal=(await (await proposalAction(x,"status",p)).json() as any).value;if(terminal.state==="terminal")break;await new Promise(r=>setTimeout(r,5));}
   assert.equal(terminal.jobState,"succeeded");assert.equal(terminal.jobId,submitted.jobId);
   if(operation==="drain"){assert.equal(x.app.runtime.services.admissions.snapshot("model-1").draining,true);assert.equal(x.repos.models.get("model-1")?.state,"running","drain must not unload");}
  }
  assert.equal(x.repos.models.get("model-1")?.state,"installed");
 }finally{await x.close();}
});
test("unchanged fresh heartbeat facts preserve proposal intent while no mutation executes during preparation",{timeout:15_000},async()=>{
 const x=await fixture();try{
  assert.equal((await x.post("/api/v1/policy/install",policy,x.headers)).status,200);const p=await proposal(x);
  assert.ok(x.heartbeat(1,"unloaded").ok);
  const submitted=(await (await proposalAction(x,"submit",p)).json() as any).value;assert.equal(submitted.state,"submitting");
  const command=await x.poll();await x.complete(command,2);
 }finally{await x.close();}
});
test("restart recovers a submitted redacted job view but never resubmits its command",{timeout:15_000},async()=>{
 const x=await fixture();let reopened:ReturnType<typeof x.reopen>|null=null;try{
  assert.equal((await x.post("/api/v1/policy/install",policy,x.headers)).status,200);const p=await proposal(x);await proposalAction(x,"submit",p);const command=await x.poll();
  await x.app.close();reopened=x.reopen();await reopened.start();
  const {routeManagementRequest}=await import("./management-api.js");const deps=createManagementDependencies(reopened.runtime,["http://127.0.0.1"],{allowLoopbackHttpDevelopment:true},{},()=>T0);
  for(const action of ["status","submit","approve","cancel"]){const response=await routeManagementRequest(deps,{method:"POST",url:proposalPath(action),headers:{cookie:x.cookie,"x-csrf-token":x.headers["x-csrf-token"],origin:"http://127.0.0.1","content-type":"application/json"},body:JSON.stringify({proposalId:p.proposalId})});assert.equal(response.status,200);const view=(response.body as any).value;assert.equal(view.state,"terminal");assert.equal(view.jobState,"cancelled");assert.equal(view.jobId,command.jobId);assert.equal(JSON.stringify(view).includes("digest"),false);}
  assert.equal(reopened.runtime.services.commands.poll("host-1").command,null);assert.equal((reopened.runtime.repositories.db.prepare("SELECT COUNT(*) n FROM jobs").get() as any).n,1);
 }finally{await reopened?.close();await x.close();}
});

test("proposal capacity is bounded and expiry releases slots without creating any job",{timeout:30_000},async()=>{
 const x=await fixture();try{
  const ids=new Set<string>();for(let i=0;i<256;i++){const p=await proposal(x);assert.ok(Date.parse(p.expiresAt)-Date.parse(T0)<=300_000);ids.add(p.proposalId);}assert.equal(ids.size,256);
  assert.equal((await x.post(proposalPath("prepare"),{operation:"load",modelId:"model-1"},x.headers)).status,409);
  assert.equal((x.repos.db.prepare("SELECT COUNT(*) n FROM jobs").get() as any).n,0);
  x.setNow("2026-09-29T10:05:00.000Z");assert.ok(await proposal(x));
  assert.equal((x.repos.db.prepare("SELECT COUNT(*) n FROM lifecycle_proposal_authorizations WHERE revoked_at IS NOT NULL").get() as any).n,256);
 }finally{await x.close();}
});
test("proposal authority is capped by the authenticated session expiry and expires with credential revocation",{timeout:15_000},async()=>{
 const x=await fixture();try{
  x.repos.db.exec("UPDATE sessions SET idle_expires_at='2026-09-29T10:00:30.000Z'");const p=await proposal(x);assert.equal(p.expiresAt,"2026-09-29T10:00:30.000Z");
  x.setNow(p.expiresAt);assert.equal((await proposalAction(x,"submit",p)).status,401);assert.equal(x.app.runtime.services.commands.poll("host-1").command,null);
 }finally{await x.close();}
});
test("concurrent proposal cancellation and submit reduce authority without duplicate jobs or remote idle claims",{timeout:15_000},async()=>{
 for(const actions of [["cancel","submit"],["submit","cancel"]]){const x=await fixture();try{
  assert.equal((await x.post("/api/v1/policy/install",policy,x.headers)).status,200);const p=await proposal(x);
  const replies=await Promise.all(actions.map(action=>proposalAction(x,action,p)));for(const response of replies)assert.equal(response.status,200);
  await x.app.stop();const jobs=x.repos.db.prepare("SELECT state FROM jobs").all() as {state:string}[];assert.ok(jobs.length<=1);for(const job of jobs)assert.equal(job.state,"cancelled");
  assert.equal(x.repos.models.get("model-1")?.state,"installed");
 }finally{await x.close();}}
});
