import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";
import { commandAuthorizationDigest, commandPolicyOperation, type CommandRequest, type OperationPolicy } from "@lan-model-manager/core";
import { createRuntimeInferenceHandler } from "./inference-runtime.js";
import { createAdmissionController } from "./admission-accounting.js";
import { CommandDispatcher } from "./command-dispatch.js";
import { createControllerApplication, type ControllerApplicationOptions } from "./controller-application.js";
import { createManagementDependencies } from "./management-runtime.js";
import { CertificateRepository } from "./certificate-repository.js";

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
  return { app, repos, post, headers, cookie, command, poll, complete, certs, fp, reopen: () => createControllerApplication(options), setNow: (value: string) => now = value, async close() { await app.close(); rmSync(root, { recursive: true, force: true }); } };
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
