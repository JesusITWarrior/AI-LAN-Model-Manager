import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { commandAuthorizationDigest, commandPolicyOperation, type CommandRequest, type CommandResponse } from "@lan-model-manager/core";
import { AgentCommandStore } from "./agent-command-channel.js";
import { CommandDispatcher } from "./command-dispatch.js";
import { CertificateRepository } from "./certificate-repository.js";
import { openControllerDatabase } from "./database.js";
import { createAllowedOrigins } from "./origin.js";
import { createJobStores } from "./jobs-store.js";
import { createOwnerBootstrapService } from "./owner-service.js";
import { guardManagementRequest } from "./guard.js";
import { OwnerNativeEvidenceIntakeService } from "./owner-native-evidence-intake.js";
import { encodeNativeTerminalEvidence } from "./native-terminal-evidence-codec.js";
import { buildOwnerNativeEvidenceSnapshot } from "./owner-native-evidence-snapshot.js";
import { SessionManager } from "./session-manager.js";

const NOW = "2026-09-27T10:00:06.000Z";
const ORIGINS = createAllowedOrigins(["https://manager.example"]);
const cryptoEngine = { random: (n: number) => Buffer.alloc(n, 3), async derive(password: Uint8Array, salt: Uint8Array, parameters: { keyLength: number }) {
  const seed = createHash("sha256").update(password).update(salt).digest(); return Buffer.alloc(parameters.keyLength, seed[0]);
}, equal: (a: Uint8Array, b: Uint8Array) => Buffer.from(a).equals(Buffer.from(b)) };
async function fixture(observationBytes = 0) {
  const db = openControllerDatabase(":memory:");
  let now = "2026-09-27T10:00:00.000Z", random = 0;
  const owners = createOwnerBootstrapService(db, { now: () => now, ownerId: () => "a".repeat(32), crypto: cryptoEngine });
  await owners.bootstrapOwner({ username: "Admin", password: "owner-password-123" });
  const sessions = new SessionManager(db, owners, { clock: () => now, random: n => Buffer.alloc(n, ++random), policy: { absoluteTtlMs: 3600000, idleTtlMs: 600000, touchAfterMs: 60000 } });
  const session = await sessions.create({ username: "admin", password: "owner-password-123" }); assert.ok(session);
  const stores = createJobStores(db, { now: () => now });
  const certs = new CertificateRepository(db), pem = "-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n";
  certs.insertCa({ caId: "b".repeat(64), version: 1, serial: "10", fingerprint: "b".repeat(64), certificatePem: pem,
    notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2036-01-01T00:00:00.000Z", createdAt: "2026-09-27T10:00:00.000Z" });
  certs.insertHost({ certificateId: "c".repeat(64), serial: "ABCD", fingerprint: "d".repeat(64), certificatePem: pem,
    caId: "b".repeat(64), caVersion: 1, binding: { candidateId: "host-1", address: "192.0.2.10", port: 7443, protocolMajor: 1, protocolMinor: 0 },
    spiffeUri: "spiffe://lanmodelmanager/host/host-1", challengeId: "e".repeat(64), transcriptDigest: "f".repeat(64),
    notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2036-01-01T00:00:00.000Z", status: "active", version: 1,
    issuedAt: "2026-09-27T10:00:00.000Z", revokedAt: null });
  const operation = "probe";
  const request: CommandRequest = { requestId: "request-1", jobId: "job-1", hostId: "host-1", operation, idempotencyKey: "idem-1", sequence: 1,
    deadline: "2026-09-27T10:05:00.000Z", capability: { operation: commandPolicyOperation(operation), targetKind: "host", targetId: "host-1",
      hostId: "host-1", modelId: null, requestDigest: "", expiresAt: "2026-09-27T10:05:00.000Z" }, params: { providerId: "provider-1", model: "model:latest" } };
  (request.capability as { requestDigest: string }).requestDigest = commandAuthorizationDigest(request);
  const queue = new AgentCommandStore(db, () => now, 30000, stores);
  assert.equal(new CommandDispatcher(stores, queue, () => now).dispatch(request).ok, true);
  assert.ok(queue.poll(request.hostId).command);
  const response: CommandResponse = { requestId: request.requestId, jobId: request.jobId, hostId: request.hostId, sequence: 1,
    status: "failed", progress: null, observedAt: NOW, observation: observationBytes ? "x".repeat(observationBytes) : null, errorCode: "ADAPTER_FAILED" };
  assert.ok(Buffer.byteLength(JSON.stringify(response), "utf8") <= 512 * 1024, "fixture response stays within the accepted wire limit");
  now = NOW; assert.ok(queue.complete(request.hostId, response));
  let raw: Uint8Array;
  stores.withAuditTransaction(tx => {
    const built = buildOwnerNativeEvidenceSnapshot(db, tx, "job-1", Buffer.from(JSON.stringify(response)), "synthetic", now);
    assert.ok(built);
    const encoded = encodeNativeTerminalEvidence(built.snapshot);
    assert.ok(encoded.ok);
    raw = Uint8Array.from(Buffer.from(encoded.payloadBase64, "base64"));
  });
  let serviceClockCalls = 0;
  const service = new OwnerNativeEvidenceIntakeService(db, sessions, ORIGINS, () => { serviceClockCalls++; return now; });
  const envelope = (bytes: Uint8Array, selector = "job-1", cookie = `__Host-lanmm_session=${session.sessionToken}`) => ({
    method: "POST", path: "/api/v1/native-evidence/prepare", cookieHeader: cookie,
    originHeader: "https://manager.example", csrfHeader: session.csrfToken, jobSelector: selector, rawPayloadBytes: bytes });
  return { db, session, sessions, stores, service, raw: raw!, envelope, get serviceClockCalls() { return serviceClockCalls; } };
}

type ObservedStage = { raw: Uint8Array; response: Uint8Array | null };
function captureService(f: Awaited<ReturnType<typeof fixture>>, clock: () => string = () => NOW) {
  const stages: ObservedStage[] = [];
  let service!: OwnerNativeEvidenceIntakeService;
  service = new OwnerNativeEvidenceIntakeService(f.db, f.sessions, ORIGINS, () => {
    const stage = (service as unknown as { staging: ObservedStage | null }).staging;
    if (stage) stages.push({ raw: stage.raw, response: stage.response });
    return clock();
  });
  return { service, stages };
}
function validGuard(f: Awaited<ReturnType<typeof fixture>>) {
  const guard = guardManagementRequest(f.sessions, ORIGINS, { method: "POST", cookieHeader: `__Host-lanmm_session=${f.session.sessionToken}`,
    originHeader: "https://manager.example", csrfHeader: f.session.csrfToken });
  assert.ok(guard.ok);
  return guard;
}
function protectedSnapshot(db: import("node:sqlite").DatabaseSync): string {
  const rows = (table: string, order: string) => db.prepare(`SELECT * FROM ${table} ORDER BY ${order}`).all();
  return JSON.stringify({ jobs: rows("jobs", "job_id"), history: rows("job_history", "history_id"), queue: rows("agent_commands", "job_id"),
    evidence: rows("supplemental_native_evidence", "tuple_digest"), audit: rows("audit_events", "seq") });
}
function assertWiped(stage: ObservedStage): void {
  assert.ok(stage.raw.length > 0);
  assert.ok(stage.raw.every(byte => byte === 0), "owned raw staging copy is wiped");
  assert.ok(stage.response && stage.response.length > 0);
  assert.ok(stage.response!.every(byte => byte === 0), "owned response staging copy observed at the boundary is wiped");
}

test("owner payload intake authenticates, validates current DB projection, and returns only redacted preview", async () => {
  const f = await fixture();
  try {
    const caller = Uint8Array.from(f.raw), original = caller.slice();
    const result = f.service.prepare(f.envelope(caller));
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.deepEqual(caller, original, "caller-owned bytes remain unchanged");
    assert.deepEqual(Object.keys(result.preview), ["candidateHandle", "expectedTupleDigest", "jobId", "hostId", "requestId", "terminalState", "terminalRevision", "evidenceKind", "payloadBytes", "responseBytes", "expiresAt", "action", "disposition", "label"]);
    assert.equal(result.preview.jobId, "job-1"); assert.equal(result.preview.hostId, "host-1");
    assert.equal(result.preview.label, "Owner-provided unsigned evidence; source not independently proven");
    assert.equal(result.preview.payloadBytes, caller.length);
    const rendered = JSON.stringify(result.preview);
    for (const forbidden of ["responseBase64", "certificateAssertion", "fingerprint", "serial", "consentedAt", "confirmationId", "trust", "runnerHold", "PRIVATE"]) assert.equal(rendered.includes(forbidden), false);
  } finally { f.service.close(); f.db.close(); }
});

test("owner payload intake denies auth, envelope, selector and malformed bytes without candidate retention", async () => {
  const f = await fixture();
  try {
    const deny = (input: unknown) => assert.deepEqual(f.service.prepare(input), { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" });
    const beforeAuth = f.serviceClockCalls;
    deny(f.envelope(f.raw, "job-1", "__Host-lanmm_session=invalid"));
    assert.equal(f.serviceClockCalls, beforeAuth, "failed authentication must not call the registry clock or staged builder");
    deny({ ...f.envelope(f.raw), method: "GET" });
    deny({ ...f.envelope(f.raw), path: "/api/v1/native-evidence/prepare?x=1" });
    deny(f.envelope(f.raw, "foreign-job"));
    const text = Buffer.from(f.raw).toString("utf8");
    const malformed = [text.replace('"kind":', '"domain":"duplicate","kind":'), text.slice(0, -1) + ',"unknown":true}',
      text.replace('"version":1', '"version":9007199254740992'), text.replace(/"responseBase64":"[^"]*"/, '"responseBase64":"@@@"'),
      text.replace('"jobId":"job-1"', '"jobId":"foreign-job"')];
    for (const bytes of [...malformed.map(value => Buffer.from(value)), Uint8Array.from([...f.raw, 0x78]),
      Uint8Array.from([0xef, 0xbb, 0xbf, ...f.raw]), Uint8Array.from([0xff, 0xfe])]) deny(bytes);
    const proxy = new Proxy(f.envelope(f.raw), { ownKeys() { throw new Error("must not invoke proxy"); } }); deny(proxy);
    const accessor = Object.defineProperty({ ...f.envelope(f.raw) }, "cookieHeader", { enumerable: true, get() { throw new Error("must not invoke getter"); } }); deny(accessor);
  } finally { f.service.close(); f.db.close(); }
});

test("intake rejects reentrant calls and close delegates once to the sole registry", async () => {
  const f = await fixture();
  try {
    let nested: unknown;
    let recursive!: OwnerNativeEvidenceIntakeService;
    recursive = new OwnerNativeEvidenceIntakeService(f.db, f.sessions, ORIGINS, () => {
      if (nested === undefined) nested = recursive.prepare(f.envelope(f.raw));
      return NOW;
    });
    const result = recursive.prepare(f.envelope(f.raw));
    assert.equal(result.ok, true);
    assert.deepEqual(nested, { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" });
    recursive.close();
    assert.deepEqual(recursive.prepare(f.envelope(f.raw)), { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" });
    f.service.close();
    assert.deepEqual(f.service.prepare(f.envelope(f.raw)), { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" });
  } finally { f.service.close(); f.db.close(); }
});

test("intake boundary wipes its exact staging copies while the later candidate lease remains intact", async () => {
  const f = await fixture(), { service, stages } = captureService(f);
  try {
    const before = protectedSnapshot(f.db), caller = Uint8Array.from(f.raw), callerBefore = caller.slice();
    const prepared = service.prepare(f.envelope(caller));
    assert.equal(prepared.ok, true);
    assert.ok(stages.length >= 1);
    for (const stage of stages) assertWiped(stage);
    assert.deepEqual(caller, callerBefore, "caller-owned payload remains untouched");
    assert.equal(protectedSnapshot(f.db), before, "intake does not change job/history/evidence/audit state");
    if (!prepared.ok) return;
    const expectedResponse = Buffer.from((JSON.parse(Buffer.from(f.raw).toString("utf8")) as { responseBase64: string }).responseBase64, "base64");
    const guard = validGuard(f), claimed = service.candidateRegistry.claim(guard, { handle: prepared.preview.candidateHandle,
      action: "append-supplemental-native-evidence", disposition: "evidence-only" });
    assert.equal(claimed.ok, true);
    if (!claimed.ok) return;
    let callbackEntered = false, payloadIntact = false, responseIntact = false;
    assert.equal(service.candidateRegistry.inspect(guard, prepared.preview.candidateHandle).ok, true, "candidate remains available before lease inspection");
    f.stores.withAuditTransaction(tx => {
      assert.ok(f.sessions.bindingInTransaction(tx, guard.session), "active coupled session binding");
      const view = service.candidateRegistry.withLeaseView(guard, tx, claimed.token, candidate => {
        callbackEntered = true;
        payloadIntact = Buffer.from(candidate.payloadBytes).equals(Buffer.from(callerBefore));
        responseIntact = Buffer.from(candidate.responseBytes).equals(Buffer.from(expectedResponse));
        return "match";
      });
      assert.equal(callbackEntered, true, "candidate lease view reached the byte-comparison callback");
      assert.deepEqual(view, { ok: true, match: true });
    });
    assert.equal(payloadIntact, true, "registry-owned raw candidate copy survived staging cleanup");
    assert.equal(responseIntact, true, "registry-owned response copy survived staging cleanup");
    assert.equal(protectedSnapshot(f.db), before);
  } finally { service.close(); f.service.close(); f.db.close(); }
});

test("decode failure, clock throw, transaction throw, and close reentrancy wipe observed temporary arrays", async t => {
  await t.test("codec mismatch after staged snapshot construction", async () => {
    const f = await fixture(), original = JSON.parse(Buffer.from(f.raw).toString("utf8")) as Record<string, unknown>;
    const tuple = { ...(original.tuple as Record<string, unknown>), responseDigest: "0".repeat(64) };
    const tampered = Buffer.from(JSON.stringify({ ...original, tuple }));
    const { service, stages } = captureService(f);
    try {
      assert.deepEqual(service.prepare(f.envelope(tampered)), { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" });
      assert.ok(stages.length >= 1); for (const stage of stages) assertWiped(stage);
      assert.equal(service.candidateRegistry.size, 0); assert.equal(service.candidateRegistry.retainedByteCount, 0);
    } finally { service.close(); f.service.close(); f.db.close(); }
  });
  await t.test("registry clock throws after staging is visible", async () => {
    const f = await fixture(), { service, stages } = captureService(f, () => { throw new Error("clock canary"); });
    try {
      assert.deepEqual(service.prepare(f.envelope(f.raw)), { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" });
      assert.ok(stages.length >= 1); for (const stage of stages) assertWiped(stage);
      assert.equal(service.candidateRegistry.size, 0); assert.equal(service.candidateRegistry.retainedByteCount, 0);
    } finally { service.close(); f.service.close(); f.db.close(); }
  });
  await t.test("an open transaction makes the builder transaction boundary throw", async () => {
    const f = await fixture(); let opened = false;
    const { service, stages } = captureService(f, () => { f.db.exec("BEGIN IMMEDIATE"); opened = true; return NOW; });
    try {
      assert.deepEqual(service.prepare(f.envelope(f.raw)), { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" });
      assert.equal(opened, true); f.db.exec("ROLLBACK");
      assert.ok(stages.length >= 1); for (const stage of stages) assertWiped(stage);
      assert.equal(service.candidateRegistry.size, 0); assert.equal(service.candidateRegistry.retainedByteCount, 0);
    } finally { if (f.db.isTransaction) f.db.exec("ROLLBACK"); service.close(); f.service.close(); f.db.close(); }
  });
  await t.test("close during preparation prevents insertion and wipes staging", async () => {
    const f = await fixture(); let service!: OwnerNativeEvidenceIntakeService;
    const stages: ObservedStage[] = [];
    service = new OwnerNativeEvidenceIntakeService(f.db, f.sessions, ORIGINS, () => {
      const stage = (service as unknown as { staging: ObservedStage | null }).staging;
      if (stage) stages.push({ raw: stage.raw, response: stage.response });
      service.close(); return NOW;
    });
    try {
      assert.deepEqual(service.prepare(f.envelope(f.raw)), { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" });
      assert.equal(stages.length, 1); assertWiped(stages[0]!);
      assert.equal(service.candidateRegistry.size, 0); assert.equal(service.candidateRegistry.retainedByteCount, 0);
      assert.deepEqual(service.prepare(f.envelope(f.raw)), { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" });
    } finally { service.close(); f.service.close(); f.db.close(); }
  });
});

test("authenticated service enforces its 16-entry boundary, expires retained bytes after 60s, and close disables preparation", async () => {
  const f = await fixture(); let registryNow = NOW;
  const { service, stages } = captureService(f, () => registryNow);
  try {
    for (let i = 0; i < 16; i++) assert.equal(service.prepare(f.envelope(f.raw)).ok, true, `entry ${i + 1}`);
    assert.equal(service.candidateRegistry.size, 16);
    const retained = service.candidateRegistry.retainedByteCount;
    assert.ok(retained > 0);
    assert.deepEqual(service.prepare(f.envelope(f.raw)), { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" });
    assertWiped(stages.at(-1)!);
    assert.equal(service.candidateRegistry.size, 16);
    registryNow = "2026-09-27T10:01:06.001Z";
    const afterExpiry = service.prepare(f.envelope(f.raw));
    assert.equal(afterExpiry.ok, true, "the first post-TTL prepare prunes real retained entries and can prepare again");
    assert.equal(service.candidateRegistry.size, 1);
    assert.ok(service.candidateRegistry.retainedByteCount > 0);
    service.close();
    assert.equal(service.candidateRegistry.size, 0); assert.equal(service.candidateRegistry.retainedByteCount, 0);
    const stageCount = stages.length;
    assert.deepEqual(service.prepare(f.envelope(f.raw)), { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" });
    assert.equal(stages.length, stageCount, "closed service cannot re-enter the clock or preparation callback");
  } finally { service.close(); f.service.close(); f.db.close(); }
});

test("realistic accepted large payloads reach aggregate retained-byte pressure and expiry frees the budget", async () => {
  // Large valid JSON observations make both response and base64 payloads large; no fake registry size/accounting is injected.
  const f = await fixture(523_700); let registryNow = NOW;
  const { service, stages } = captureService(f, () => registryNow);
  try {
    const rawLength = f.raw.length;
    assert.ok(rawLength > 600 * 1024 && rawLength < 768 * 1024, "fixture is a realistically large accepted payload");
    for (let i = 0; i < 6; i++) assert.equal(service.prepare(f.envelope(f.raw)).ok, true, `large candidate ${i + 1}`);
    const retained = service.candidateRegistry.retainedByteCount;
    assert.equal(service.candidateRegistry.size, 6);
    const responseLength = Buffer.from((JSON.parse(Buffer.from(f.raw).toString("utf8")) as { responseBase64: string }).responseBase64, "base64").length;
    assert.ok(retained > 6 * 1024 * 1024 && retained < 8 * 1024 * 1024, "real retained copies approach the aggregate limit");
    assert.ok(retained + f.raw.length + responseLength > 8 * 1024 * 1024, "the next otherwise-valid large candidate crosses the 8 MiB bound");
    const overBudget = service.prepare(f.envelope(f.raw));
    assert.deepEqual(overBudget, { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" });
    assertWiped(stages.at(-1)!);
    assert.equal(service.candidateRegistry.size, 6);
    assert.equal(service.candidateRegistry.retainedByteCount, retained, "rejected preparation retains no registry candidate");
    registryNow = "2026-09-27T10:01:06.001Z";
    const afterExpiry = service.prepare(f.envelope(f.raw));
    assert.equal(afterExpiry.ok, true);
    assert.equal(service.candidateRegistry.size, 1);
    assert.ok(service.candidateRegistry.retainedByteCount < 8 * 1024 * 1024);
    service.close();
    assert.equal(service.candidateRegistry.size, 0); assert.equal(service.candidateRegistry.retainedByteCount, 0);
  } finally { service.close(); f.service.close(); f.db.close(); }
});

test("cookie, origin, and CSRF failures do not read attacker byte properties or mutate protected state", async () => {
  const f = await fixture();
  try {
    const before = protectedSnapshot(f.db); let byteReads = 0;
    const makeHostile = () => {
      const bytes = Uint8Array.from(f.raw);
      Object.defineProperty(bytes, "buffer", { configurable: true, get() { byteReads++; throw new Error("byte canary"); } });
      return bytes;
    };
    const requests = [
      f.envelope(makeHostile(), "job-1", "__Host-lanmm_session=invalid"),
      { ...f.envelope(makeHostile()), originHeader: "https://attacker.example" },
      { ...f.envelope(makeHostile()), csrfHeader: "wrong-csrf-token" },
    ];
    for (const request of requests) {
      assert.deepEqual(f.service.prepare(request), { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" });
      assert.equal(f.serviceClockCalls, 0, "auth denial precedes candidate clock/build");
      assert.equal(byteReads, 0, "auth denial does not read hostile byte accessors");
    }
    assert.equal(f.service.candidateRegistry.size, 0); assert.equal(f.service.candidateRegistry.retainedByteCount, 0);
    assert.equal(protectedSnapshot(f.db), before);
  } finally { f.service.close(); f.db.close(); }
});

test("hostile, shared, detached, subclass, and oversized byte views fail without invoking shadowed accessors", async () => {
  const f = await fixture();
  try {
    const before = protectedSnapshot(f.db); let invoked = 0;
    const accessors: Uint8Array[] = [];
    for (const key of ["buffer", "byteLength", "byteOffset", Symbol.iterator] as const) {
      const bytes = Uint8Array.from(f.raw);
      Object.defineProperty(bytes, key, { configurable: true, get() { invoked++; throw new Error("byte accessor canary"); } });
      accessors.push(bytes);
    }
    class HostileSubclass extends Uint8Array { override get byteOffset(): number { invoked++; throw new Error("subclass accessor canary"); } }
    const subclass = new HostileSubclass(f.raw);
    const shared = new Uint8Array(new SharedArrayBuffer(f.raw.length)); shared.set(f.raw);
    const detached = Uint8Array.from(f.raw); structuredClone(detached, { transfer: [detached.buffer] });
    const oversized = new Uint8Array(768 * 1024 + 1);
    const inputs: unknown[] = [...accessors, subclass, shared, detached, oversized,
      new Proxy(Uint8Array.from(f.raw), { get() { invoked++; throw new Error("proxy canary"); } })];
    for (const bytes of inputs) assert.deepEqual(f.service.prepare(f.envelope(bytes as Uint8Array)),
      { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" });
    assert.equal(invoked, 0, "all boundary checks use non-invoking slot/type checks");
    assert.equal(f.service.candidateRegistry.size, 0); assert.equal(f.service.candidateRegistry.retainedByteCount, 0);
    assert.equal(protectedSnapshot(f.db), before);
  } finally { f.service.close(); f.db.close(); }
});

test("intake rejects malformed raw JSON and hostile payload claims at exact wire boundaries", async () => {
  const f = await fixture();
  try {
    const text = Buffer.from(f.raw).toString("utf8"), payload = JSON.parse(text) as Record<string, unknown>;
    const response = Buffer.from(payload.responseBase64 as string, "base64");
    const badResponse = Buffer.from(JSON.stringify({ requestId: "other-request", jobId: "job-1", hostId: "host-1", sequence: 1,
      status: "failed", progress: null, observedAt: NOW, observation: null, errorCode: "ADAPTER_FAILED" }));
    const oversizedResponse = Buffer.alloc(512 * 1024 + 1, 0x20);
    const duplicateEscapedKey = Buffer.from(text.replace('"kind":', '"\\u006bind":"duplicate","kind":'));
    const unknownField = Buffer.from(text.replace(/}\s*$/, ',"unknown":true}'));
    const unsafeNumber = Buffer.from(text.replace('"version":1', '"version":9007199254740992'));
    const noncanonicalBase64 = Buffer.from(JSON.stringify({ ...payload, responseBase64: `${payload.responseBase64 as string}\n` }));
    const badHold = Buffer.from(JSON.stringify({ ...payload, tuple: { ...(payload.tuple as Record<string, unknown>), holdClass: "retained" } }));
    const badDigest = Buffer.from(JSON.stringify({ ...payload, tuple: { ...(payload.tuple as Record<string, unknown>), responseDigest: "0".repeat(64) } }));
    const callerTrustClaim = Buffer.from(JSON.stringify({ ...payload, runnerHold: "retained", currentTrust: { provenance: "verified_current" } }));
    const wrongResponse = Buffer.from(JSON.stringify({ ...payload, responseBase64: badResponse.toString("base64") }));
    const overResponse = Buffer.from(JSON.stringify({ ...payload, responseBase64: oversizedResponse.toString("base64") }));
    const mismatch = Buffer.from(JSON.stringify({ ...payload, tuple: { ...(payload.tuple as Record<string, unknown>), jobId: "other-job" } }));
    const invalids = [duplicateEscapedKey, unknownField, unsafeNumber, noncanonicalBase64, badHold, badDigest, callerTrustClaim, wrongResponse, overResponse,
      mismatch, Buffer.from(text.slice(0, -1) + " garbage"), Uint8Array.from([0xef, 0xbb, 0xbf, ...f.raw]), Uint8Array.from([0xff, 0xfe]),
      Uint8Array.from([...f.raw, 0x78]), new Uint8Array(768 * 1024 + 1)];
    const before = protectedSnapshot(f.db);
    for (const bytes of invalids) assert.deepEqual(f.service.prepare(f.envelope(bytes)), { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" });
    assert.equal(f.service.candidateRegistry.size, 0); assert.equal(f.service.candidateRegistry.retainedByteCount, 0);
    assert.equal(protectedSnapshot(f.db), before);
  } finally { f.service.close(); f.db.close(); }
});

test("allowed payload provenance never alters the fixed unsigned-evidence preview label", async () => {
  const f = await fixture();
  try {
    for (const source of ["retained_same_process", "explicit_snapshot", "synthetic"] as const) {
      const input = JSON.parse(Buffer.from(f.raw).toString("utf8")) as Record<string, unknown>;
      const result = f.service.prepare(f.envelope(Buffer.from(JSON.stringify({ ...input, evidenceSource: source }))));
      assert.equal(result.ok, true);
      if (result.ok) assert.equal(result.preview.label, "Owner-provided unsigned evidence; source not independently proven");
    }
  } finally { f.service.close(); f.db.close(); }
});

test("preparation clock closure mutations to job or certificate authority cannot produce a stale preview", async t => {
  for (const change of ["job", "certificate"] as const) await t.test(change, async () => {
    const f = await fixture(); let changed = false;
    const stages: ObservedStage[] = [];
    let service!: OwnerNativeEvidenceIntakeService;
    service = new OwnerNativeEvidenceIntakeService(f.db, f.sessions, ORIGINS, () => {
      const stage = (service as unknown as { staging: ObservedStage | null }).staging;
      if (stage) stages.push({ raw: stage.raw, response: stage.response });
      if (!changed) {
        changed = true;
        if (change === "job") f.db.prepare("UPDATE jobs SET state='running' WHERE job_id='job-1'").run();
        else f.db.prepare("UPDATE host_certificates SET status='revoked',revoked_at=? WHERE candidate_id='host-1'").run(NOW);
      }
      return NOW;
    });
    try {
      const result = service.prepare(f.envelope(f.raw));
      assert.deepEqual(result, { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" }, "fresh server projection rejects callback-mutated authority");
      assert.equal(changed, true); assert.ok(stages.length >= 1); for (const stage of stages) assertWiped(stage);
      assert.equal(service.candidateRegistry.size, 0); assert.equal(service.candidateRegistry.retainedByteCount, 0);
    } finally { service.close(); f.service.close(); f.db.close(); }
  });
});
