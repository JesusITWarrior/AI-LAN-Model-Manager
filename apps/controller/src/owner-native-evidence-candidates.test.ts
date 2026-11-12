import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { createAllowedOrigins } from "./origin.js";
import { openControllerDatabase } from "./database.js";
import { createJobStores } from "./jobs-store.js";
import { createOwnerBootstrapService } from "./owner-service.js";
import { SessionManager } from "./session-manager.js";
import { guardManagementRequest, type GuardResult } from "./guard.js";
import type { PasswordCryptoEngine } from "./credentials.js";
import {
  OWNER_NATIVE_EVIDENCE_ACTION, OWNER_NATIVE_EVIDENCE_DISPOSITION,
  OWNER_NATIVE_EVIDENCE_MAX_CANDIDATES, OWNER_NATIVE_EVIDENCE_MAX_RETAINED_BYTES,
  OwnerNativeEvidenceCandidateRegistry, type CapturedNativeEvidenceCandidate, type NativeEvidenceCandidateInput,
} from "./owner-native-evidence-candidates.js";

const START = "2026-09-27T10:00:00.000Z";
const ORIGINS = createAllowedOrigins(["https://manager.example"]);
const cryptoEngine = (): PasswordCryptoEngine => ({
  random: size => Buffer.alloc(size, 3),
  async derive(password, salt, parameters) {
    const seed = createHash("sha256").update(password).update(salt).digest();
    return Buffer.alloc(parameters.keyLength, seed[0]);
  },
  equal: (a, b) => Buffer.from(a).equals(Buffer.from(b)),
});
async function setup() {
  const db = openControllerDatabase(":memory:");
  let now = START, counter = 0;
  const owners = createOwnerBootstrapService(db, { now: () => now, ownerId: () => "a".repeat(32), crypto: cryptoEngine() });
  await owners.bootstrapOwner({ username: "Admin", password: "owner-password-123" });
  const manager = new SessionManager(db, owners, { clock: () => now, random: size => Buffer.alloc(size, ++counter),
    policy: { absoluteTtlMs: 3_600_000, idleTtlMs: 600_000, touchAfterMs: 60_000 } });
  return { db, owners, manager, setNow: (value: string) => { now = value; }, getNow: () => now };
}
type TestSession = NonNullable<Awaited<ReturnType<SessionManager["create"]>>>;
async function newSession(manager: SessionManager): Promise<TestSession> {
  const session = await manager.create({ username: "admin", password: "owner-password-123" });
  assert.ok(session);
  return session;
}
function post(manager: SessionManager, session: TestSession, csrf = session.csrfToken, origin: string | null = "https://manager.example"): GuardResult {
  return guardManagementRequest(manager, ORIGINS, { method: "POST", cookieHeader: `__Host-lanmm_session=${session.sessionToken}`, originHeader: origin, csrfHeader: csrf });
}
function sha(bytes: Uint8Array, domain: string): string {
  return createHash("sha256").update(domain, "utf8").update(bytes).digest("hex");
}
const tupleKeys = ["domain", "hostId", "jobId", "requestId", "commandSequence", "idempotencyKey", "authorizationRequestDigest", "storedQueueDigest", "terminalState", "terminalRevision", "responseDigest", "responseByteLength", "evidenceKind", "holdClass"] as const;
function makeCandidate(payload = new Uint8Array([80, 65, 89]), response = new Uint8Array([82, 83, 80])): NativeEvidenceCandidateInput {
  const tuple = Object.freeze({
    domain: "lanmm-native-terminal-evidence-v1", hostId: "host-1", jobId: "job-1", requestId: "request-1",
    commandSequence: 1, idempotencyKey: "idem-1", authorizationRequestDigest: "a".repeat(64), storedQueueDigest: "b".repeat(64),
    terminalState: "timed-out" as const, terminalRevision: "history-1", responseDigest: sha(response, "lanmm-native-response-bytes-v1\0"),
    responseByteLength: response.length, evidenceKind: "failed" as const, holdClass: "unknown" as const,
  });
  const tupleDigest = createHash("sha256").update("lanmm-native-terminal-evidence-tuple-digest-v1\0", "utf8")
    .update(JSON.stringify(tupleKeys.map(key => tuple[key])), "utf8").digest("hex");
  return {
    tuple, tupleDigest, payloadBytes: payload, responseBytes: response,
    certificateBindingAssertion: { certificateId: "cert-1", serial: "serial-1", fingerprint: "c".repeat(64), version: 1,
      candidateId: "candidate-1", address: "127.0.0.1", port: 7341, protocolMajor: 1, protocolMinor: 0, notBefore: "2026-09-27T09:00:00.000Z",
      notAfter: "2026-09-27T11:00:00.000Z", caId: "ca-1", caVersion: 1, spiffeUri: "spiffe://lanmm/host-1" },
  };
}
function makeRegistry(manager: SessionManager, prepare: () => unknown, consume: (candidate: unknown) => unknown = () => undefined, id = (() => { let n = 0; return () => `candidate-${++n}`; })(), clock: () => string = () => START) {
  return new OwnerNativeEvidenceCandidateRegistry(manager, { clock, id, prepareCandidate: () => prepare(), consumeCandidate: consume });
}
function dbSnapshot(db: DatabaseSync): string {
  return JSON.stringify({ jobs: db.prepare("SELECT * FROM jobs ORDER BY job_id").all(),
    history: db.prepare("SELECT * FROM job_history ORDER BY history_id").all(),
    commands: db.prepare("SELECT * FROM agent_commands ORDER BY rowid").all() });
}

test("real guarded prepare and redacted inspect consume exactly once without DB mutations", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session);
    assert.equal(guard.ok, true);
    const before = dbSnapshot(db), original = makeCandidate(), sourcePayload = original.payloadBytes, sourceResponse = original.responseBytes;
    let consumed: unknown, calls = 0;
    const registry = makeRegistry(manager, () => original, value => { calls++; consumed = value; });
    const prepared = registry.prepare(guard);
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    assert.equal(registry.size, 1);
    assert.equal(prepared.summary.action, OWNER_NATIVE_EVIDENCE_ACTION);
    assert.equal(prepared.summary.disposition, OWNER_NATIVE_EVIDENCE_DISPOSITION);
    assert.equal(prepared.summary.currentHistoryAndCertificateRevalidated, false);
    assert.equal(JSON.stringify(registry.inspect(guard, prepared.handle)).includes(Buffer.from(sourcePayload).toString()), false);
    assert.equal(JSON.stringify(registry.inspect(guard, prepared.handle)).includes(Buffer.from(sourceResponse).toString()), false);
    sourcePayload.fill(0); sourceResponse.fill(0);
    const result = registry.consume(guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION });
    assert.deepEqual(result, { ok: true, consumed: true });
    assert.equal(calls, 1);
    assert.deepEqual(Array.from((consumed as NativeEvidenceCandidateInput).payloadBytes), [80, 65, 89]);
    assert.deepEqual(Array.from((consumed as NativeEvidenceCandidateInput).responseBytes), [82, 83, 80]);
    assert.equal(registry.size, 0);
    assert.equal(registry.consume(guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }).ok, false);
    assert.equal(calls, 1);
    assert.equal(dbSnapshot(db), before);
  } finally { db.close(); }
});

test("guard denial, forged metadata, and same-owner separate session cannot access candidates", async () => {
  const { db, manager } = await setup();
  try {
    const first = await newSession(manager), second = await newSession(manager), preparedGuard = post(manager, first);
    assert.equal(preparedGuard.ok, true);
    const registry = makeRegistry(manager, makeCandidate);
    const prepared = registry.prepare(preparedGuard);
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const deniedNoCookie = guardManagementRequest(manager, ORIGINS, { method: "POST", cookieHeader: "", originHeader: "https://manager.example", csrfHeader: first.csrfToken });
    const deniedOrigin = post(manager, first, first.csrfToken, "https://evil.example");
    const deniedCsrf = post(manager, first, "wrong-token");
    for (const denied of [deniedNoCookie, deniedOrigin, deniedCsrf]) assert.equal(registry.inspect(denied, prepared.handle).ok, false);
    const other = post(manager, second);
    assert.equal(registry.inspect(other, prepared.handle).ok, false);
    const forged = Object.freeze({ ok: true, session: Object.freeze({ ...preparedGuard.session }) }) as GuardResult;
    assert.equal(registry.inspect(forged, prepared.handle).ok, false);
    assert.equal(registry.consume(other, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }).ok, false);
    assert.equal(registry.size, 1);
  } finally { db.close(); }
});

test("session revoke, credential rotation, absolute/idle expiry, and candidate TTL fail closed", async () => {
  const { db, owners, manager, setNow } = await setup();
  try {
    const first = await newSession(manager), registry = makeRegistry(manager, makeCandidate, () => assert.fail("must not consume"), undefined, () => setNowValue);
    let setNowValue = START;
    const firstGuard = post(manager, first), firstCandidate = registry.prepare(firstGuard);
    assert.equal(firstCandidate.ok, true);
    assert.ok(manager.revoke(first.sessionToken));
    assert.equal(registry.inspect(post(manager, first), firstCandidate.ok ? firstCandidate.handle : "").ok, false);

    const second = await newSession(manager), secondGuard = post(manager, second), secondCandidate = registry.prepare(secondGuard);
    assert.equal(secondCandidate.ok, true);
    const owner = owners.getOwner()!;
    db.prepare("UPDATE owners SET credential_version=credential_version+1 WHERE owner_id=?").run(owner.ownerId);
    assert.equal(registry.inspect(post(manager, second), secondCandidate.ok ? secondCandidate.handle : "").ok, false);

    const third = await newSession(manager), thirdGuard = post(manager, third), thirdCandidate = registry.prepare(thirdGuard);
    assert.equal(thirdCandidate.ok, true);
    setNowValue = "2026-09-27T10:01:00.000Z";
    assert.equal(registry.inspect(thirdGuard, thirdCandidate.ok ? thirdCandidate.handle : "").ok, false);
    assert.equal(registry.size, 0);

    const fourth = await newSession(manager), fourthGuard = post(manager, fourth), fourthCandidate = registry.prepare(fourthGuard);
    assert.equal(fourthCandidate.ok, true);
    const ownerId = owners.getOwner()!.ownerId;
    db.prepare("UPDATE sessions SET idle_expires_at=? WHERE owner_id=? AND revoked_at IS NULL").run("2026-09-27T10:00:30.000Z", ownerId);
    setNow("2026-09-27T10:00:30.000Z");
    assert.equal(registry.inspect(fourthGuard, fourthCandidate.ok ? fourthCandidate.handle : "").ok, false);

    const fifth = await newSession(manager), fifthGuard = post(manager, fifth), fifthCandidate = registry.prepare(fifthGuard);
    assert.equal(fifthCandidate.ok, true);
    db.prepare("UPDATE sessions SET session_version=session_version+1 WHERE owner_id=? AND revoked_at IS NULL").run(ownerId);
    assert.equal(registry.inspect(fifthGuard, fifthCandidate.ok ? fifthCandidate.handle : "").ok, false);
  } finally { db.close(); }
});

test("entry and aggregate retained-byte caps reject without eviction; handle collision fails closed", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session);
    let n = 0;
    const many = makeRegistry(manager, () => makeCandidate(), () => undefined, () => `entry-${++n}`);
    for (let i = 0; i < OWNER_NATIVE_EVIDENCE_MAX_CANDIDATES; i++) assert.equal(many.prepare(guard).ok, true);
    assert.equal(many.size, OWNER_NATIVE_EVIDENCE_MAX_CANDIDATES);
    assert.equal(many.prepare(guard).ok, false);
    assert.equal(many.size, OWNER_NATIVE_EVIDENCE_MAX_CANDIDATES);

    let b = 0;
    const large = new Uint8Array(768 * 1024);
    const aggregate = makeRegistry(manager, () => makeCandidate(large, new Uint8Array([1])), () => undefined, () => `large-${++b}`);
    for (let i = 0; i < 10; i++) assert.equal(aggregate.prepare(guard).ok, true);
    assert.ok(aggregate.retainedByteCount <= OWNER_NATIVE_EVIDENCE_MAX_RETAINED_BYTES);
    assert.equal(aggregate.prepare(guard).ok, false);
    assert.equal(aggregate.size, 10);

    // A constant injected base ID is not a reusable confirmation handle: a
    // monotonically issued suffix gives every candidate a fresh opaque value.
    let now = START;
    const collision = makeRegistry(manager, makeCandidate, () => undefined, () => "same-handle", () => now);
    const first = collision.prepare(guard), second = collision.prepare(guard);
    assert.equal(first.ok, true);
    assert.equal(second.ok, true);
    if (!first.ok || !second.ok) return;
    assert.notEqual(first.handle, second.handle);
    assert.equal(collision.consume(guard, { handle: first.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }).ok, true);

    const expiredId = makeRegistry(manager, makeCandidate, () => undefined, () => "expired-handle", () => now);
    const expiring = expiredId.prepare(guard);
    assert.equal(expiring.ok, true);
    if (!expiring.ok) return;
    now = "2026-09-27T10:01:00.000Z";
    assert.equal(expiredId.inspect(guard, expiring.handle).ok, false);
    const replacement = expiredId.prepare(guard);
    assert.equal(replacement.ok, true);
    if (replacement.ok) {
      assert.notEqual(expiring.handle, replacement.handle);
      assert.equal(expiredId.consume(guard, { handle: expiring.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }).ok, false);
      assert.equal(expiredId.consume(guard, { handle: replacement.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }).ok, true);
    }
    const issuedHandles = new Set([expiring.handle, replacement.ok ? replacement.handle : ""]);
    for (let i = 0; i < OWNER_NATIVE_EVIDENCE_MAX_CANDIDATES + 2; i++) {
      const candidate = expiredId.prepare(guard);
      assert.equal(candidate.ok, true);
      if (candidate.ok) {
        assert.equal(issuedHandles.has(candidate.handle), false);
        issuedHandles.add(candidate.handle);
        assert.equal(expiredId.consume(guard, { handle: candidate.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }).ok, true);
      }
    }
    assert.equal(expiredId.consume(guard, { handle: expiring.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }).ok, false);
  } finally { db.close(); }
});

test("input bytes are copied; byte accessors, proxies, and shared backing are rejected while Buffer is accepted", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session), source = makeCandidate();
    let current: unknown = source;
    const registry = makeRegistry(manager, () => current);
    const prepared = registry.prepare(guard);
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    (source.payloadBytes as Uint8Array).fill(0); (source.responseBytes as Uint8Array).fill(0);
    let delivered: unknown;
    const reader = makeRegistry(manager, makeCandidate, value => { delivered = value; });
    const next = reader.prepare(guard);
    assert.equal(next.ok, true);
    if (!next.ok) return;
    assert.deepEqual(reader.consume(guard, { handle: next.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }), { ok: true, consumed: true });
    assert.deepEqual(Array.from((delivered as NativeEvidenceCandidateInput).payloadBytes), [80, 65, 89]);

    const base = makeCandidate();
    let getterCalls = 0;
    const hostileTuple = { ...base.tuple } as Record<string, unknown>;
    Object.defineProperty(hostileTuple, "hostId", { enumerable: true, get() { getterCalls++; throw new Error("must not execute"); } });
    current = { ...base, tuple: hostileTuple };
    assert.equal(registry.prepare(guard).ok, false);
    const evil = { [Symbol.toPrimitive]() { getterCalls++; throw new Error("must not execute"); } };
    current = { ...base, tuple: { ...base.tuple, authorizationRequestDigest: evil } };
    assert.equal(registry.prepare(guard).ok, false);
    current = { ...base, tupleDigest: evil };
    assert.equal(registry.prepare(guard).ok, false);
    current = { ...base, tuple: { ...base.tuple, terminalState: evil } };
    assert.equal(registry.prepare(guard).ok, false);
    current = { ...base, certificateBindingAssertion: { ...base.certificateBindingAssertion, fingerprint: evil } };
    assert.equal(registry.prepare(guard).ok, false);
    const withThenGetter = { ...base } as Record<string, unknown>;
    Object.defineProperty(withThenGetter, "then", { enumerable: true, get() { getterCalls++; throw new Error("must not execute"); } });
    current = withThenGetter;
    assert.equal(registry.prepare(guard).ok, false);
    const byteAccessor = new Uint8Array([1, 2, 3]);
    Object.defineProperty(byteAccessor, "byteLength", { get() { getterCalls++; throw new Error("must not execute"); } });
    current = makeCandidate(byteAccessor, new Uint8Array([1]));
    assert.equal(registry.prepare(guard).ok, true);
    assert.equal(getterCalls, 0);
    current = new Proxy(makeCandidate(), {});
    assert.equal(registry.prepare(guard).ok, false);
    const byteProxy = new Proxy(new Uint8Array([1, 2, 3]), {});
    current = makeCandidate(byteProxy, new Uint8Array([1]));
    assert.equal(registry.prepare(guard).ok, false);
    const shared = new Uint8Array(new SharedArrayBuffer(3)) as unknown as Uint8Array;
    current = makeCandidate(shared as unknown as Uint8Array<ArrayBuffer>, new Uint8Array([1]));
    assert.equal(registry.prepare(guard).ok, false);
    current = makeCandidate(Buffer.from([80, 65, 89]), Buffer.from([82, 83, 80]));
    assert.equal(registry.prepare(guard).ok, true);
  } finally { db.close(); }
});

test("registry close releases retained bytes and permanently rejects operations", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session), registry = makeRegistry(manager, makeCandidate);
    const candidate = registry.prepare(guard);
    assert.equal(candidate.ok, true);
    assert.ok(registry.retainedByteCount > 0);
    registry.close();
    registry.close();
    assert.equal(registry.size, 0);
    assert.equal(registry.retainedByteCount, 0);
    assert.equal(registry.prepare(guard).ok, false);
    assert.equal(registry.inspect(guard, candidate.ok ? candidate.handle : "").ok, false);
    assert.equal(registry.consume(guard, { handle: candidate.ok ? candidate.handle : "", action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }).ok, false);
  } finally { db.close(); }
});

test("owner disablement revokes otherwise authenticated metadata", async () => {
  const { db, owners, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session), registry = makeRegistry(manager, makeCandidate);
    assert.equal(guard.ok, true);
    if (!guard.ok) return;
    const candidate = registry.prepare(guard);
    assert.equal(candidate.ok, true);
    const owner = owners.getOwner()!;
    db.prepare("UPDATE owners SET disabled=1 WHERE owner_id=?").run(owner.ownerId);
    assert.equal(manager.binding(guard.session), null);
    assert.equal(registry.inspect(guard, candidate.ok ? candidate.handle : "").ok, false);
    assert.equal(registry.consume(guard, { handle: candidate.ok ? candidate.handle : "", action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }).ok, false);
  } finally { db.close(); }
});

test("tuple/digest mismatch, wrong action/disposition, thrown or thenable callback is one-shot", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session);
    const bad = makeCandidate();
    const mismatched = { ...bad, tuple: { ...bad.tuple, hostId: "other" } };
    assert.equal(makeRegistry(manager, () => mismatched).prepare(guard).ok, false);
    let calls = 0;
    const throwing = makeRegistry(manager, makeCandidate, () => { calls++; throw new Error("closed"); });
    const prepared = throwing.prepare(guard);
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    assert.equal(throwing.consume(guard, { handle: prepared.handle, action: "wrong", disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }).ok, false);
    assert.equal(throwing.consume(guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }).ok, false);
    assert.equal(throwing.consume(guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }).ok, false);
    assert.equal(calls, 1);

    let asyncCalls = 0;
    const asyncRegistry = makeRegistry(manager, makeCandidate, (() => { asyncCalls++; return Promise.resolve(); }) as unknown as (candidate: unknown) => undefined);
    const asyncPrepared = asyncRegistry.prepare(guard);
    assert.equal(asyncPrepared.ok, true);
    if (!asyncPrepared.ok) return;
    assert.equal(asyncRegistry.consume(guard, { handle: asyncPrepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }).ok, false);
    assert.equal(asyncRegistry.consume(guard, { handle: asyncPrepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }).ok, false);
    assert.equal(asyncCalls, 1);

    let thenGetterCalls = 0;
    const hostileReturnRegistry = makeRegistry(manager, makeCandidate, (() => {
      thenGetterCalls++;
      return Object.defineProperty({}, "then", { get() { thenGetterCalls++; throw new Error("must not execute"); } });
    }) as unknown as (candidate: unknown) => undefined);
    const hostileReturn = hostileReturnRegistry.prepare(guard);
    assert.equal(hostileReturn.ok, true);
    if (hostileReturn.ok) assert.equal(hostileReturnRegistry.consume(guard, { handle: hostileReturn.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }).ok, false);
    assert.equal(thenGetterCalls, 1);
  } finally { db.close(); }
});

test("generated handles stay lookup-bounded and callback shutdown cannot retain candidates", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session);
    const tooLong = makeRegistry(manager, makeCandidate, () => undefined, () => "x".repeat(128));
    assert.equal(tooLong.prepare(guard).ok, false);
    assert.equal(tooLong.size, 0);
    assert.equal(tooLong.retainedByteCount, 0);
    for (const phase of ["prepare", "id"] as const) {
      let registry: OwnerNativeEvidenceCandidateRegistry;
      registry = makeRegistry(manager, () => { if (phase === "prepare") registry.close(); return makeCandidate(); },
        () => undefined, () => { if (phase === "id") registry.close(); return "handle"; });
      assert.equal(registry.prepare(guard).ok, false, phase);
      assert.equal(registry.size, 0, phase);
      assert.equal(registry.retainedByteCount, 0, phase);
      assert.equal(registry.prepare(guard).ok, false, phase);
    }
  } finally { db.close(); }
});

test("preparation callbacks cannot reenter prepare or retain after clock shutdown", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session);
    let registry: OwnerNativeEvidenceCandidateRegistry;
    let nested: unknown;
    registry = makeRegistry(manager, () => { nested = registry.prepare(guard); return makeCandidate(); });
    assert.equal(registry.prepare(guard).ok, true);
    assert.deepEqual(nested, { ok: false, error: "ERR_NATIVE_EVIDENCE_CANDIDATE" });
    assert.equal(registry.size, 1);
    let calls = 0;
    const closedByClock = new OwnerNativeEvidenceCandidateRegistry(manager, {
      clock: () => { closedByClock.close(); return START; },
      prepareCandidate: () => { calls++; return makeCandidate(); }, consumeCandidate: () => undefined,
    });
    assert.equal(closedByClock.prepare(guard).ok, false);
    assert.equal(calls, 0);
    assert.equal(closedByClock.retainedByteCount, 0);
  } finally { db.close(); }
});

test("lease token is opaque; commit terminally spends candidate and releases bytes", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session), before = dbSnapshot(db);
    const registry = makeRegistry(manager, makeCandidate);
    const p = registry.prepare(guard);
    assert.equal(p.ok, true);
    if (!p.ok) return;
    const req = { handle: p.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION };
    const lease = registry.claim(guard, req);
    assert.equal(lease.ok, true);
    if (!lease.ok) return;
    assert.deepEqual(Reflect.ownKeys(lease.token), []);
    assert.equal(JSON.stringify(lease.token), "{}");
    const bytes = registry.retainedByteCount;
    assert.ok(bytes > 0);
    assert.equal(registry.consume(guard, req).ok, false);
    assert.equal(registry.claim(guard, req).ok, false);
    assert.deepEqual(registry.commitLease(guard, lease.token), { ok: true, committed: true });
    assert.equal(registry.size, 0);
    assert.equal(registry.retainedByteCount, 0);
    assert.equal(registry.inspect(guard, p.handle).ok, false);
    assert.equal(registry.consume(guard, req).ok, false);
    assert.equal(registry.claim(guard, req).ok, false);
    assert.equal(registry.commitLease(guard, lease.token).ok, false);
    assert.equal(registry.releaseLease(guard, lease.token).ok, false);
    assert.equal(dbSnapshot(db), before);
  } finally { db.close(); }
});

test("only exact live lease token can release once; explicit release reopens entry", async () => {
  const { db, manager } = await setup();
  try {
    const first = await newSession(manager), other = await newSession(manager);
    const guard = post(manager, first), otherGuard = post(manager, other), registry = makeRegistry(manager, makeCandidate);
    const p = registry.prepare(guard);
    assert.equal(p.ok, true);
    if (!p.ok) return;
    const req = { handle: p.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION };
    const lease = registry.claim(guard, req);
    assert.equal(lease.ok, true);
    if (!lease.ok) return;
    const forged = Object.freeze(Object.create(null));
    assert.equal(registry.releaseLease(guard, forged).ok, false);
    assert.equal(registry.releaseLease(otherGuard, lease.token).ok, false);
    assert.equal(registry.commitLease(otherGuard, lease.token).ok, false);
    assert.deepEqual(registry.releaseLease(guard, lease.token), { ok: true, released: true });
    assert.equal(registry.releaseLease(guard, lease.token).ok, false);
    assert.equal(registry.claim(guard, req).ok, true);
    assert.equal(registry.consume(guard, req).ok, false);
  } finally { db.close(); }
});

test("lease tokens are instance-local; leased bytes stay charged through explicit release", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session), before = dbSnapshot(db);
    const a = makeRegistry(manager, makeCandidate), b = makeRegistry(manager, makeCandidate);
    const pa = a.prepare(guard), pb = b.prepare(guard);
    assert.equal(pa.ok, true); assert.equal(pb.ok, true);
    if (!pa.ok || !pb.ok) return;
    const ra = { handle: pa.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION };
    const rb = { handle: pb.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION };
    const la = a.claim(guard, ra), lb = b.claim(guard, rb);
    assert.equal(la.ok, true); assert.equal(lb.ok, true);
    if (!la.ok || !lb.ok) return;
    assert.equal(b.commitLease(guard, la.token).ok, false);
    assert.equal(a.commitLease(guard, structuredClone(la.token)).ok, false);
    assert.equal(a.releaseLease(guard, Object.freeze(Object.create(null))).ok, false);
    const bytes = a.retainedByteCount;
    assert.ok(bytes > 0);
    assert.deepEqual(a.releaseLease(guard, la.token), { ok: true, released: true });
    assert.equal(a.retainedByteCount, bytes);
    assert.equal(a.consume(guard, ra).ok, true);
    assert.equal(a.size, 0);
    assert.equal(a.retainedByteCount, 0);
    assert.equal(dbSnapshot(db), before);
  } finally { db.close(); }
});

test("expiry, revoke and close invalidate leases without DB writes or caller-buffer mutation", async () => {
  const { db, manager } = await setup();
  try {
    let now = START;
    const session = await newSession(manager), guard = post(manager, session), source = makeCandidate();
    const registry = makeRegistry(manager, () => source, undefined, undefined, () => now);
    const before = dbSnapshot(db), p = registry.prepare(guard);
    assert.equal(p.ok, true);
    if (!p.ok) return;
    const req = { handle: p.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION };
    const lease = registry.claim(guard, req);
    assert.equal(lease.ok, true);
    if (!lease.ok) return;
    const retained = registry.retainedByteCount;
    source.payloadBytes.fill(0); source.responseBytes.fill(0);
    assert.equal(registry.retainedByteCount, retained);
    now = "2026-09-27T10:01:00.000Z";
    assert.equal(registry.commitLease(guard, lease.token).ok, false);
    assert.equal(registry.releaseLease(guard, lease.token).ok, false);
    assert.equal(registry.size, 0);
    assert.equal(registry.retainedByteCount, 0);
    assert.equal(dbSnapshot(db), before);

    const second = await newSession(manager), guard2 = post(manager, second), registry2 = makeRegistry(manager, makeCandidate), p2 = registry2.prepare(guard2);
    assert.equal(p2.ok, true);
    if (p2.ok) {
      const req2 = { handle: p2.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION };
      const lease2 = registry2.claim(guard2, req2);
      assert.equal(lease2.ok, true);
      registry2.close();
      assert.equal(registry2.size, 0);
      assert.equal(registry2.retainedByteCount, 0);
      assert.equal(registry2.prepare(guard2).ok, false);
      if (lease2.ok) {
        assert.equal(registry2.commitLease(guard2, lease2.token).ok, false);
        assert.equal(registry2.releaseLease(guard2, lease2.token).ok, false);
      }
    }

    const third = await newSession(manager), guard3 = post(manager, third), registry3 = makeRegistry(manager, makeCandidate);
    const p3 = registry3.prepare(guard3);
    assert.equal(p3.ok, true);
    if (p3.ok) {
      const req3 = { handle: p3.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION };
      const lease3 = registry3.claim(guard3, req3);
      assert.equal(lease3.ok, true);
      if (lease3.ok) {
        assert.equal(manager.revoke(third.sessionToken), true);
        assert.equal(registry3.claim(guard3, req3).ok, false);
        assert.equal(registry3.commitLease(guard3, lease3.token).ok, false);
        assert.equal(registry3.releaseLease(guard3, lease3.token).ok, false);
        registry3.close();
      }
    }
  } finally { db.close(); }
});

test("leased candidates count against capacity until release", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session);
    let id = 0;
    const registry = makeRegistry(manager, makeCandidate, undefined, () => `cap-${++id}`);
    const requests: Array<{ handle: string; action: typeof OWNER_NATIVE_EVIDENCE_ACTION; disposition: typeof OWNER_NATIVE_EVIDENCE_DISPOSITION }> = [];
    for (let i = 0; i < OWNER_NATIVE_EVIDENCE_MAX_CANDIDATES; i++) {
      const p = registry.prepare(guard);
      assert.equal(p.ok, true);
      if (p.ok) requests.push({ handle: p.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION });
    }
    assert.equal(registry.size, OWNER_NATIVE_EVIDENCE_MAX_CANDIDATES);
    const lease = registry.claim(guard, requests[0]!);
    assert.equal(lease.ok, true);
    assert.equal(registry.prepare(guard).ok, false);
    if (lease.ok) assert.equal(registry.releaseLease(guard, lease.token).ok, true);
    assert.equal(registry.consume(guard, requests[0]!).ok, true);
    assert.equal(registry.size, OWNER_NATIVE_EVIDENCE_MAX_CANDIDATES - 1);
    assert.equal(registry.prepare(guard).ok, true);
  } finally { db.close(); }
});

test("lease view requires the real active coupled transaction and returns a detached fixed verdict", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session), stores = createJobStores(db, { now: () => START });
    const registry = makeRegistry(manager, makeCandidate);
    const prepared = registry.prepare(guard);
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const request = { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION };
    const lease = registry.claim(guard, request);
    assert.equal(lease.ok, true);
    if (!lease.ok) return;
    let captured: unknown;
    let result: unknown;
    stores.withAuditTransaction(tx => {
      result = registry.withLeaseView(guard, tx, lease.token, view => {
        captured = view;
        assert.deepEqual(Array.from(view.payloadBytes), [80, 65, 89]);
        assert.deepEqual(Array.from(view.responseBytes), [82, 83, 80]);
        assert.equal(view.serverBinding.ownerId, session.metadata.ownerId);
        assert.equal(view.serverBinding.credentialVersion, session.metadata.credentialVersion);
        const binding = manager.binding(session.metadata)!;
        assert.equal(view.serverBinding.sessionId, binding.id);
        assert.equal(view.serverBinding.expiresAt, binding.expiresAt);
        assert.equal(view.candidateExpiresAt, "2026-09-27T10:01:00.000Z");
        assert.ok(Object.isFrozen(view) && Object.isFrozen(view.tuple) && Object.isFrozen(view.certificateBindingAssertion) && Object.isFrozen(view.serverBinding));
        assert.equal(Reflect.set(view.tuple, "hostId", "mutated"), false);
        assert.equal(Reflect.set(view.certificateBindingAssertion, "certificateId", "mutated"), false);
        assert.equal(Reflect.set(view, "candidateExpiresAt", START), false);
        view.payloadBytes.fill(0);
        view.responseBytes.fill(0);
        return "match";
      });
    });
    assert.deepEqual(result, { ok: true, match: true });
    assert.ok(Object.isFrozen(result));
    assert.deepEqual(Object.keys(result as object).sort(), ["match", "ok"]);
    assert.ok(captured && typeof captured === "object");
    const capturedView = captured as object;
    assert.equal("handle" in capturedView, false);
    assert.equal("token" in capturedView, false);
    assert.equal("session" in capturedView, false);
    assert.equal("tx" in capturedView, false);
    assert.equal("db" in capturedView, false);
    const serialized = JSON.stringify(capturedView);
    assert.equal(serialized.includes(prepared.handle), false);
    assert.equal(serialized.includes(session.sessionToken), false);
    assert.equal(serialized.includes(session.csrfToken), false);
    assert.equal(registry.retainedByteCount, 6);
    let mismatch: unknown;
    stores.withAuditTransaction(tx => {
      mismatch = registry.withLeaseView(guard, tx, lease.token, view => {
        assert.deepEqual(Array.from(view.payloadBytes), [80, 65, 89]);
        assert.deepEqual(Array.from(view.responseBytes), [82, 83, 80]);
        return "mismatch";
      });
    });
    assert.deepEqual(mismatch, { ok: true, match: false });
    assert.deepEqual(registry.releaseLease(guard, lease.token), { ok: true, released: true });
    const reclaimed = registry.claim(guard, request);
    assert.equal(reclaimed.ok, true);
    if (reclaimed.ok) assert.deepEqual(registry.commitLease(guard, reclaimed.token), { ok: true, committed: true });
  } finally { db.close(); }
});

test("lease view rejects forged, stale, fake, and foreign transaction authorities before callback", async () => {
  const { db, owners, manager } = await setup();
  const foreignDb = openControllerDatabase(":memory:");
  try {
    const session = await newSession(manager), otherSession = await newSession(manager), guard = post(manager, session), otherGuard = post(manager, otherSession), stores = createJobStores(db), foreignStores = createJobStores(foreignDb);
    const foreignManager = new SessionManager(db, owners, { clock: () => START });
    const foreignManagerGuard = Object.freeze({ ok: true as const, session: foreignManager.authenticate(session.sessionToken)! });
    const registry = makeRegistry(manager, makeCandidate), another = makeRegistry(manager, makeCandidate);
    const p = registry.prepare(guard), q = another.prepare(guard);
    assert.equal(p.ok, true); assert.equal(q.ok, true);
    if (!p.ok || !q.ok) return;
    const req = { handle: p.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION };
    const lease = registry.claim(guard, req), foreignLease = another.claim(guard, { ...req, handle: q.handle });
    assert.equal(lease.ok, true); assert.equal(foreignLease.ok, true);
    if (!lease.ok || !foreignLease.ok) return;
    let stale: unknown;
    stores.withAuditTransaction(tx => { stale = tx; });
    let called = 0, metadataTrapCalls = 0;
    const invoke = (g: unknown, tx: unknown, token: unknown) => registry.withLeaseView(g as GuardResult, tx, token as never, () => { called++; return "match"; });
    assert.equal(invoke(guard, stale, lease.token).ok, false);
    assert.equal(invoke({ ...guard, session: { ...session.metadata } }, stale, lease.token).ok, false);
    assert.equal(invoke(new Proxy(guard, { get() { throw new Error("must not run"); } }), stale, lease.token).ok, false);
    const metadataProxy = new Proxy(session.metadata, {
      get() { metadataTrapCalls++; throw new Error("metadata getter must not run"); },
      ownKeys() { metadataTrapCalls++; throw new Error("metadata reflection must not run"); },
    });
    assert.equal(invoke({ ok: true, session: metadataProxy }, stale, lease.token).ok, false);
    assert.equal(invoke(guard, stale, Object.freeze(Object.create(null))).ok, false);
    assert.equal(invoke(guard, stale, foreignLease.token).ok, false);
    assert.equal(called, 0);
    stores.withAuditTransaction(tx => {
      assert.equal(invoke(guard, { ...tx }, lease.token).ok, false);
      assert.equal(invoke(guard, {}, lease.token).ok, false);
      assert.equal(invoke(otherGuard, tx, lease.token).ok, false);
      assert.equal(invoke(foreignManagerGuard, tx, lease.token).ok, false);
      foreignStores.withAuditTransaction(foreignTx => assert.equal(invoke(guard, foreignTx, lease.token).ok, false));
      assert.equal(invoke(guard, tx, Object.freeze({ ...lease.token })).ok, false);
      assert.equal(invoke(guard, tx, new Proxy(lease.token, {})).ok, false);
      assert.equal(called, 0);
    });
    assert.deepEqual(registry.releaseLease(guard, lease.token), { ok: true, released: true });
    stores.withAuditTransaction(tx => assert.equal(invoke(guard, tx, lease.token).ok, false));
    const spent = registry.claim(guard, req);
    assert.equal(spent.ok, true);
    if (spent.ok) {
      assert.deepEqual(registry.commitLease(guard, spent.token), { ok: true, committed: true });
      stores.withAuditTransaction(tx => assert.equal(invoke(guard, tx, spent.token).ok, false));
    }
    assert.equal(called, 0);
    assert.equal(metadataTrapCalls, 0);
    assert.deepEqual(another.releaseLease(guard, foreignLease.token), { ok: true, released: true });
  } finally { foreignDb.close(); db.close(); }
});

test("lease view rejects reentry while a preparation callback is active", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session), stores = createJobStores(db);
    let registry!: OwnerNativeEvidenceCandidateRegistry;
    let token: Parameters<OwnerNativeEvidenceCandidateRegistry["withLeaseView"]>[2] = Object.freeze(Object.create(null)) as Parameters<OwnerNativeEvidenceCandidateRegistry["withLeaseView"]>[2];
    let tryNestedView = false;
    let nestedView: unknown;
    registry = new OwnerNativeEvidenceCandidateRegistry(manager, {
      clock: () => START,
      prepareCandidate: () => {
        if (tryNestedView) stores.withAuditTransaction(tx => {
          nestedView = registry.withLeaseView(guard, tx, token, () => "match");
        });
        return makeCandidate();
      },
      consumeCandidate: () => undefined,
    });
    const prepared = registry.prepare(guard);
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const request = { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION };
    const lease = registry.claim(guard, request);
    assert.equal(lease.ok, true);
    if (!lease.ok) return;
    token = lease.token;

    tryNestedView = true;
    const next = registry.prepare(guard);
    assert.equal(next.ok, true);
    assert.deepEqual(nestedView, { ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" });
    assert.equal(registry.size, 2);
    assert.deepEqual(registry.releaseLease(guard, lease.token), { ok: true, released: true });
  } finally { db.close(); }
});

test("lease view rejects an already-expired candidate before invoking the callback", async () => {
  const { db, manager } = await setup();
  try {
    let now = START;
    const session = await newSession(manager), guard = post(manager, session), stores = createJobStores(db);
    const registry = makeRegistry(manager, makeCandidate, undefined, undefined, () => now);
    const p = registry.prepare(guard);
    assert.equal(p.ok, true);
    if (!p.ok) return;
    const lease = registry.claim(guard, { handle: p.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION });
    assert.equal(lease.ok, true);
    if (!lease.ok) return;
    now = "2026-09-27T10:01:00.000Z";
    let calls = 0;
    stores.withAuditTransaction(tx => assert.equal(registry.withLeaseView(guard, tx, lease.token, () => { calls++; return "match"; }).ok, false));
    assert.equal(calls, 0);
  } finally { db.close(); }
});

test("lease view rejects hostile callback outcomes without probing them and leaves lease unsettled", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session), stores = createJobStores(db);
    const registry = makeRegistry(manager, makeCandidate), p = registry.prepare(guard);
    assert.equal(p.ok, true);
    if (!p.ok) return;
    const req = { handle: p.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION };
    const lease = registry.claim(guard, req);
    assert.equal(lease.ok, true);
    if (!lease.ok) return;
    let thenGets = 0;
    const hostile = Object.defineProperty({}, "then", { get() { thenGets++; throw new Error("must not execute"); } });
    const outcomes: unknown[] = [
      Promise.resolve("match"), hostile, {}, [], Symbol("verdict"), 1, undefined, "other", "MATCH",
    ];
    for (const outcome of outcomes) stores.withAuditTransaction(tx => {
      assert.equal(registry.withLeaseView(guard, tx, lease.token, (() => outcome) as never).ok, false);
    });
    stores.withAuditTransaction(tx => assert.equal(registry.withLeaseView(guard, tx, lease.token, (() => { throw new Error("expected"); }) as never).ok, false));
    assert.equal(thenGets, 0);
    assert.deepEqual(registry.releaseLease(guard, lease.token), { ok: true, released: true });
  } finally { db.close(); }
});

test("lease view blocks registry reentrancy and detects irreversible close", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session), stores = createJobStores(db);
    let active = false, callbackTx: unknown, registry!: OwnerNativeEvidenceCandidateRegistry, clockAttempts: unknown[] = [];
    const requestFor = (handle: string) => ({ handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION });
    registry = new OwnerNativeEvidenceCandidateRegistry(manager, {
      clock: () => {
        if (active && callbackTx) {
          clockAttempts.push(registry.prepare(guard), registry.inspect(guard, "missing"), registry.consume(guard, requestFor("missing")),
            registry.claim(guard, requestFor("missing")), registry.commitLease(guard, Object.freeze(Object.create(null))),
            registry.releaseLease(guard, Object.freeze(Object.create(null))), registry.withLeaseView(guard, callbackTx, Object.freeze(Object.create(null)) as never, () => "match"));
        }
        return START;
      }, id: () => "reentrant", prepareCandidate: () => makeCandidate(), consumeCandidate: () => undefined,
    });
    const p = registry.prepare(guard);
    assert.equal(p.ok, true);
    if (!p.ok) return;
    const req = requestFor(p.handle), lease = registry.claim(guard, req);
    assert.equal(lease.ok, true);
    if (!lease.ok) return;
    let nested: unknown[] = [];
    stores.withAuditTransaction(tx => {
      callbackTx = tx; active = true;
      const viewed = registry.withLeaseView(guard, tx, lease.token, () => {
        nested = [registry.prepare(guard), registry.inspect(guard, p.handle), registry.consume(guard, req), registry.claim(guard, req),
          registry.withLeaseView(guard, tx, lease.token, () => "match"), registry.commitLease(guard, lease.token), registry.releaseLease(guard, lease.token)];
        return "match";
      });
      assert.deepEqual(viewed, { ok: true, match: true });
      active = false;
    });
    assert.ok(clockAttempts.length >= 7);
    assert.deepEqual(nested.map(value => (value as { ok: boolean }).ok), Array(7).fill(false));
    assert.deepEqual(registry.releaseLease(guard, lease.token), { ok: true, released: true });

    const closedRegistry = makeRegistry(manager, makeCandidate), closedPrepared = closedRegistry.prepare(guard);
    assert.equal(closedPrepared.ok, true);
    if (!closedPrepared.ok) return;
    const closedLease = closedRegistry.claim(guard, requestFor(closedPrepared.handle));
    assert.equal(closedLease.ok, true);
    if (!closedLease.ok) return;
    stores.withAuditTransaction(tx => assert.equal(closedRegistry.withLeaseView(guard, tx, closedLease.token, () => {
      closedRegistry.close(); return "match";
    }).ok, false));
    assert.equal(closedRegistry.size, 0);
    assert.equal(closedRegistry.retainedByteCount, 0);
    assert.equal(closedRegistry.releaseLease(guard, closedLease.token).ok, false);
  } finally { db.close(); }
});

test("lease view clock close after callback overrides an apparent match", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session), stores = createJobStores(db);
    let registry!: OwnerNativeEvidenceCandidateRegistry;
    let closeAtNextClock = false;
    let callbackCalls = 0;
    registry = new OwnerNativeEvidenceCandidateRegistry(manager, {
      clock: () => {
        if (closeAtNextClock) {
          closeAtNextClock = false;
          registry.close();
        }
        return START;
      },
      id: () => "clock-close-candidate",
      prepareCandidate: () => makeCandidate(),
      consumeCandidate: () => undefined,
    });
    const prepared = registry.prepare(guard);
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const lease = registry.claim(guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION });
    assert.equal(lease.ok, true);
    if (!lease.ok) return;

    let result: unknown;
    stores.withAuditTransaction(tx => {
      result = registry.withLeaseView(guard, tx, lease.token, () => {
        callbackCalls++;
        closeAtNextClock = true;
        return "match";
      });
    });
    assert.equal(callbackCalls, 1);
    assert.deepEqual(result, { ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" });
    assert.equal(registry.size, 0);
    assert.equal(registry.retainedByteCount, 0);
    assert.equal(registry.releaseLease(guard, lease.token).ok, false);
    assert.equal(registry.prepare(guard).ok, false);
  } finally { db.close(); }
});

test("lease view rejects a registry-clock close before invoking the callback", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session), stores = createJobStores(db);
    let registry!: OwnerNativeEvidenceCandidateRegistry;
    let closeAtNextClock = false, callbackCalls = 0;
    registry = new OwnerNativeEvidenceCandidateRegistry(manager, {
      clock: () => {
        if (closeAtNextClock) {
          closeAtNextClock = false;
          registry.close();
        }
        return START;
      },
      id: () => "clock-close-before-view",
      prepareCandidate: () => makeCandidate(),
      consumeCandidate: () => undefined,
    });
    const prepared = registry.prepare(guard);
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const lease = registry.claim(guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION });
    assert.equal(lease.ok, true);
    if (!lease.ok) return;
    closeAtNextClock = true;
    let result: unknown;
    stores.withAuditTransaction(tx => {
      result = registry.withLeaseView(guard, tx, lease.token, () => { callbackCalls++; return "match"; });
    });
    assert.equal(callbackCalls, 0);
    assert.deepEqual(result, { ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" });
    assert.equal(registry.size, 0);
    assert.equal(registry.retainedByteCount, 0);
  } finally { db.close(); }
});

test("lease view rejects a transaction invalidated inside the callback", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session), stores = createJobStores(db);
    const registry = makeRegistry(manager, makeCandidate);
    const prepared = registry.prepare(guard);
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const lease = registry.claim(guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION });
    assert.equal(lease.ok, true);
    if (!lease.ok) return;
    let result: unknown;
    assert.throws(() => stores.withAuditTransaction(tx => {
      result = registry.withLeaseView(guard, tx, lease.token, () => {
        db.exec("ROLLBACK");
        return "match";
      });
    }));
    assert.deepEqual(result, { ok: false, error: "ERR_NATIVE_EVIDENCE_LEASE" });
    assert.equal(registry.size, 1);
    assert.deepEqual(registry.releaseLease(guard, lease.token), { ok: true, released: true });
  } finally { db.close(); }
});

test("lease view post-check rejects revoke, rotation, stale/disabled owner, and either expiry", async () => {
  const { db, owners, manager, setNow } = await setup();
  try {
    const stores = createJobStores(db);
    for (const mutation of ["revoke", "rotate", "stale-session", "candidate-expiry", "binding-expiry", "owner-disabled"] as const) {
      let clockNow = START;
      const session = await newSession(manager), guard = post(manager, session);
      const registry = makeRegistry(manager, makeCandidate, undefined, undefined, () => clockNow);
      const p = registry.prepare(guard);
      assert.equal(p.ok, true);
      if (!p.ok) continue;
      const req = { handle: p.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION };
      const lease = registry.claim(guard, req);
      assert.equal(lease.ok, true);
      if (!lease.ok) continue;
      stores.withAuditTransaction(tx => {
        const result = registry.withLeaseView(guard, tx, lease.token, view => {
          if (mutation === "revoke") db.prepare("UPDATE sessions SET revoked_at=? WHERE owner_id=? AND revoked_at IS NULL").run(START, session.metadata.ownerId);
          if (mutation === "rotate") db.prepare("UPDATE owners SET credential_version=credential_version+1 WHERE owner_id=?").run(session.metadata.ownerId);
          if (mutation === "stale-session") db.prepare("UPDATE sessions SET session_version=session_version+1 WHERE owner_id=? AND session_version=?").run(session.metadata.ownerId, session.metadata.sessionVersion);
          if (mutation === "candidate-expiry") clockNow = view.candidateExpiresAt;
          if (mutation === "binding-expiry") setNow(view.serverBinding.expiresAt);
          if (mutation === "owner-disabled") db.prepare("UPDATE owners SET disabled=1 WHERE owner_id=?").run(session.metadata.ownerId);
          return "match";
        });
        assert.equal(result.ok, false, mutation);
      });
      assert.equal(registry.size, 1, mutation);
      if (mutation === "revoke" || mutation === "rotate" || mutation === "stale-session" || mutation === "owner-disabled") continue;
      if (mutation === "binding-expiry") {
        setNow(START);
        assert.equal(clockNow, START);
        assert.ok(registry.inspect(guard, p.handle).ok, "candidate remains unexpired after isolating session-binding expiry");
      }
    }
  } finally { db.close(); }
});

const certificateKeys = ["certificateId", "serial", "fingerprint", "version", "candidateId", "address", "port", "protocolMajor", "protocolMinor", "notBefore", "notAfter", "caId", "caVersion", "spiffeUri"] as const;
const baseCertificate = (): Record<string, unknown> => ({
  certificateId: "cert-1", serial: "serial-1", fingerprint: "c".repeat(64), version: 1, candidateId: "candidate-1",
  address: "127.0.0.1", port: 7341, protocolMajor: 1, protocolMinor: 0, notBefore: "2026-09-27T09:00:00.000Z",
  notAfter: "2026-09-27T11:00:00.000Z", caId: "ca-1", caVersion: 1, spiffeUri: "spiffe://lanmm/host-1" });
function inputWithCertificate(certificate: unknown): NativeEvidenceCandidateInput {
  return { ...makeCandidate(), certificateBindingAssertion: certificate as NativeEvidenceCandidateInput["certificateBindingAssertion"] };
}
function mutateCertificate(base: Record<string, unknown>, patch: Partial<Record<string, unknown>>): NativeEvidenceCandidateInput {
  return inputWithCertificate({ ...base, ...patch });
}
test("prepare captures the complete canonical assertion while preserving summary redaction", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session);
    let delivered: CapturedNativeEvidenceCandidate | undefined;
    const registry = makeRegistry(manager, makeCandidate, candidate => { delivered = candidate as CapturedNativeEvidenceCandidate; });
    const prepared = registry.prepare(guard);
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const summaryCert = prepared.summary.certificateAssertion;
    assert.deepEqual(Object.keys(summaryCert).sort(), ["caId", "caVersion", "candidateId", "certificateId", "fingerprint", "serial", "version"]);
    const request = { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION };
    assert.equal(registry.consume(guard, request).ok, true);
    assert.ok(delivered);
    const cert = delivered.certificateBindingAssertion;
    assert.deepEqual(Object.keys(cert), [...certificateKeys]);
    assert.equal(cert.protocolMajor, 1);
    assert.equal(cert.protocolMinor, 0);
    assert.equal(cert.notBefore, "2026-09-27T09:00:00.000Z");
    assert.equal(cert.notAfter, "2026-09-27T11:00:00.000Z");
    assert.ok(Object.isFrozen(cert));
    assert.ok(!("protocolVersion" in cert));
    const snapshot = JSON.stringify(prepared.summary);
    assert.equal(snapshot.includes("806579"), false);
  } finally { db.close(); }
});
test("certificate capture is detached from source mutation and includes immutable fields in stored integrity", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session), source = baseCertificate();
    let delivered: CapturedNativeEvidenceCandidate | undefined;
    const registry = makeRegistry(manager, () => inputWithCertificate(source), candidate => { delivered = candidate as CapturedNativeEvidenceCandidate; });
    const prepared = registry.prepare(guard);
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    source.protocolMajor = 9; source.protocolMinor = 5; source.notBefore = "2026-09-27T08:00:00.000Z";
    source.notAfter = "2026-09-27T12:00:00.000Z"; source.certificateId = "mutated";
    assert.equal(registry.inspect(guard, prepared.handle).ok, true);
    assert.equal(registry.consume(guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION }).ok, true);
    assert.ok(delivered);
    assert.equal(delivered.certificateBindingAssertion.protocolMajor, 1);
    assert.equal(delivered.certificateBindingAssertion.protocolMinor, 0);
    assert.equal(delivered.certificateBindingAssertion.notBefore, "2026-09-27T09:00:00.000Z");
    assert.equal(delivered.certificateBindingAssertion.notAfter, "2026-09-27T11:00:00.000Z");
    assert.equal(delivered.certificateBindingAssertion.certificateId, "cert-1");
  } finally { db.close(); }
});
test("legacy singular protocolVersion, missing/extra/symbol/accessor/proxy certificate shapes fail closed", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session);
    const attempt = (certificate: unknown) => makeRegistry(manager, () => inputWithCertificate(certificate)).prepare(guard).ok;
    const legacy = baseCertificate(); delete legacy.protocolMajor; delete legacy.protocolMinor; legacy.protocolVersion = 1;
    assert.equal(attempt(legacy), false);
    const missing = baseCertificate(); delete missing.protocolMinor; assert.equal(attempt(missing), false);
    const missingDate = baseCertificate(); delete missingDate.notAfter; assert.equal(attempt(missingDate), false);
    const extra = { ...baseCertificate(), extra: true }; assert.equal(attempt(extra), false);
    const withSymbol = baseCertificate(); (withSymbol as Record<symbol, unknown>)[Symbol("extra")] = 1; assert.equal(attempt(withSymbol), false);
    let invoked = false;
    const withGetter = baseCertificate(); Object.defineProperty(withGetter, "protocolMajor", { enumerable: true, get() { invoked = true; return 1; } });
    assert.equal(attempt(withGetter), false); assert.equal(invoked, false);
    assert.equal(attempt(new Proxy(baseCertificate(), {})), false);
  } finally { db.close(); }
});
test("protocol versions require safe integer major >= 1 and minor >= 0", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session);
    const attempt = (patch: Partial<Record<string, unknown>>) => makeRegistry(manager, () => mutateCertificate(baseCertificate(), patch)).prepare(guard).ok;
    for (const major of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1]) assert.equal(attempt({ protocolMajor: major }), false);
    for (const minor of [-1, 0.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1]) assert.equal(attempt({ protocolMinor: minor }), false);
    for (const caVersion of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) assert.equal(attempt({ caVersion }), false);
    assert.equal(attempt({ protocolMajor: 1, protocolMinor: 0 }), true);
    assert.equal(attempt({ protocolMajor: Number.MAX_SAFE_INTEGER, protocolMinor: Number.MAX_SAFE_INTEGER }), true);
  } finally { db.close(); }
});
test("certificate validity timestamps must be real canonical UTC milliseconds", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session);
    const attempt = (patch: Partial<Record<string, unknown>>) => makeRegistry(manager, () => mutateCertificate(baseCertificate(), patch)).prepare(guard).ok;
    for (const value of ["2026-02-30T00:00:00.000Z", "2026-13-01T00:00:00.000Z", "2026-09-27T25:00:00.000Z", "2026-09-27T09:00:00Z", "2026-09-27T09:00:00+00:00", "not-a-date"]) {
      assert.equal(attempt({ notBefore: value }), false, value);
    }
    assert.equal(attempt({ notBefore: "2026-09-27T09:00:00.001Z" }), true);
  } finally { db.close(); }
});
test("certificate validity interval rejects equal and reversed bounds", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), guard = post(manager, session);
    const attempt = (patch: Partial<Record<string, unknown>>) => makeRegistry(manager, () => mutateCertificate(baseCertificate(), patch)).prepare(guard).ok;
    assert.equal(attempt({ notAfter: "2026-09-27T09:00:00.000Z" }), false);
    assert.equal(attempt({ notAfter: "2026-09-27T08:59:59.999Z" }), false);
    assert.equal(attempt({ notBefore: "2026-09-27T09:00:00.001Z", notAfter: "2026-09-27T09:00:00.002Z" }), true);
  } finally { db.close(); }
});
