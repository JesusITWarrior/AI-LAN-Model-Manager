import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { createAllowedOrigins } from "./origin.js";
import { openControllerDatabase } from "./database.js";
import { createOwnerBootstrapService } from "./owner-service.js";
import { SessionManager } from "./session-manager.js";
import { guardManagementRequest, type GuardResult } from "./guard.js";
import type { PasswordCryptoEngine } from "./credentials.js";
import {
  OWNER_NATIVE_EVIDENCE_ACTION, OWNER_NATIVE_EVIDENCE_DISPOSITION,
  OWNER_NATIVE_EVIDENCE_MAX_CANDIDATES, OWNER_NATIVE_EVIDENCE_MAX_RETAINED_BYTES,
  OwnerNativeEvidenceCandidateRegistry, type NativeEvidenceCandidateInput,
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
      candidateId: "candidate-1", address: "127.0.0.1", port: 7341, protocolVersion: 1, caId: "ca-1", caVersion: 1, spiffeUri: "spiffe://lanmm/host-1" },
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
