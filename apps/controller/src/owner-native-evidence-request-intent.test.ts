import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { DatabaseSync, constants as sqliteConstants } from "node:sqlite";
import test from "node:test";
import type { PasswordCryptoEngine } from "./credentials.js";
import { openControllerDatabase } from "./database.js";
import { guardManagementRequest } from "./guard.js";
import {
  OWNER_NATIVE_EVIDENCE_ACTION,
  OWNER_NATIVE_EVIDENCE_DISPOSITION,
  OwnerNativeEvidenceCandidateRegistry,
  type NativeEvidenceCandidateInput,
} from "./owner-native-evidence-candidates.js";
import { OwnerNativeEvidenceRequestIntentValidator } from "./owner-native-evidence-request-intent.js";
import { createAllowedOrigins } from "./origin.js";
import { createOwnerBootstrapService } from "./owner-service.js";
import { SessionManager } from "./session-manager.js";

const START = "2026-09-27T10:00:00.000Z";
const ORIGIN = "https://manager.example";
const ORIGINS = createAllowedOrigins([ORIGIN]);
const ERROR = "ERR_NATIVE_EVIDENCE_REQUEST_INTENT";
const tupleKeys = ["domain", "hostId", "jobId", "requestId", "commandSequence", "idempotencyKey", "authorizationRequestDigest", "storedQueueDigest", "terminalState", "terminalRevision", "responseDigest", "responseByteLength", "evidenceKind", "holdClass"] as const;

const cryptoEngine = (): PasswordCryptoEngine => ({
  random: size => Buffer.alloc(size, 3),
  async derive(password, salt, parameters) {
    const seed = createHash("sha256").update(password).update(salt).digest();
    return Buffer.alloc(parameters.keyLength, seed[0]);
  },
  equal: (a, b) => Buffer.from(a).equals(Buffer.from(b)),
});

async function setup(managerClock: () => string = () => START) {
  const db = openControllerDatabase(":memory:");
  let random = 0;
  const owners = createOwnerBootstrapService(db, { now: () => START, ownerId: () => "a".repeat(32), crypto: cryptoEngine() });
  await owners.bootstrapOwner({ username: "Admin", password: "owner-password-123" });
  const manager = new SessionManager(db, owners, { clock: managerClock, random: size => Buffer.alloc(size, ++random),
    policy: { absoluteTtlMs: 3_600_000, idleTtlMs: 600_000, touchAfterMs: 60_000 } });
  return { db, owners, manager };
}

type TestSession = NonNullable<Awaited<ReturnType<SessionManager["create"]>>>;
async function newSession(manager: SessionManager): Promise<TestSession> {
  const session = await manager.create({ username: "admin", password: "owner-password-123" });
  assert.ok(session);
  return session;
}

function request(session: TestSession, patch: Record<string, unknown> = {}): Record<string, unknown> {
  return { method: "POST", cookieHeader: `__Host-lanmm_session=${session.sessionToken}`,
    originHeader: ORIGIN, csrfHeader: session.csrfToken, ...patch };
}
function body(handle: string, digest: string, patch: Record<string, unknown> = {}): Record<string, unknown> {
  return { candidateHandle: handle, expectedTupleDigest: digest,
    action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION, ...patch };
}
function digest(bytes: Uint8Array, domain: string): string {
  return createHash("sha256").update(domain, "utf8").update(bytes).digest("hex");
}
function candidate(): NativeEvidenceCandidateInput {
  const responseBytes = new Uint8Array([0x52, 0x53, 0x50]);
  const tuple = Object.freeze({
    domain: "lanmm-native-terminal-evidence-v1", hostId: "host-1", jobId: "job-1", requestId: "request-1",
    commandSequence: 1, idempotencyKey: "idem-1", authorizationRequestDigest: "a".repeat(64), storedQueueDigest: "b".repeat(64),
    terminalState: "timed-out" as const, terminalRevision: "history-1",
    responseDigest: digest(responseBytes, "lanmm-native-response-bytes-v1\0"), responseByteLength: responseBytes.length,
    evidenceKind: "failed" as const, holdClass: "unknown" as const,
  });
  const tupleDigest = digest(Buffer.from(JSON.stringify(tupleKeys.map(key => tuple[key])), "utf8"), "lanmm-native-terminal-evidence-tuple-digest-v1\0");
  return {
    tuple, tupleDigest, payloadBytes: new Uint8Array([0x50, 0x41, 0x59]), responseBytes,
    certificateBindingAssertion: { certificateId: "cert-1", serial: "serial-1", fingerprint: "c".repeat(64), version: 1,
      candidateId: "candidate-1", address: "127.0.0.1", port: 7341, protocolMajor: 1, protocolMinor: 0,
      notBefore: "2026-09-27T09:00:00.000Z", notAfter: "2026-09-27T11:00:00.000Z",
      caId: "ca-1", caVersion: 1, spiffeUri: "spiffe://lanmm/host-1" },
  };
}
function makeRegistry(manager: SessionManager, options: { clock?: () => string; prepare?: () => unknown; id?: () => string } = {}) {
  let sequence = 0;
  return new OwnerNativeEvidenceCandidateRegistry(manager, {
    clock: options.clock ?? (() => START),
    id: options.id ?? (() => `intent-candidate-${++sequence}`),
    prepareCandidate: () => options.prepare?.() ?? candidate(),
    consumeCandidate: () => undefined,
  });
}
function authenticatedGuard(manager: SessionManager, session: TestSession) {
  return guardManagementRequest(manager, ORIGINS, request(session));
}
function assertDenied(value: unknown): void {
  assert.deepEqual({ ...(value as Record<string, unknown>) }, { ok: false, error: ERROR });
}
function databaseSnapshot(db: DatabaseSync): string {
  const tables = new Set((db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as Array<{ name: string }>).map(row => row.name));
  const rows: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  const queries: ReadonlyArray<readonly [string, string]> = [
    ["jobs", "SELECT * FROM jobs ORDER BY job_id"],
    ["job_history", "SELECT * FROM job_history ORDER BY history_id"],
    ["agent_commands", "SELECT * FROM agent_commands ORDER BY job_id"],
    ["audit_events", "SELECT * FROM audit_events ORDER BY seq"],
    ["owners", "SELECT * FROM owners ORDER BY owner_id"],
    ["sessions", "SELECT * FROM sessions ORDER BY session_digest"],
    ["transport_replay_state", "SELECT * FROM transport_replay_state ORDER BY certificate_fingerprint"],
    ["supplemental_native_evidence", "SELECT * FROM supplemental_native_evidence ORDER BY tuple_digest"],
  ];
  for (const [table, sql] of queries) rows[table] = tables.has(table) ? db.prepare(sql).all() : null;
  return JSON.stringify(rows);
}

function expectIntent(result: ReturnType<OwnerNativeEvidenceRequestIntentValidator["validate"]>, handle: string, tupleDigest: string) {
  assert.equal(result.ok, true);
  if (!result.ok) return null;
  assert.deepEqual({ ...result.intent }, {
    method: "POST", candidateHandle: handle, expectedTupleDigest: tupleDigest,
    action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION,
    consentCaptured: false, appendAuthorized: false, currentHistoryAndCertificateRevalidated: false,
  });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.intent), true);
  assert.deepEqual(Reflect.ownKeys(result), ["ok", "intent"]);
  assert.deepEqual(Reflect.ownKeys(result.intent), ["method", "candidateHandle", "expectedTupleDigest", "action", "disposition", "consentCaptured", "appendAuthorized", "currentHistoryAndCertificateRevalidated"]);
  return result.intent;
}

test("real guarded POST validates one exact candidate as repeatable redacted non-authority data", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), registry = makeRegistry(manager), guard = authenticatedGuard(manager, session);
    assert.equal(guard.ok, true);
    const prepared = registry.prepare(guard);
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const validator = new OwnerNativeEvidenceRequestIntentValidator(manager, registry, ORIGINS);
    const before = databaseSnapshot(db), size = registry.size, retainedBytes = registry.retainedByteCount;
    const inputRequest = request(session), inputBody = body(prepared.handle, prepared.summary.tupleDigest);
    const first = validator.validate(inputRequest, inputBody), intent = expectIntent(first, prepared.handle, prepared.summary.tupleDigest);
    assert.ok(intent);
    const second = validator.validate(inputRequest, inputBody);
    expectIntent(second, prepared.handle, prepared.summary.tupleDigest);
    const rendered = JSON.stringify(first);
    for (const secret of [session.sessionToken, session.csrfToken, "cert-1", "serial-1", "spiffe://lanmm/host-1", "2026-09-27T09:00:00.000Z", "PAY", "RSP"])
      assert.equal(rendered.includes(secret), false, `output must not expose ${secret}`);
    assert.equal("certificateAssertion" in (intent as unknown as object), false);
    assert.equal("expiresAt" in (intent as unknown as object), false);
    assert.equal("tuple" in (intent as unknown as object), false);
    assert.equal(databaseSnapshot(db), before);
    assert.equal(registry.size, size);
    assert.equal(registry.retainedByteCount, retainedBytes);

    // A real subsequent claim still succeeds, proving validation did not claim/consume a lease.
    const lease = registry.claim(guard, { handle: prepared.handle, action: OWNER_NATIVE_EVIDENCE_ACTION, disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION });
    assert.equal(lease.ok, true);
    if (lease.ok) assert.deepEqual(registry.releaseLease(guard, lease.token), { ok: true, released: true });
    assert.equal(registry.size, size);
    assert.equal(registry.retainedByteCount, retainedBytes);
    assert.equal(databaseSnapshot(db), before);
  } finally { db.close(); }
});

test("non-POST method is rejected before any session SQL, guard clock, or registry clock", async () => {
  let managerClockCalls = 0, registryClockCalls = 0;
  const { db, manager } = await setup(() => { managerClockCalls++; return START; });
  try {
    const session = await newSession(manager), registry = makeRegistry(manager, { clock: () => { registryClockCalls++; return START; } });
    const guard = authenticatedGuard(manager, session), prepared = registry.prepare(guard);
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const validator = new OwnerNativeEvidenceRequestIntentValidator(manager, registry, ORIGINS);
    managerClockCalls = 0; registryClockCalls = 0;
    let ownerSessionReads = 0;
    db.setAuthorizer((action, arg1) => {
      if (action === sqliteConstants.SQLITE_READ && (arg1 === "sessions" || arg1 === "owners")) ownerSessionReads++;
      return sqliteConstants.SQLITE_OK;
    });
    try {
      assertDenied(validator.validate(request(session, { method: "GET" }), body(prepared.handle, prepared.summary.tupleDigest)));
      assertDenied(validator.validate(request(session, { method: "get" }), body(prepared.handle, prepared.summary.tupleDigest)));
      assert.equal(ownerSessionReads, 0);
      assert.equal(managerClockCalls, 0);
      assert.equal(registryClockCalls, 0);
    } finally { db.setAuthorizer(null); }
  } finally { db.close(); }
});

test("real guard rejects cookie, origin, CSRF, and alternate-session requests without revealing candidate state", async () => {
  const { db, manager } = await setup();
  try {
    const first = await newSession(manager), second = await newSession(manager);
    const registry = makeRegistry(manager), prepared = registry.prepare(authenticatedGuard(manager, first));
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const validator = new OwnerNativeEvidenceRequestIntentValidator(manager, registry, ORIGINS);
    const expected = body(prepared.handle, prepared.summary.tupleDigest);
    const invalidRequests = [
      request(first, { cookieHeader: "" }),
      request(first, { originHeader: "https://evil.example" }),
      request(first, { originHeader: null }),
      request(first, { csrfHeader: "wrong-token" }),
      request(first, { csrfHeader: null }),
      request(second),
    ];
    for (const invalid of invalidRequests) assertDenied(validator.validate(invalid, expected));
    assert.equal(registry.size, 1);
    assert.equal(registry.retainedByteCount, 6);
    assert.equal(registry.inspect(authenticatedGuard(manager, first), prepared.handle).ok, true);
  } finally { db.close(); }
});

test("hostile, malformed, or mismatched DTOs fail closed without invoking accessors", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), registry = makeRegistry(manager);
    const prepared = registry.prepare(authenticatedGuard(manager, session));
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const validator = new OwnerNativeEvidenceRequestIntentValidator(manager, registry, ORIGINS);
    const validRequest = request(session), validBody = body(prepared.handle, prepared.summary.tupleDigest);
    let getterCalls = 0;
    const requestGetter = { ...validRequest };
    Object.defineProperty(requestGetter, "csrfHeader", { enumerable: true, get() { getterCalls++; return session.csrfToken; } });
    const bodyGetter = { ...validBody };
    Object.defineProperty(bodyGetter, "action", { enumerable: true, get() { getterCalls++; return OWNER_NATIVE_EVIDENCE_ACTION; } });
    const requestProxy = new Proxy(validRequest, { ownKeys() { throw new Error("must not invoke proxy"); } });
    const bodyProxy = new Proxy(validBody, { getOwnPropertyDescriptor() { throw new Error("must not invoke proxy"); } });
    const inheritedRequest = Object.assign(Object.create({ extra: true }), validRequest);
    const inheritedBody = Object.assign(Object.create({ extra: true }), validBody);
    const invalidPairs: Array<[unknown, unknown]> = [
      [null, validBody], [[], validBody], [requestProxy, validBody], [requestGetter, validBody],
      [{ ...validRequest, extra: true }, validBody], [inheritedRequest, validBody],
      [validRequest, null], [validRequest, []], [validRequest, bodyProxy], [validRequest, bodyGetter],
      [validRequest, { ...validBody, extra: true }], [validRequest, inheritedBody],
      [request(session, { cookieHeader: "x".repeat(4097) }), validBody],
      [request(session, { originHeader: "x".repeat(2049) }), validBody],
      [request(session, { csrfHeader: "x".repeat(129) }), validBody],
      [validRequest, body("", prepared.summary.tupleDigest)],
      [validRequest, body("x".repeat(129), prepared.summary.tupleDigest)],
      [validRequest, body("bad\nhandle", prepared.summary.tupleDigest)],
      [validRequest, body(prepared.handle, "A".repeat(64))],
      [validRequest, body(prepared.handle, "0".repeat(64))],
      [validRequest, body(prepared.handle, prepared.summary.tupleDigest, { action: "other" })],
      [validRequest, body(prepared.handle, prepared.summary.tupleDigest, { disposition: "release-hold" })],
    ];
    for (const [requestInput, bodyInput] of invalidPairs) assertDenied(validator.validate(requestInput, bodyInput));
    assert.equal(getterCalls, 0);
    assert.equal(registry.size, 1);
    assert.equal(registry.retainedByteCount, 6);
    assert.equal(registry.inspect(authenticatedGuard(manager, session), prepared.handle).ok, true);
  } finally { db.close(); }
});

test("session revoke and owner rotation/disablement deny a fresh validation", async () => {
  const { db, owners, manager } = await setup();
  try {
    const session = await newSession(manager), registry = makeRegistry(manager), prepared = registry.prepare(authenticatedGuard(manager, session));
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const validator = new OwnerNativeEvidenceRequestIntentValidator(manager, registry, ORIGINS);
    const inputRequest = request(session), inputBody = body(prepared.handle, prepared.summary.tupleDigest);
    expectIntent(validator.validate(inputRequest, inputBody), prepared.handle, prepared.summary.tupleDigest);
    assert.equal(manager.revoke(session.sessionToken), true);
    assertDenied(validator.validate(inputRequest, inputBody));
    assert.equal(registry.size, 1, "revocation does not consume an unexpired candidate");

    const rotatedSession = await newSession(manager), rotatedRegistry = makeRegistry(manager);
    const rotatedCandidate = rotatedRegistry.prepare(authenticatedGuard(manager, rotatedSession));
    assert.equal(rotatedCandidate.ok, true);
    if (!rotatedCandidate.ok) return;
    const rotatedValidator = new OwnerNativeEvidenceRequestIntentValidator(manager, rotatedRegistry, ORIGINS);
    const owner = owners.getOwner()!;
    db.prepare("UPDATE owners SET credential_version=credential_version+1 WHERE owner_id=?").run(owner.ownerId);
    assertDenied(rotatedValidator.validate(request(rotatedSession), body(rotatedCandidate.handle, rotatedCandidate.summary.tupleDigest)));
    assert.equal(rotatedRegistry.size, 1);

    const disabledSession = await newSession(manager), disabledRegistry = makeRegistry(manager);
    const disabledCandidate = disabledRegistry.prepare(authenticatedGuard(manager, disabledSession));
    assert.equal(disabledCandidate.ok, true);
    if (!disabledCandidate.ok) return;
    const disabledValidator = new OwnerNativeEvidenceRequestIntentValidator(manager, disabledRegistry, ORIGINS);
    db.prepare("UPDATE owners SET disabled=1 WHERE owner_id=?").run(owner.ownerId);
    assertDenied(disabledValidator.validate(request(disabledSession), body(disabledCandidate.handle, disabledCandidate.summary.tupleDigest)));
    assert.equal(disabledRegistry.size, 1);
  } finally { db.close(); }
});

test("final fresh binding catches SQL session rotation during registry inspect without consuming candidate", async () => {
  let now = START, mutateOnInspect = false, didMutate = false;
  const { db, manager } = await setup(() => now);
  try {
    const session = await newSession(manager), ownerId = session.metadata.ownerId;
    const registry = makeRegistry(manager, { clock: () => {
      if (mutateOnInspect && !didMutate) {
        db.prepare("UPDATE sessions SET session_version=session_version+1 WHERE owner_id=? AND revoked_at IS NULL").run(ownerId);
        didMutate = true;
      }
      return now;
    } });
    const prepared = registry.prepare(authenticatedGuard(manager, session));
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const validator = new OwnerNativeEvidenceRequestIntentValidator(manager, registry, ORIGINS);
    const before = databaseSnapshot(db), size = registry.size, retainedBytes = registry.retainedByteCount;
    mutateOnInspect = true;
    assertDenied(validator.validate(request(session), body(prepared.handle, prepared.summary.tupleDigest)));
    assert.equal(didMutate, true);
    assert.equal(registry.size, size);
    assert.equal(registry.retainedByteCount, retainedBytes);
    assert.notEqual(databaseSnapshot(db), before, "only the test's deliberate real SQL session-version change differs");
    db.prepare("UPDATE sessions SET session_version=? WHERE owner_id=? AND revoked_at IS NULL").run(session.metadata.sessionVersion, ownerId);
    mutateOnInspect = false;
    expectIntent(validator.validate(request(session), body(prepared.handle, prepared.summary.tupleDigest)), prepared.handle, prepared.summary.tupleDigest);
    assert.equal(registry.size, size);
    assert.equal(registry.retainedByteCount, retainedBytes);
  } finally { db.close(); }
});

test("thrown clocks fail closed; actual candidate TTL expiry prunes only volatile candidate bytes", async () => {
  let now = START, managerThrows = false, registryThrows = false, registryNow = START;
  const { db, manager } = await setup(() => { if (managerThrows) throw new Error("clock failure"); return now; });
  try {
    const session = await newSession(manager), registry = makeRegistry(manager, { clock: () => {
      if (registryThrows) throw new Error("registry clock failure");
      return registryNow;
    } });
    const prepared = registry.prepare(authenticatedGuard(manager, session));
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const validator = new OwnerNativeEvidenceRequestIntentValidator(manager, registry, ORIGINS);
    const inputRequest = request(session), inputBody = body(prepared.handle, prepared.summary.tupleDigest);
    managerThrows = true;
    assertDenied(validator.validate(inputRequest, inputBody));
    managerThrows = false;
    registryThrows = true;
    assertDenied(validator.validate(inputRequest, inputBody));
    registryThrows = false;
    expectIntent(validator.validate(inputRequest, inputBody), prepared.handle, prepared.summary.tupleDigest);
    assert.equal(registry.size, 1);
    assert.equal(registry.retainedByteCount, 6);

    registryNow = "2026-09-27T10:01:00.000Z";
    assertDenied(validator.validate(inputRequest, inputBody));
    assert.equal(registry.size, 0, "inspect prunes a legitimately expired candidate");
    assert.equal(registry.retainedByteCount, 0, "only volatile candidate bytes are released by TTL pruning");
  } finally { db.close(); }
});

test("idle-session expiry denies before registry inspection and preserves the unexpired candidate", async () => {
  let now = START, registryClockCalls = 0;
  const { db, manager } = await setup(() => now);
  try {
    const session = await newSession(manager);
    const registry = makeRegistry(manager, { clock: () => { registryClockCalls++; return START; } });
    const prepared = registry.prepare(authenticatedGuard(manager, session));
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const validator = new OwnerNativeEvidenceRequestIntentValidator(manager, registry, ORIGINS);
    const inputRequest = request(session), inputBody = body(prepared.handle, prepared.summary.tupleDigest);
    assert.ok(Date.parse(session.metadata.idleExpiresAt) < Date.parse(session.metadata.absoluteExpiresAt));
    const before = databaseSnapshot(db), size = registry.size, retainedBytes = registry.retainedByteCount;
    assert.equal(size, 1);
    assert.equal(retainedBytes, 6);

    registryClockCalls = 0;
    now = session.metadata.idleExpiresAt; // SessionManager rejects at the exact idle-expiry boundary.
    assertDenied(validator.validate(inputRequest, inputBody));
    assert.equal(registryClockCalls, 0, "the real guard rejects before registry inspection");
    assert.equal(registry.size, size);
    assert.equal(registry.retainedByteCount, retainedBytes);
    assert.equal(databaseSnapshot(db), before, "validation does not mutate SQLite on idle expiry");
  } finally { db.close(); }
});

test("absolute-session expiry denies independently of idle expiry and candidate TTL", async () => {
  let now = START, registryClockCalls = 0;
  const { db, manager } = await setup(() => now);
  try {
    const session = await newSession(manager), ownerId = session.metadata.ownerId;
    const registry = makeRegistry(manager, { clock: () => { registryClockCalls++; return START; } });
    const prepared = registry.prepare(authenticatedGuard(manager, session));
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const validator = new OwnerNativeEvidenceRequestIntentValidator(manager, registry, ORIGINS);
    const inputRequest = request(session), inputBody = body(prepared.handle, prepared.summary.tupleDigest);
    const extendedIdleExpiry = new Date(Date.parse(session.metadata.absoluteExpiresAt) + 60_000).toISOString();
    db.prepare("UPDATE sessions SET idle_expires_at=? WHERE owner_id=? AND revoked_at IS NULL").run(extendedIdleExpiry, ownerId);
    assert.ok(Date.parse(extendedIdleExpiry) > Date.parse(session.metadata.absoluteExpiresAt));
    const beforeValidation = databaseSnapshot(db), size = registry.size, retainedBytes = registry.retainedByteCount;
    assert.equal(size, 1);
    assert.equal(retainedBytes, 6);

    registryClockCalls = 0;
    now = session.metadata.absoluteExpiresAt; // Active-session comparison is strict: now < absoluteExpiresAt.
    assertDenied(validator.validate(inputRequest, inputBody));
    assert.equal(registryClockCalls, 0, "the real guard rejects before registry inspection");
    assert.equal(registry.size, size);
    assert.equal(registry.retainedByteCount, retainedBytes);
    assert.equal(databaseSnapshot(db), beforeValidation, "only the explicit idle-expiry SQL update precedes this snapshot");
  } finally { db.close(); }
});

test("malformed manager and registry clock returns fail closed without sticky state", async () => {
  let managerClockCalls = 0, managerClockValue = START;
  let registryClockCalls = 0, registryClockMalformed = false;
  const { db, manager } = await setup(() => { managerClockCalls++; return managerClockValue; });
  try {
    const session = await newSession(manager);
    const registry = makeRegistry(manager, { clock: () => {
      registryClockCalls++;
      return registryClockMalformed ? "2026-99-99T99:99:99.999Z" : START;
    } });
    const prepared = registry.prepare(authenticatedGuard(manager, session));
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const validator = new OwnerNativeEvidenceRequestIntentValidator(manager, registry, ORIGINS);
    const inputRequest = request(session), inputBody = body(prepared.handle, prepared.summary.tupleDigest);
    const before = databaseSnapshot(db), size = registry.size, retainedBytes = registry.retainedByteCount;
    assert.equal(size, 1);
    assert.equal(retainedBytes, 6);

    managerClockCalls = 0;
    registryClockCalls = 0;
    managerClockValue = "2026-99-99T99:99:99.999Z";
    assertDenied(validator.validate(inputRequest, inputBody));
    assert.ok(managerClockCalls > 0);
    assert.equal(registryClockCalls, 0, "malformed SessionManager time is rejected by the guard before registry access");
    assert.equal(registry.size, size);
    assert.equal(registry.retainedByteCount, retainedBytes);
    assert.equal(databaseSnapshot(db), before);

    managerClockValue = START;
    managerClockCalls = 0;
    registryClockCalls = 0;
    registryClockMalformed = true;
    assertDenied(validator.validate(inputRequest, inputBody));
    assert.ok(registryClockCalls > 0, "registry inspection sampled its malformed clock");
    assert.ok(managerClockCalls > 0, "real guard/session binding remains active before registry clock validation");
    assert.equal(registry.size, size, "invalid registry time cannot prune the still-unexpired entry");
    assert.equal(registry.retainedByteCount, retainedBytes);
    assert.equal(databaseSnapshot(db), before);

    registryClockMalformed = false;
    expectIntent(validator.validate(inputRequest, inputBody), prepared.handle, prepared.summary.tupleDigest);
    assert.equal(registry.size, size);
    assert.equal(registry.retainedByteCount, retainedBytes);
    assert.equal(databaseSnapshot(db), before, "restoring valid clocks recovers without sticky guard or registry state");
  } finally { db.close(); }
});

test("allowed-origin configuration is copied and frozen at construction", async () => {
  const { db, manager } = await setup();
  try {
    const session = await newSession(manager), registry = makeRegistry(manager), prepared = registry.prepare(authenticatedGuard(manager, session));
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const origins = [ORIGIN];
    const validator = new OwnerNativeEvidenceRequestIntentValidator(manager, registry, origins);
    origins[0] = "https://evil.example";
    expectIntent(validator.validate(request(session), body(prepared.handle, prepared.summary.tupleDigest)), prepared.handle, prepared.summary.tupleDigest);
    assert.throws(() => new OwnerNativeEvidenceRequestIntentValidator(manager, registry, ["https://evil.example/path"]));
  } finally { db.close(); }
});
