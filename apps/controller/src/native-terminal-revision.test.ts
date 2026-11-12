import assert from "node:assert/strict";
import { test } from "node:test";
import { isProxy } from "node:util/types";
import {
  computeTerminalRevision,
  TERMINAL_REVISION_DOMAIN,
  TERMINAL_STATES,
  type JobHistoryProjection,
  type RequestQueueBinding,
  type TerminalJobProjection,
  type TerminalRevisionInput,
} from "./native-terminal-revision.js";

const SUBMITTED = "2026-11-11T18:00:00.000Z";
const TERMINAL_AT = "2026-11-11T18:10:00.000Z";
const HISTORY_CREATED = "2026-11-11T18:10:00.001Z";

function job(patch: Partial<TerminalJobProjection> = {}): TerminalJobProjection {
  return { jobId: "job-1", requestId: "request-1", state: "failed", hostId: "host-1", submittedAt: SUBMITTED,
    updatedAt: TERMINAL_AT, attempt: 2, idempotencyKey: "idem-1", ...patch };
}
function history(patch: Partial<JobHistoryProjection> = {}): JobHistoryProjection {
  return { historyId: 7, jobId: "job-1", fromState: "running", toState: "failed", attempt: 2,
    occurredAt: TERMINAL_AT, createdAt: HISTORY_CREATED, ...patch };
}
function binding(patch: Partial<RequestQueueBinding> = {}): RequestQueueBinding {
  return { jobId: "job-1", hostId: "host-1", requestId: "request-1", operation: "load", idempotencyKey: "idem-1",
    sequence: 4, deadline: "2026-11-11T18:05:00.000Z", storedQueueDigest: "a".repeat(64),
    authorizationDigest: "b".repeat(64), updatedAt: "2026-11-11T18:11:00.000Z", auditTail: { marker: "audit-secret" }, ...patch };
}
function input(patch: Partial<{ job: TerminalJobProjection; history: JobHistoryProjection; binding: RequestQueueBinding }> = {}): TerminalRevisionInput {
  return { job: job(), history: history(), binding: binding(), ...patch };
}
function revision(value: unknown): string {
  const result = computeTerminalRevision(value);
  assert.equal(result.ok, true);
  if (!result.ok) throw new Error("expected valid terminal revision");
  return result.revision;
}

test("returns a deterministic versioned SHA-256 revision for a valid exact projection", () => {
  const a = revision(input());
  const b = revision(input());
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.equal(TERMINAL_REVISION_DOMAIN, "lanmm/native/terminal-revision/v1");
});

for (const state of TERMINAL_STATES) {
  test(`accepts terminal state ${state}`, () => {
    const value = input({ job: job({ state }), history: history({ toState: state }) });
    assert.match(revision(value), /^[0-9a-f]{64}$/);
  });
}

test("rejects state, latest history ID row, attempt, and timestamp mismatches", () => {
  for (const candidate of [
    input({ history: history({ toState: "succeeded" }) }),
    input({ history: history({ jobId: "other-job" }) }),
    input({ history: history({ attempt: 1 }) }),
    input({ history: history({ occurredAt: SUBMITTED }) }),
    input({ job: job({ updatedAt: SUBMITTED }) }),
  ]) {
    const result = computeTerminalRevision(candidate);
    assert.deepEqual(result, { ok: false, code: "history-mismatch" });
  }
});

test("rejects queue bindings that do not match job/host/request/idempotency", () => {
  for (const candidate of [
    input({ binding: binding({ jobId: "other-job" }) }),
    input({ binding: binding({ hostId: "other-host" }) }),
    input({ binding: binding({ requestId: "other-request" }) }),
    input({ binding: binding({ idempotencyKey: "other-idem" }) }),
    input({ job: job({ requestId: "other-request" }) }),
  ]) {
    assert.deepEqual(computeTerminalRevision(candidate), { ok: false, code: "binding-mismatch" });
  }
});

test("revision changes when immutable history identity/transition or either digest changes", () => {
  const base = input();
  const first = revision(base);
  const changed: TerminalRevisionInput[] = [
    input({ history: history({ historyId: 8 }) }),
    input({ history: history({ fromState: "accepted" }) }),
    input({ history: history({ createdAt: "2026-11-11T18:10:00.002Z" }) }),
    input({ binding: binding({ storedQueueDigest: "c".repeat(64) }) }),
    input({ binding: binding({ authorizationDigest: "d".repeat(64) }) }),
  ];
  for (const value of changed) assert.notEqual(revision(value), first);
});

test("keeps digest fields separate but does not require distinct digest values", () => {
  const same = "e".repeat(64);
  assert.match(revision(input({ binding: binding({ storedQueueDigest: same, authorizationDigest: same }) })), /^[0-9a-f]{64}$/);
});

test("ignores only explicitly non-authoritative queue updatedAt and audit-tail metadata", () => {
  const before = revision(input());
  const after = revision(input({ binding: binding({ updatedAt: "2026-11-11T23:59:59.999Z", auditTail: { arbitrary: [1, "other"] } }) }));
  assert.equal(after, before);
});

test("rejects malformed, impossible, and non-canonical timestamps", () => {
  for (const bad of ["2026-11-11T18:00:00Z", "2026-02-30T18:00:00.000Z", "2026-11-11T18:00:00.000+00:00"]) {
    const result = computeTerminalRevision(input({ job: job({ submittedAt: bad }) }));
    assert.deepEqual(result, { ok: false, code: "invalid-field" });
  }
});

test("rejects unsafe integer attempts/history IDs/sequences and malformed digest fields", () => {
  for (const candidate of [
    input({ job: job({ attempt: 101 }) }),
    input({ history: history({ historyId: Number.MAX_SAFE_INTEGER + 1 }) }),
    input({ binding: binding({ sequence: Number.MAX_SAFE_INTEGER + 1 }) }),
    input({ binding: binding({ storedQueueDigest: "not-a-digest" }) }),
  ]) assert.deepEqual(computeTerminalRevision(candidate), { ok: false, code: "invalid-field" });
});

test("rejects invalid identifiers including control characters", () => {
  for (const value of ["", "bad\u0000id", "has space", "x".repeat(129)]) {
    assert.deepEqual(computeTerminalRevision(input({ job: job({ jobId: value }) })), { ok: false, code: "invalid-field" });
  }
});

test("rejects top-level and nested accessors without invoking them", () => {
  let calls = 0;
  const top = Object.defineProperty({}, "job", { enumerable: true, get() { calls++; return job(); } });
  assert.deepEqual(computeTerminalRevision(top), { ok: false, code: "invalid-input" });
  const hostileJob = Object.defineProperty({ ...job() }, "jobId", { enumerable: true, get() { calls++; return "secret-canary"; } });
  assert.deepEqual(computeTerminalRevision({ job: hostileJob, history: history(), binding: binding() }), { ok: false, code: "invalid-input" });
  assert.equal(calls, 0);
});

test("rejects proxies before invoking traps", () => {
  if (typeof isProxy !== "function") return;
  let calls = 0;
  const hostile = new Proxy({}, { ownKeys() { calls++; throw new Error("trap-canary"); } });
  assert.deepEqual(computeTerminalRevision(hostile), { ok: false, code: "invalid-input" });
  const nested = new Proxy(job(), { get() { calls++; throw new Error("get-canary"); } });
  assert.deepEqual(computeTerminalRevision({ job: nested, history: history(), binding: binding() }), { ok: false, code: "invalid-input" });
  assert.equal(calls, 0);
});

test("fixed failures and success output never include untrusted canaries", () => {
  const hostile = Object.defineProperty({ ...job() }, "jobId", { enumerable: true, get() { throw new Error("secret-canary"); } });
  const result = computeTerminalRevision({ job: hostile, history: history(), binding: binding() });
  assert.doesNotMatch(JSON.stringify(result), /secret-canary|audit-secret|request-1/);
  const success = computeTerminalRevision(input());
  assert.doesNotMatch(JSON.stringify(success), /audit-secret|cert|session|secret/);
});
