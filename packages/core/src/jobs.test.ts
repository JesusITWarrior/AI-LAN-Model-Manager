import assert from "node:assert/strict";
import test from "node:test";
import { canRetryJob, parseJobOperation, parseJobSnapshot, transitionJob, type JobState } from "./jobs.js";

const operation = (overrides: Record<string, unknown> = {}) => ({ jobId: "job-1", requestId: "request-1", action: "load", hostId: "host-1", submittedAt: "2026-09-26T12:00:00.000Z", manifestRevision: null, idempotencyKey: "idem-1", idempotent: true, ...overrides });
const snapshot = (state: JobState = "submitted", overrides: Record<string, unknown> = {}) => {
  const terminal = state === "failed" || state === "timed-out" || state === "cancelled";
  const progress = state === "accepted" || state === "running" ? 0 : state === "succeeded" ? 100 : null;
  return { operation: operation(), state, updatedAt: "2026-09-26T12:00:01.000Z", progressPercent: progress, attempt: 1, terminalCode: terminal ? "FAILED" : null, terminalMessage: terminal ? "Job failed" : null, ...overrides };
};

test("strictly parses frozen operations and snapshots", () => {
  const op = parseJobOperation(operation()); assert.equal(op.ok, true); if (op.ok) { assert.equal(Object.getPrototypeOf(op.value), null); assert.equal(Object.isFrozen(op.value), true); }
  const snap = parseJobSnapshot(snapshot()); assert.equal(snap.ok, true); if (snap.ok) { assert.equal(Object.getPrototypeOf(snap.value), null); assert.equal(Object.isFrozen(snap.value), true); }
  for (const value of [operation({ action: "shell" }), operation({ manifestRevision: "bad/rev" }), operation({ idempotencyKey: "bad key" })]) assert.equal(parseJobOperation(value).ok, false);
});

test("enforces snapshot progress, terminal, time, and attempt invariants", () => {
  assert.equal(parseJobSnapshot(snapshot("accepted", { progressPercent: 99 })).ok, true);
  for (const value of [snapshot("submitted", { progressPercent: 0 }), snapshot("running", { progressPercent: 100 }), snapshot("succeeded", { progressPercent: 99 }), snapshot("failed", { progressPercent: 0 }), snapshot("failed", { terminalCode: null }), snapshot("submitted", { terminalCode: "BAD", terminalMessage: "bad" }), snapshot("submitted", { attempt: 0 }), snapshot("submitted", { updatedAt: "2026-09-26T11:59:59.000Z" })]) assert.equal(parseJobSnapshot(value).ok, false);
});

test("allows every declared forward transition and forbids skips or backwards", () => {
  const edges: Array<[JobState, JobState, Record<string, unknown>?]> = [["submitted", "validated"], ["submitted", "cancelled", { terminalCode: "CANCELLED", terminalMessage: "Cancelled" }], ["validated", "authorized"], ["authorized", "dispatched"], ["dispatched", "accepted"], ["accepted", "running"], ["running", "succeeded"], ["running", "failed", { terminalCode: "FAILED", terminalMessage: "Failed" }], ["dispatched", "timed-out", { terminalCode: "TIMEOUT", terminalMessage: "Timed out" }]];
  for (const [from, to, patch] of edges) assert.equal(transitionJob(snapshot(from), to, "2026-09-26T12:00:02.000Z", patch).ok, true);
  assert.equal(transitionJob(snapshot("submitted"), "authorized", "2026-09-26T12:00:02.000Z").ok, false);
  assert.equal(transitionJob(snapshot("running"), "accepted", "2026-09-26T12:00:02.000Z").ok, false);
});

test("terminal states cannot transition and time cannot regress", () => {
  for (const state of ["succeeded", "failed", "timed-out", "cancelled"] as const) assert.equal(transitionJob(snapshot(state), "running", "2026-09-26T12:00:02.000Z").ok, false);
  assert.equal(transitionJob(snapshot(), "validated", "2026-09-26T12:00:00.500Z").ok, false);
});

test("same-state retry requires idempotency, eligible state, and increments attempt", () => {
  for (const state of ["dispatched", "accepted", "running"] as const) {
    const result = transitionJob(snapshot(state, { attempt: 4 }), state, "2026-09-26T12:00:02.000Z");
    assert.equal(result.ok, true); if (result.ok) assert.equal(result.value.attempt, 5);
  }
  assert.equal(transitionJob(snapshot("submitted"), "submitted", "2026-09-26T12:00:02.000Z").ok, false);
  assert.equal(transitionJob(snapshot("running", { operation: operation({ idempotent: false }) }), "running", "2026-09-26T12:00:02.000Z").ok, false);
  assert.equal(transitionJob(snapshot("running", { attempt: 100 }), "running", "2026-09-26T12:00:02.000Z").ok, false);
});

test("new transitions preserve attempt and strict patches satisfy target invariants", () => {
  const result = transitionJob(snapshot("running", { attempt: 7 }), "succeeded", "2026-09-26T12:00:02.000Z"); assert.equal(result.ok, true); if (result.ok) assert.equal(result.value.attempt, 7);
  assert.equal(transitionJob(snapshot("running"), "failed", "2026-09-26T12:00:02.000Z", { terminalCode: "FAILED", terminalMessage: "Failed" }).ok, true);
  assert.equal(transitionJob(snapshot("running"), "failed", "2026-09-26T12:00:02.000Z", { extra: true }).ok, false);
  let invoked = false; const patch = {}; Object.defineProperty(patch, "progressPercent", { get() { invoked = true; throw new Error("no"); } });
  assert.equal(transitionJob(snapshot("dispatched"), "accepted", "2026-09-26T12:00:02.000Z", patch).ok, false); assert.equal(invoked, false);
});

test("retry predicate is limited to idempotent failed or timed-out attempts below 100", () => {
  for (const state of ["failed", "timed-out"] as const) { const parsed = parseJobSnapshot(snapshot(state)); assert.equal(parsed.ok, true); if (parsed.ok) assert.equal(canRetryJob(parsed.value), true); }
  for (const state of ["succeeded", "cancelled", "running"] as const) { const parsed = parseJobSnapshot(snapshot(state)); assert.equal(parsed.ok, true); if (parsed.ok) assert.equal(canRetryJob(parsed.value), false); }
  const maxed = parseJobSnapshot(snapshot("failed", { attempt: 100 })); if (maxed.ok) assert.equal(canRetryJob(maxed.value), false);
});

test("parsers never invoke getters or throw on hostile proxies", () => {
  let invoked = false; const accessor = operation(); Object.defineProperty(accessor, "jobId", { get() { invoked = true; throw new Error("no"); } });
  assert.equal(parseJobOperation(accessor).ok, false); assert.equal(invoked, false);
  const hostile = new Proxy({}, { ownKeys() { throw new Error("hostile"); } }); assert.doesNotThrow(() => parseJobSnapshot(hostile));
  const revoked = Proxy.revocable(snapshot(), {}); revoked.revoke(); assert.doesNotThrow(() => parseJobSnapshot(revoked.proxy));
});
