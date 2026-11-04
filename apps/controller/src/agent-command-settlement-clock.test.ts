import assert from "node:assert/strict";
import test from "node:test";
import { commandAuthorizationDigest, commandPolicyOperation, type CommandOperation, type CommandRequest, type CommandResponse } from "@lan-model-manager/core";
import { AgentCommandStore } from "./agent-command-channel.js";
import { CommandDispatcher } from "./command-dispatch.js";
import { openControllerDatabase } from "./database.js";
import { createJobStores } from "./jobs-store.js";

const at = (ms: number) => new Date(Date.parse("2026-11-04T16:15:43.000Z") + ms).toISOString();
function fixture(operation: CommandOperation = "probe", deferred = false, start = 516) {
  let now = at(start);
  const db = openControllerDatabase(":memory:"), clock = () => now;
  const stores = createJobStores(db, { now: clock });
  const queue = new AgentCommandStore(db, clock, 30_000, stores, deferred);
  const capability = { operation: commandPolicyOperation(operation), targetKind: "host", targetId: "host-1", hostId: "host-1", modelId: null, requestDigest: "", expiresAt: at(60_000) };
  const request: CommandRequest = { requestId: "request-1", jobId: "job-1", hostId: "host-1", operation, idempotencyKey: "idem-1", sequence: 1, deadline: at(30_000), capability, params: { providerId: "ollama-1", model: "qwen:latest" } };
  capability.requestDigest = commandAuthorizationDigest(request);
  assert.ok(new CommandDispatcher(stores, queue, clock).dispatch(request).ok);
  assert.equal(stores.jobs.get(request.jobId)?.updatedAt, at(start + 4));
  assert.ok(queue.poll(request.hostId).command);
  const response = (observedAt = at(502), status: CommandResponse["status"] = "failed"): CommandResponse => ({ requestId: request.requestId, jobId: request.jobId, hostId: request.hostId, sequence: request.sequence, status, progress: status === "succeeded" ? 100 : null, observedAt, observation: null, errorCode: status === "failed" ? "ADAPTER_FAILED" : null });
  const snapshot = () => ({ job: stores.jobs.get(request.jobId), history: stores.jobs.listHistory(request.jobId), audit: stores.audit.list(), queue: db.prepare("SELECT * FROM agent_commands WHERE job_id=?").get(request.jobId) });
  return { db, stores, queue, request, response, snapshot, setNow: (ms: number) => { now = at(ms); } };
}

for (const [label, native] of [["behind", 502], ["equal", 520], ["ahead", 540]] as const) {
  test(`native ${label} clock cannot set authoritative transition time; original result and audit survive`, () => {
    const x = fixture();
    try {
      x.setNow(530);
      const response = x.response(at(native)), original = JSON.stringify(response);
      assert.equal(x.queue.complete("host-1", response)?.duplicate, false);
      assert.equal(x.stores.jobs.get("job-1")?.state, "failed");
      assert.deepEqual(x.stores.jobs.listHistory("job-1").slice(-2).map(h => h.occurredAt), [at(530), at(531)]);
      assert.equal(JSON.stringify(x.queue.result("job-1")), original);
      assert.equal(JSON.stringify(response), original);
      const audit = x.stores.audit.list().at(-1)!;
      assert.equal(audit.actorKind, "agent");
      assert.equal(audit.actorId, "host-1");
      assert.equal(audit.action, "command-result");
      assert.equal(audit.requestId, "request-1");
      assert.equal(audit.jobId, "job-1");
      assert.equal(audit.hostId, "host-1");
      assert.equal(audit.occurredAt, at(native));
      assert.equal(JSON.stringify(audit.details), JSON.stringify({ status: "failed" }));
      const settled = x.snapshot();
      x.setNow(40_000); // Exact ACK replay remains idempotent even after deadline.
      assert.equal(x.queue.complete("host-1", response)?.duplicate, true);
      assert.deepEqual(x.snapshot(), settled);
      assert.equal(x.queue.complete("host-1", { ...response, observedAt: at(native + 1) }), null);
      assert.deepEqual(x.snapshot(), settled);
    } finally { x.db.close(); }
  });
}

test("same-tick fast failure and rolled-back controller clock advance from authoritative updatedAt", () => {
  for (const receipt of [516, 490]) {
    const x = fixture();
    try {
      x.setNow(receipt);
      assert.ok(x.queue.complete("host-1", x.response()));
      assert.deepEqual(x.stores.jobs.listHistory("job-1").slice(-2).map(h => h.occurredAt), [at(521), at(522)]);
    } finally { x.db.close(); }
  }
  const x = fixture("probe", false, 496);
  try { // The .500 acceptance / .502 observation case was already valid.
    x.setNow(503);
    assert.ok(x.queue.complete("host-1", x.response()));
    assert.equal(x.stores.jobs.get("job-1")?.state, "failed");
  } finally { x.db.close(); }
});

test("accepted/running updates and a terminal outcome remain monotonic with identical native timestamps", () => {
  const x = fixture();
  try {
    x.setNow(490);
    for (const status of ["accepted", "running", "accepted", "failed"] as const) {
      assert.ok(x.queue.complete("host-1", x.response(at(502), status)));
      if (status !== "failed") assert.ok(x.queue.poll("host-1").command);
    }
    assert.deepEqual(x.stores.jobs.listHistory("job-1").slice(-2).map(h => h.occurredAt), [at(521), at(522)]);
    assert.equal(x.stores.jobs.get("job-1")?.state, "failed");
  } finally { x.db.close(); }
});

test("audit failure rolls back queue, all authoritative transitions and audit; exact retry succeeds", () => {
  const x = fixture();
  try {
    x.setNow(530);
    const before = x.snapshot();
    x.db.exec("CREATE TEMP TRIGGER fail_command_result BEFORE INSERT ON audit_events WHEN NEW.action='command-result' BEGIN SELECT RAISE(ABORT,'injected'); END");
    assert.throws(() => x.queue.complete("host-1", x.response()), { message: "ERR_AUDIT_DATABASE" });
    assert.deepEqual(x.snapshot(), before);
    x.db.exec("DROP TRIGGER fail_command_result");
    assert.ok(x.queue.complete("host-1", x.response()));
    assert.equal(x.stores.jobs.get("job-1")?.state, "failed");
  } finally { x.db.close(); }
});

test("controller deadline and expired queue reject native outcomes regardless of native time", () => {
  for (const expire of [false, true]) {
    const x = fixture();
    try {
      x.setNow(30_000);
      if (expire) assert.equal(x.queue.poll("host-1").command, null);
      const before = x.snapshot();
      for (const native of [502, 30_001]) assert.equal(x.queue.complete("host-1", x.response(at(native))), null);
      assert.deepEqual(x.snapshot(), before);
      if (expire) assert.equal(x.stores.jobs.get("job-1")?.state, "timed-out");
    } finally { x.db.close(); }
  }
});

test("terminal controller history is never rewritten by a retained native result", () => {
  for (const terminal of ["succeeded", "failed", "timed-out", "cancelled"] as const) {
    const x = fixture();
    try {
      x.stores.jobs.transition("job-1", "running", at(521));
      x.stores.jobs.transition("job-1", terminal, at(522), { progressPercent: terminal === "succeeded" ? 100 : null, terminalCode: terminal === "succeeded" ? null : "TERMINAL", terminalMessage: terminal === "succeeded" ? null : "terminal" });
      const before = x.snapshot();
      x.setNow(530);
      assert.ok(x.queue.complete("host-1", x.response()));
      const after = x.snapshot();
      assert.deepEqual(after.job, before.job);
      assert.deepEqual(after.history, before.history);
      assert.deepEqual(after.audit, before.audit);
      assert.equal(x.queue.result("job-1")?.observedAt, at(502));
    } finally { x.db.close(); }
  }
});

test("response bindings, request digest, queue state and cancellation guards stay fail closed", () => {
  const x = fixture();
  try {
    const before = x.snapshot();
    for (const patch of [{ requestId: "wrong" }, { jobId: "wrong" }, { hostId: "wrong" }, { sequence: 2 }]) {
      assert.equal(x.queue.complete("host-1", { ...x.response(), ...patch }), null);
      assert.deepEqual(x.snapshot(), before);
    }
    assert.equal(x.queue.complete("other-host", x.response()), null);
    x.db.prepare("UPDATE agent_commands SET request_digest=?").run("0".repeat(64));
    const corrupt = x.snapshot();
    assert.equal(x.queue.complete("host-1", x.response()), null);
    assert.deepEqual(x.snapshot(), corrupt);
  } finally { x.db.close(); }
  for (const cancelled of [false, true]) {
    const y = fixture();
    try {
      if (cancelled) assert.ok(y.queue.cancel("job-1"));
      else y.db.exec("UPDATE agent_commands SET state='queued',lease_until=NULL");
      const before = y.snapshot();
      assert.equal(y.queue.complete("host-1", y.response()), null);
      assert.deepEqual(y.snapshot(), before);
      if (cancelled) {
        assert.ok(y.queue.complete("host-1", y.response(at(502), "cancelled")));
        assert.deepEqual(y.stores.jobs.listHistory("job-1"), before.history);
      }
    } finally { y.db.close(); }
  }
});

for (const operation of ["load", "drain", "unload"] as const) for (const native of [502, 520, 540, 30_530]) {
  test(`${operation} lifecycle observation checks preserve native clock ${native} within valid bounds`, () => {
    const x = fixture(operation);
    try {
      x.setNow(530);
      const observation = { action: operation, providerId: "ollama-1", canonicalModelName: "qwen:latest", outcome: "succeeded", runtimeState: operation === "unload" ? "unloaded" : "loaded", activeRequests: 0, observedAt: at(525) };
      const good = { ...x.response(at(native), "succeeded"), observation };
      const before = x.snapshot();
      for (const patch of [{ observedAt: at(516) }, { observedAt: at(515) }, { observedAt: at(30_531) }, { providerId: "wrong" }, { canonicalModelName: "wrong" }, { action: "wrong" }, { outcome: "failed" }, { runtimeState: "unknown" }, ...(operation === "drain" ? [{ activeRequests: 1 }] : [])]) {
        assert.equal(x.queue.complete("host-1", { ...good, observation: { ...observation, ...patch } }), null);
        assert.deepEqual(x.snapshot(), before);
      }
      assert.equal(x.queue.complete("host-1", { ...good, observedAt: at(30_531) }), null);
      assert.deepEqual(x.snapshot(), before);
      assert.ok(x.queue.complete("host-1", good));
      assert.equal(x.stores.jobs.get("job-1")?.state, "succeeded");
      assert.equal(x.queue.result("job-1")?.observedAt, at(native));
      assert.deepEqual(x.stores.jobs.listHistory("job-1").slice(-2).map(h => h.occurredAt), [at(530), at(531)]);
    } finally { x.db.close(); }
  });
}

test("deferred lifecycle success stores immutable native result without settling authoritative job", () => {
  const x = fixture("load", true);
  try {
    x.setNow(530);
    const before = x.snapshot();
    const response = { ...x.response(at(502), "succeeded"), observation: { action: "load", providerId: "ollama-1", canonicalModelName: "qwen:latest", outcome: "succeeded", runtimeState: "loaded", observedAt: at(525) } };
    assert.ok(x.queue.complete("host-1", response));
    assert.deepEqual(x.stores.jobs.get("job-1"), before.job);
    assert.deepEqual(x.stores.jobs.listHistory("job-1"), before.history);
    assert.deepEqual(x.stores.audit.list(), before.audit);
    assert.equal(JSON.stringify(x.queue.result("job-1")), JSON.stringify(response));
  } finally { x.db.close(); }
});
