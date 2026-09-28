import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { CONTROLLER_MIGRATIONS, migrateControllerDatabase, openControllerDatabase } from "./database.js";
import { JobStoreError, JobStores, createJobStores } from "./jobs-store.js";

const t0 = "2026-09-27T05:00:00.000Z";
const t1 = "2026-09-27T06:00:00.000Z";

function memoryStores(now = () => t0): { stores: JobStores; db: DatabaseSync } {
  const db = openControllerDatabase(":memory:");
  migrateControllerDatabase(db, CONTROLLER_MIGRATIONS);
  return { stores: createJobStores(db, { now }), db };
}

type Op = {
  jobId: string;
  requestId: string;
  action: string;
  hostId: string;
  submittedAt: string;
  manifestRevision: string | null;
  idempotencyKey: string;
  idempotent: boolean;
};
type Sn = {
  operation: Op;
  state: string;
  updatedAt: string;
  progressPercent: number | null;
  attempt: number;
  terminalCode: string | null;
  terminalMessage: string | null;
};

const snapshot = (state: string, opOverrides?: Partial<Op>): Sn => {
  const base: Op = {
    jobId: "job-1",
    requestId: "request-1",
    action: "load",
    hostId: "host-1",
    submittedAt: "2026-09-26T12:00:00.000Z",
    manifestRevision: null,
    idempotencyKey: "idem-1",
    idempotent: true,
  };
  const operation = { ...base, ...opOverrides };
  const progressPercent = state === "running" ? 50 : state === "succeeded" ? 100 : null;
  return {
    operation,
    state,
    updatedAt: "2026-09-26T12:00:01.000Z",
    progressPercent,
    attempt: 1,
    terminalCode: state === "failed" ? "FAILED" : null,
    terminalMessage: state === "failed" ? "nope" : null,
  };
};

function audit(command: Record<string, unknown> = {}) {
  return {
    actorKind: "controller",
    actorId: "controller-1",
    action: "load",
    outcome: "observed",
    requestId: null,
    jobId: null,
    hostId: "host-1",
    details: {},
    occurredAt: "2026-09-26T12:00:02.000Z",
    ...command,
  };
}

test("migration2 registers jobs/job_history/audit_events and migration ledger has version 2", () => {
  const db = openControllerDatabase(":memory:");
  try {
    const n = migrateControllerDatabase(db, CONTROLLER_MIGRATIONS);
    assert.equal(n, CONTROLLER_MIGRATIONS.length);
    const names = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
      .all() as Array<{ name: string }>;
    const set = names.map((r) => r.name).sort();
    assert.deepEqual(set, ["audit_events", "certificate_authorities", "fleet_liveness", "host_certificates", "hosts", "inference_tokens", "job_history", "jobs", "models", "owners", "pairing_challenges", "providers", "schema_migrations", "sessions", "transport_replay_state"]);
    const cols = db.prepare(`PRAGMA table_info(audit_events)`).all() as Array<{ name: string }>;
    for (const col of ["seq", "event_json", "body_json", "outcome", "previous_hash", "hash", "created_at"]) {
      assert.ok(cols.some((c) => c.name === col), `audit_events has column ${col}`);
    }
    assert.equal(CONTROLLER_MIGRATIONS.length, 9);
    assert.equal(CONTROLLER_MIGRATIONS[1]!.name, "durable-jobs-v1");
  } finally {
    db.close();
  }
});

test("a migration1 database upgrades transactionally to migration2", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-upgrade-"));
  try {
    const path = join(dir, "upgrade.sqlite3");
    let db = new DatabaseSync(path);
    migrateControllerDatabase(db, [CONTROLLER_MIGRATIONS[0]!]);
    assert.equal((db.prepare("PRAGMA user_version").get() as { user_version: number }).user_version, 1);
    db.close();
    db = openControllerDatabase(path);
    assert.equal((db.prepare("PRAGMA user_version").get() as { user_version: number }).user_version, CONTROLLER_MIGRATIONS.length);
    assert.ok(db.prepare("SELECT name FROM sqlite_master WHERE name='jobs'").get());
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("create() is idempotent by idempotency key with identical payload", () => {
  const { stores, db } = memoryStores();
  try {
    const snap = snapshot("submitted");
    const a = stores.jobs.create(snap);
    const b = stores.jobs.create(snap);
    assert.deepEqual(a, b);
    assert.notEqual(a, b);
    assert.equal(stores.jobs.list("submitted").length, 1);
    const rec = stores.jobs.get("job-1");
    assert.ok(rec);
    assert.equal(Object.isFrozen(rec), true);
    assert.equal(Object.getPrototypeOf(rec), null);
    assert.equal(Object.isFrozen(rec.payload), true);
  } finally {
    db.close();
  }
});

test("create() fails STABLE on conflicting payload (same key, different operation) without mutating", () => {
  const { stores, db } = memoryStores();
  try {
    stores.jobs.create(snapshot("submitted"));
    const conflict = snapshot("submitted", { idempotencyKey: "idem-1", requestId: "request-2" });
    assert.throws(() => stores.jobs.create(conflict), JobStoreError);
    assert.equal(stores.jobs.list("submitted").length, 1);
    assert.equal(stores.jobs.get("job-1")?.payload.operation.requestId, "request-1");
  } finally {
    db.close();
  }
});

test("transition() enforces core invariants and appends history", () => {
  const { stores, db } = memoryStores();
  try {
    stores.jobs.create(snapshot("submitted"));
    const r = stores.jobs.transition("job-1", "validated", "2026-09-26T12:00:02.000Z");
    assert.ok(r);
    assert.equal(r.state, "validated");
    const hist = stores.jobs.listHistory("job-1");
    assert.equal(hist.length, 1);
    assert.equal(hist[0]!.fromState, "submitted");
    assert.equal(hist[0]!.toState, "validated");
  } finally {
    db.close();
  }
});

test("transition() rejects illegal, terminal, and non-increasing updates", () => {
  const { stores, db } = memoryStores();
  try {
    stores.jobs.create(snapshot("submitted"));
    assert.throws(() => stores.jobs.transition("job-1", "running", "2026-09-26T12:00:02.000Z"), JobStoreError);
    stores.jobs.transition("job-1", "validated", "2026-09-26T12:00:02.000Z");
    assert.throws(() => stores.jobs.transition("job-1", "authorized", "2026-09-26T12:00:02.000Z"), (error: unknown) => error instanceof JobStoreError && error.code === "ERR_JOB_STALE");
    stores.jobs.transition("job-1", "authorized", "2026-09-26T12:00:03.000Z");
    stores.jobs.transition("job-1", "dispatched", "2026-09-26T12:00:04.000Z");
    stores.jobs.transition("job-1", "accepted", "2026-09-26T12:00:05.000Z");
    stores.jobs.transition("job-1", "running", "2026-09-26T12:00:06.000Z");
    stores.jobs.transition("job-1", "succeeded", "2026-09-26T12:00:07.000Z");
    assert.throws(() => stores.jobs.transition("job-1", "failed", "2026-09-26T12:00:08.000Z"), JobStoreError);
  } finally { db.close(); }
});

test("transition() rejects a stale timestamp after another connection advances", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-cas-"));
  try {
    const path = join(dir, "jobs.sqlite3");
    const firstDb = openControllerDatabase(path);
    const secondDb = openControllerDatabase(path);
    const first = createJobStores(firstDb, { now: () => t0 });
    const second = createJobStores(secondDb, { now: () => t0 });
    first.jobs.create(snapshot("submitted"));
    first.jobs.transition("job-1", "validated", "2026-09-26T12:00:02.000Z");
    assert.throws(() => second.jobs.transition("job-1", "authorized", "2026-09-26T12:00:02.000Z"), JobStoreError);
    assert.equal(second.jobs.get("job-1")?.state, "validated");
    firstDb.close(); secondDb.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("retry eligibility survives persistence", () => {
  const { stores, db } = memoryStores();
  try {
    stores.jobs.create(snapshot("submitted"));
    stores.jobs.transition("job-1", "validated", "2026-09-26T12:00:02.000Z");
    stores.jobs.transition("job-1", "failed", "2026-09-26T12:00:03.000Z", { terminalCode: "FAILED", terminalMessage: "failed" });
    const record = stores.jobs.get("job-1");
    assert.ok(record);
    assert.equal(stores.jobs.canRetry(record), true);
  } finally { db.close(); }
});

test("get/list/listByHost/listHistory validate input and wrap DB errors", () => {
  const { stores, db } = memoryStores();
  try {
    assert.throws(() => stores.jobs.get("x' OR 1=1 --"), JobStoreError);
    assert.throws(() => stores.jobs.list("bogus-state"), JobStoreError);
    assert.throws(() => stores.jobs.listByHost(123 as never), JobStoreError);
    // Corrupt a row's payload with valid JSON of the wrong shape.
    stores.jobs.create(snapshot("submitted"));
    db.prepare("UPDATE jobs SET payload_json = '{}' WHERE job_id = 'job-1'").run();
    assert.throws(() => stores.jobs.get("job-1"), JobStoreError);
  } finally {
    db.close();
  }
});

test("create/transition wrap low-level SQLite errors without leaking internals", () => {
  const { stores, db } = memoryStores();
  try {
    stores.jobs.create(snapshot("submitted"));
    assert.throws(() => stores.jobs.create("not-an-object"), JobStoreError);
    // Structurally invalid persisted JSON is surfaced through a stable code.
    db.prepare("UPDATE jobs SET payload_json = '{}' WHERE job_id = 'job-1'").run();
    assert.throws(() => stores.jobs.get("job-1"), JobStoreError);
    // Invalid transition target.
    assert.throws(() => stores.jobs.transition("missing-id", "bogus", t1), JobStoreError);
  } finally {
    db.close();
  }
});

test("append() assigns contiguous sequence + previous hash from tail, verifies chain", () => {
  const { stores, db } = memoryStores();
  try {
    const a = stores.audit.append(audit({ action: "load", outcome: "observed" }));
    const b = stores.audit.append(audit({ action: "drain", outcome: "succeeded" }));
    const c = stores.audit.append(audit({ action: "unload", outcome: "denied" }));
    assert.equal(a.sequence, 1);
    assert.equal(a.previousHash, null);
    assert.equal(b.sequence, 2);
    assert.equal(c.sequence, 3);
    // Chain is contiguous: each event's previousHash equals the prior event's hash.
    assert.equal(b.previousHash, a.hash);
    assert.equal(c.previousHash, b.hash);
    assert.equal(stores.audit.lastSequence(), 3);
    assert.equal(stores.audit.count(), 3);
    const tail = stores.audit.tail();
    assert.ok(tail);
    assert.equal(tail.sequence, 3);
    // Full list verifies integrity on read.
    const list = stores.audit.list();
    assert.equal(list.length, 3);
    assert.deepEqual(list.map((e) => e.sequence), [1, 2, 3]);
    for (const e of list) {
      assert.ok(Object.isFrozen(e));
      assert.equal(Object.getPrototypeOf(e), null);
    }
  } finally {
    db.close();
  }
});

test("append() rejects caller-supplied chain fields and requires strict command keys", () => {
  const { stores, db } = memoryStores();
  try {
    assert.throws(() => stores.audit.append(audit({ sequence: 999, previousHash: "x".repeat(64) })), JobStoreError);
    const missing: Record<string, unknown> = audit(); delete missing.occurredAt;
    assert.throws(() => stores.audit.append(missing), JobStoreError);
    // Unknown extra key.
    assert.throws(() => stores.audit.append(audit({ foo: "bar" } as never)), JobStoreError);
    // No-op attempt field must be rejected (attempt not in allowed command keys).
    assert.throws(() => stores.audit.append(audit({ attempt: 1 } as never)), JobStoreError);
    // Hostile proxy / accessor never invoked.
    let called = 0;
    const hostile: Record<string, unknown> = audit({});
    Object.defineProperty(hostile, "outcome", { get() { called += 1; throw new Error("boom"); } });
    assert.throws(() => stores.audit.append(hostile), JobStoreError);
    assert.equal(called, 0);
  } finally {
    db.close();
  }
});

test("append() blocks tampering, gaps, and reordering (fail closed on chain)", () => {
  const { stores, db } = memoryStores();
  try {
    stores.audit.append(audit({ action: "load" }));
    stores.audit.append(audit({ action: "drain" }));
    // Tamper event 1's hash.
    db.prepare("UPDATE audit_events SET hash = ? WHERE seq = 1").run("a".repeat(64));
    assert.throws(() => stores.audit.verifyChain(), JobStoreError);
    assert.throws(() => stores.audit.list(), JobStoreError);
    assert.throws(() => stores.audit.tail(), JobStoreError);
    assert.throws(() => stores.audit.lastSequence(), JobStoreError);
    assert.throws(() => stores.audit.count(), JobStoreError);
  } finally {
    db.close();
  }
});

test("append() blocks sequence gaps (replaying a lower sequence)", () => {
  const { stores, db } = memoryStores();
  try {
    stores.audit.append(audit({ action: "load" }));
    stores.audit.append(audit({ action: "drain" }));
    const third = stores.audit.append(audit({ action: "unload" }));
    // Insert a bogus event manually with a high sequence that does not chain from #3.
    const body = { ...audit({ action: "load" }), sequence: 999, previousHash: third.hash };
    const created = { ...body, hash: "c".repeat(64) };
    db.prepare("INSERT INTO audit_events (seq, event_json, body_json, outcome, previous_hash, hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run(99, JSON.stringify(created), JSON.stringify(body), created.outcome, created.previousHash, created.hash, t0);
    assert.throws(() => stores.audit.verifyChain(), JobStoreError);
  } finally {
    db.close();
  }
});

test("coupled job mutation + audit append commit together or neither (withAuditTransaction)", () => {
  const { stores, db } = memoryStores();
  try {
    stores.jobs.create(snapshot("submitted"));
    // The callback throws after transitioning the job, so the audit append must roll back too.
    assert.throws(
      () =>
        stores.withAuditTransaction((tx) => {
          tx.jobs.transition("job-1", "validated", "2026-09-26T12:00:02.000Z");
          tx.audit.append(audit({ action: "load" }));
          throw new Error("boom");
        }),
      Error,
    );
    // After rollback: no new state, no new audit events.
    assert.equal(stores.jobs.get("job-1")?.state, "submitted");
    assert.equal(stores.audit.count(), 0);
  } finally {
    db.close();
  }
});

test("failed audit append rolls back the coupled job transition", () => {
  const { stores, db } = memoryStores();
  try {
    stores.jobs.create(snapshot("submitted"));
    assert.throws(() => stores.withAuditTransaction((tx) => {
      tx.jobs.transition("job-1", "validated", "2026-09-26T12:00:02.000Z");
      tx.audit.append({ ...audit(), action: "bad action?" });
    }), JobStoreError);
    assert.equal(stores.jobs.get("job-1")?.state, "submitted");
    assert.equal(stores.jobs.listHistory("job-1").length, 0);
    assert.equal(stores.audit.count(), 0);
  } finally { db.close(); }
});

test("coupled transaction commits both on success", () => {
  const { stores, db } = memoryStores();
  try {
    stores.jobs.create(snapshot("submitted"));
    stores.withAuditTransaction((tx) => {
      tx.jobs.transition("job-1", "validated", "2026-09-26T12:00:02.000Z");
      tx.audit.append(audit({ action: "load", outcome: "observed" }));
    });
    assert.equal(stores.jobs.get("job-1")?.state, "validated");
    assert.equal(stores.audit.count(), 1);
    assert.equal(stores.audit.lastSequence(), 1);
  } finally {
    db.close();
  }
});

test("results are detached, deeply frozen, null-prototype and SQL-looking ids stay inert", () => {
  const { stores, db } = memoryStores();
  try {
    stores.jobs.create(snapshot("submitted"));
    const rec = stores.jobs.get("job-1")!;
    assert.throws(() => {
      (rec as { state: string }).state = "running";
    });
    assert.equal(rec.state, "submitted");
    // SQL-looking id string stays inert (no injection).
    assert.throws(() => stores.jobs.get("1; DROP TABLE jobs;"), JobStoreError);
    assert.throws(() => stores.jobs.get("x' OR 1=1 --"), JobStoreError);
  } finally {
    db.close();
  }
});

test("running, terminal jobs, and transition history survive restart", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-job-restart-"));
  try {
    const path = join(dir, "jobs.sqlite3");
    let db = openControllerDatabase(path);
    let stores = createJobStores(db, { now: () => t0 });
    stores.jobs.create(snapshot("submitted"));
    stores.jobs.transition("job-1", "validated", "2026-09-26T12:00:02.000Z");
    stores.jobs.transition("job-1", "authorized", "2026-09-26T12:00:03.000Z");
    stores.jobs.transition("job-1", "dispatched", "2026-09-26T12:00:04.000Z");
    stores.jobs.transition("job-1", "accepted", "2026-09-26T12:00:05.000Z");
    stores.jobs.transition("job-1", "running", "2026-09-26T12:00:06.000Z");
    stores.jobs.create(snapshot("submitted", { jobId: "job-2", requestId: "request-2", idempotencyKey: "idem-2" }));
    stores.jobs.transition("job-2", "validated", "2026-09-26T12:00:02.000Z");
    stores.jobs.transition("job-2", "failed", "2026-09-26T12:00:03.000Z", { terminalCode: "FAILED", terminalMessage: "failed" });
    db.close();
    db = openControllerDatabase(path);
    stores = createJobStores(db, { now: () => t1 });
    assert.equal(stores.jobs.get("job-1")?.state, "running");
    assert.equal(stores.jobs.get("job-2")?.state, "failed");
    assert.equal(stores.jobs.listHistory("job-1").length, 5);
    assert.equal(stores.jobs.listHistory("job-2").length, 2);
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("audit sequence and integrity continue across restart and tamper blocks reopen", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-audit-restart-"));
  try {
    const path = join(dir, "audit.sqlite3");
    let db = openControllerDatabase(path);
    let stores = createJobStores(db, { now: () => t0 });
    const first = stores.audit.append(audit({ action: "load" }));
    db.close();
    db = openControllerDatabase(path);
    stores = createJobStores(db, { now: () => t1 });
    const second = stores.audit.append({ ...audit({ action: "unload" }), occurredAt: t1 });
    assert.equal(second.sequence, 2);
    assert.equal(second.previousHash, first.hash);
    db.prepare("UPDATE audit_events SET outcome='failed' WHERE seq=1").run();
    db.close();
    db = openControllerDatabase(path);
    assert.throws(() => createJobStores(db), (error: unknown) => error instanceof JobStoreError && error.code === "ERR_AUDIT_INTEGRITY");
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("readOnly store applies migration2 and reads jobs written earlier", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-jobs-"));
  try {
    const path = join(dir, "jobs.sqlite3");
    const db = openControllerDatabase(path);
    migrateControllerDatabase(db, CONTROLLER_MIGRATIONS);
    const stores = createJobStores(db, { now: () => t0 });
    stores.jobs.create(snapshot("submitted"));
    db.close();
    const ro = openControllerDatabase(path, { readOnly: true });
    // Read-only opens require the complete current migration set.
    const uv = (ro.prepare("PRAGMA user_version").get() as { user_version: number }).user_version;
    assert.equal(uv, CONTROLLER_MIGRATIONS.length);
    // A job created via a write connection is readable in the read-only connection.
    const reopened = createJobStores(ro, { now: () => t1 });
    const list = reopened.jobs.list("submitted");
    assert.equal(list.length, 1);
    ro.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
