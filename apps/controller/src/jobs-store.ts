import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import {
  canRetryJob,
  createAuditEvent,
  parseAuditEventBody,
  parseJobSnapshot,
  parseProtocolId,
  parseProtocolMessageType,
  parseJsonValue,
  parseUtcTimestamp,
  transitionJob,
  verifyAuditChain,
  type AuditEvent,
  type AuditEventBody,
  type AuditActorKind,
  type AuditOutcome,
  type HostId,
  type JobId,
  type JobState,
  type JobSnapshot,
  type JsonValue,
  type ParseResult,
  type RequestId,
  type UtcTimestamp,
} from "@lan-model-manager/core";
import { PersistenceError } from "./database.js";
import { RepositoryError } from "./repositories.js";

/**
 * Durable job + audit persistence for the controller.
 *
 * Boundary contract (matching the rest of the controller):
 *   - Every public function is strict: identifiers/enums/timestamps are
 *     validated, limits are bounded, results are detached, deeply frozen,
 *     null-prototype.
 *   - Low-level SQLite failures are wrapped into stable error codes; no SQLite
 *     internals or untrusted values leak in an error message.
 *   - Job mutation + audit append are coupled through a single `BEGIN IMMEDIATE`
 *     transaction so they commit together or neither.
 *
 * Transaction ownership: at most one `BEGIN IMMEDIATE` per connection is active
 * at a time. {@link runTransaction} tracks the in-progress flag on the
 * connection via a module-scoped `WeakMap`; nested repository operations
 * invoked while a coupled transaction is open skip re-begunning so the whole
 * operation shares a single atomic unit.
 */

// ---------------------------------------------------------------------------
// Stable error codes

export type JobStoreErrorCode =
  | "ERR_JOB_CREATE_INPUT"
  | "ERR_JOB_TRANSITION_INPUT"
  | "ERR_JOB_NOT_FOUND"
  | "ERR_JOB_CONFLICT"
  | "ERR_JOB_STALE"
  | "ERR_JOB_STATE"
  | "ERR_JOB_INPUT"
  | "ERR_JOB_DATABASE"
  | "ERR_JOB_HISTORY_STATE"
  | "ERR_AUDIT_APPEND_INPUT"
  | "ERR_AUDIT_INTEGRITY"
  | "ERR_AUDIT_STALE"
  | "ERR_AUDIT_DATABASE";

// JobStoreError has its own stable error-code namespace, so it extends Error
// directly rather than the shared RepositoryError base (whose `code` union does
// not cover the job/audit codes).
export class JobStoreError extends Error {
  readonly code: JobStoreErrorCode;
  readonly detail: readonly string[];
  constructor(code: JobStoreErrorCode, detail: readonly string[] = []) {
    super(code);
    this.name = "JobStoreError";
    this.code = code;
    this.detail = Object.freeze([...detail]);
  }
}

// ---------------------------------------------------------------------------
// Records

export interface JobRecord {
  readonly jobId: JobId;
  readonly state: JobState;
  readonly hostId: HostId;
  readonly submittedAt: UtcTimestamp;
  readonly updatedAt: UtcTimestamp;
  readonly attempt: number;
  readonly idempotencyKey: string;
  readonly payload: JobSnapshot;
}

export interface HistoryRecord {
  readonly jobId: JobId;
  readonly fromState: JobState;
  readonly toState: JobState;
  readonly attempt: number;
  readonly occurredAt: UtcTimestamp;
}

export interface AuditRecord {
  readonly sequence: number;
  readonly occurredAt: UtcTimestamp;
  readonly actorKind: AuditActorKind;
  readonly actorId: string;
  readonly action: string;
  readonly outcome: AuditOutcome;
  readonly requestId: RequestId | null;
  readonly jobId: JobId | null;
  readonly hostId: HostId | null;
  readonly details: JsonValue;
  readonly previousHash: string | null;
  readonly hash: string;
  readonly createdAt: UtcTimestamp;
}

export interface JobStores {
  readonly jobs: JobRepository;
  readonly audit: AuditRepository;
  /** Run `mutate` inside a single coupled `BEGIN IMMEDIATE` transaction so a
   *  job mutation and an audit append commit together or neither. A failed
   *  audit cannot leave a partial job mutation behind. */
  withAuditTransaction(mutate: (tx: CoupledContext) => void): void;
}

export interface CoupledContext {
  readonly jobs: JobRepository;
  readonly audit: AuditRepository;
}

// ---------------------------------------------------------------------------
// Low-level helpers (non-throwing on bad input; they throw RepositoryError)

function query<T>(fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    if (e instanceof RepositoryError || e instanceof PersistenceError) throw e;
    if (e instanceof JobStoreError) throw e;
    throw new JobStoreError("ERR_JOB_DATABASE");
  }
}

function dbFail(): never {
  throw new JobStoreError("ERR_JOB_DATABASE");
}

function frozen<T>(o: Record<string, unknown>): T {
  return Object.freeze(Object.assign(Object.create(null), o)) as T;
}

const JOB_STATES: readonly JobState[] = Object.freeze([
  "submitted", "validated", "authorized", "dispatched", "accepted",
  "running", "succeeded", "failed", "timed-out", "cancelled",
]);
function assertJobState(v: unknown): asserts v is JobState {
  if (typeof v === "string" && JOB_STATES.includes(v as JobState)) return;
  throw new JobStoreError("ERR_JOB_STATE");
}

// Command keys a caller may supply to {@link AuditRepository.append}.
// `sequence` and `previousHash` are intentionally NOT allowed here: they are
// assigned from the chain tail during storage (see {@link AuditRepository.append}).
const ALLOWED_COMMAND_KEYS: readonly string[] = Object.freeze([
  "actorKind", "actorId", "action", "outcome",
  "requestId", "jobId", "hostId", "details", "occurredAt",
]);

// ---------------------------------------------------------------------------
// Transaction helper (single BEGIN IMMEDIATE per connection)

// Per-connection coupling gate. `couplingState` tracks, per DatabaseSync
// connection, whether a coupled `BEGIN IMMEDIATE` is in progress so nested
// repository operations invoked by a coupled transaction share a single atomic
// unit (one BEGIN/COMMIT) rather than nesting BEGIN IMMEDIATEs.
const couplingState = new WeakMap<DatabaseSync, boolean>();

export function runTransaction<T>(db: DatabaseSync, fn: () => T): T {
  if (couplingState.get(db) ?? false) return fn();
  couplingState.set(db, true);
  try {
    db.exec("BEGIN IMMEDIATE");
    const result = fn();
    db.exec("COMMIT");
    return result;
  } catch (e) {
    try {
      db.exec("ROLLBACK");
    } catch {
      /* already rolled back */
    }
    throw e;
  } finally {
    couplingState.set(db, false);
  }
}

// ---------------------------------------------------------------------------
// Canonicalization of a normalized JobSnapshot (fixed key order)

function normalizeSnapshot(snap: JobSnapshot): string {
  const op = snap.operation;
  const obj: Record<string, unknown> = {
    operation: {
      jobId: op.jobId,
      requestId: op.requestId,
      action: op.action,
      hostId: op.hostId,
      submittedAt: op.submittedAt,
      manifestRevision: op.manifestRevision,
      idempotencyKey: op.idempotencyKey,
      idempotent: op.idempotent,
    },
    state: snap.state,
    updatedAt: snap.updatedAt,
    progressPercent: snap.progressPercent,
    attempt: snap.attempt,
    terminalCode: snap.terminalCode,
    terminalMessage: snap.terminalMessage,
  };
  return JSON.stringify(obj);
}

function operationsEqual(a: JobSnapshot, b: JobSnapshot): boolean {
  return JSON.stringify(a.operation) === JSON.stringify(b.operation);
}

// ---------------------------------------------------------------------------
// SQLite row shapes (loosely typed; always decoded through strict parsers)

type JobRow = {
  job_id: string;
  state: string;
  host_id: string;
  submitted_at: string;
  updated_at: string;
  attempt: number | bigint;
  idempotency_key: string;
  payload_json: string;
  created_at: string;
};

type HistoryRow = {
  job_id: string;
  from_state: string;
  to_state: string;
  attempt: number | bigint;
  occurred_at: string;
  created_at: string;
};

type StoredRow = {
  seq: number | bigint;
  event_json: string;
  body_json: string;
  outcome: string;
  previous_hash: string | null;
  hash: string;
  created_at: string;
};

// ---------------------------------------------------------------------------
// JobRepository

function readJobRows(db: DatabaseSync, sql: string, params: readonly SQLInputValue[]): JobRow[] {
  return query<JobRow[]>(() => db.prepare(sql).all(...params) as unknown as JobRow[]);
}

function decodeJobRow(row: JobRow): JobRecord {
  const jobIdParsed = parseProtocolId("job", row.job_id);
  if (!jobIdParsed.ok) throw new JobStoreError("ERR_JOB_INPUT");
  const state: JobState = row.state as JobState;
  assertJobState(state);
  const hostParsed = parseProtocolId("host", row.host_id);
  if (!hostParsed.ok) throw new JobStoreError("ERR_JOB_INPUT");
  const submittedParsed = parseUtcTimestamp(row.submitted_at);
  if (!submittedParsed.ok) throw new JobStoreError("ERR_JOB_INPUT");
  const updatedParsed = parseUtcTimestamp(row.updated_at);
  if (!updatedParsed.ok) throw new JobStoreError("ERR_JOB_INPUT");
  const attempt = Number(row.attempt);
  if (!Number.isInteger(attempt) || attempt < 1 || attempt > 100) throw new JobStoreError("ERR_JOB_INPUT");
  const payloadJson = row.payload_json;
  if (typeof payloadJson !== "string") throw new JobStoreError("ERR_JOB_INPUT");
  let payload: JobSnapshot;
  try {
    payload = JSON.parse(payloadJson);
  } catch {
    throw new JobStoreError("ERR_JOB_INPUT");
  }
  const parsedPayload = parseJobSnapshot(payload);
  if (!parsedPayload.ok || parsedPayload.value.operation.jobId !== jobIdParsed.value ||
      parsedPayload.value.operation.hostId !== hostParsed.value || parsedPayload.value.operation.submittedAt !== submittedParsed.value ||
      parsedPayload.value.state !== state || parsedPayload.value.updatedAt !== updatedParsed.value ||
      parsedPayload.value.attempt !== attempt || parsedPayload.value.operation.idempotencyKey !== row.idempotency_key) {
    throw new JobStoreError("ERR_JOB_INPUT");
  }
  return frozen<JobRecord>({
    jobId: jobIdParsed.value,
    state,
    hostId: hostParsed.value,
    submittedAt: submittedParsed.value,
    updatedAt: updatedParsed.value,
    attempt,
    idempotencyKey: row.idempotency_key,
    payload: parsedPayload.value,
  });
}

function decodeHistoryRow(row: HistoryRow): HistoryRecord {
  const jobIdParsed = parseProtocolId("job", row.job_id);
  if (!jobIdParsed.ok) throw new JobStoreError("ERR_JOB_INPUT");
  const from: JobState = row.from_state as JobState;
  const to: JobState = row.to_state as JobState;
  assertJobState(from);
  assertJobState(to);
  const attempt = Number(row.attempt);
  if (!Number.isInteger(attempt) || attempt < 1 || attempt > 100) throw new JobStoreError("ERR_JOB_INPUT");
  const occurredParsed = parseUtcTimestamp(row.occurred_at);
  if (!occurredParsed.ok) throw new JobStoreError("ERR_JOB_INPUT");
  return frozen<HistoryRecord>({
    jobId: jobIdParsed.value,
    fromState: from,
    toState: to,
    attempt,
    occurredAt: occurredParsed.value,
  });
}

export class JobRepository {
  constructor(
    protected readonly db: DatabaseSync,
    protected readonly now: () => string = () => new Date().toISOString(),
  ) {}

  /** Idempotently create a submitted job. Same idempotency key + identical
   *  operation returns the existing snapshot; a conflicting payload fails
   *  stably without mutating the store. */
  create(input: unknown): JobSnapshot {
    const parsed = parseJobSnapshot(input);
    if (!parsed.ok) throw new JobStoreError("ERR_JOB_CREATE_INPUT");
    const snap = parsed.value;
    if (snap.state !== "submitted") throw new JobStoreError("ERR_JOB_CREATE_INPUT");
    return runTransaction(this.db, () => {
      const row = query<JobRow | undefined>(() =>
        this.db
          .prepare(
            "SELECT job_id, state, host_id, submitted_at, updated_at, attempt, idempotency_key, payload_json FROM jobs WHERE idempotency_key = ?",
          )
          .get(snap.operation.idempotencyKey) as JobRow | undefined,
      );
      if (row) {
        const existing = decodeJobRow(row);
        if (operationsEqual(existing.payload, snap)) return existing.payload;
        // Same key, different operation => stable conflict, no mutation.
        throw new JobStoreError("ERR_JOB_CONFLICT");
      }
      const jobIdParsed = parseProtocolId("job", snap.operation.jobId);
      if (!jobIdParsed.ok) throw new JobStoreError("ERR_JOB_CREATE_INPUT");
      const now = this.now();
      const result = query<JobRow | undefined>(() =>
        this.db
          .prepare(
            "INSERT INTO jobs (job_id, state, host_id, submitted_at, updated_at, attempt, idempotency_key, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
          )
          .run(
            jobIdParsed.value,
            snap.state,
            snap.operation.hostId,
            snap.operation.submittedAt,
            snap.updatedAt,
            snap.attempt,
            snap.operation.idempotencyKey,
            normalizeSnapshot(snap),
            now,
          ) as unknown as JobRow,
      );
      if (!result) dbFail();
      return snap;
    });
  }

  /** Transactional, CAS-guarded job transition using core invariants. */
  transition(
    jobId: unknown,
    targetInput: unknown,
    updatedInput: unknown,
    patchInput?: unknown,
  ): JobSnapshot {
    const jobIdParsed = parseProtocolId("job", jobId);
    if (!jobIdParsed.ok) throw new JobStoreError("ERR_JOB_TRANSITION_INPUT");
    return runTransaction(this.db, () => {
      const row = query<JobRow | undefined>(() =>
        this.db
          .prepare(
            "SELECT job_id, state, host_id, submitted_at, updated_at, attempt, idempotency_key, payload_json FROM jobs WHERE job_id = ?",
          )
          .get(jobIdParsed.value) as JobRow | undefined,
      );
      if (!row) throw new JobStoreError("ERR_JOB_NOT_FOUND");
      const before = decodeJobRow(row);

      // Enforce legal edge / time / progress / terminal invariants via core.
      const updated = parseUtcTimestamp(updatedInput);
      if (!updated.ok) throw new JobStoreError("ERR_JOB_TRANSITION_INPUT");
      if (updated.value <= before.updatedAt) throw new JobStoreError("ERR_JOB_STALE");
      const transitioned = transitionJob(before.payload, targetInput, updated.value, patchInput);
      if (!transitioned.ok) throw new JobStoreError("ERR_JOB_STATE");
      const after = transitioned.value;

      // CAS on (state, updated_at) to reject a stale writer. node:sqlite's
      // .run() returns {changes,lastInsertRowid}; .changes === 0 means the row's
      // current (state,updated_at) no longer matches `before`, i.e. a concurrent
      // writer already advanced it => fail STALE (one writer wins).
      const cas = query<{changes:number}>(() =>
        this.db
          .prepare(
            "UPDATE jobs SET state = ?, updated_at = ?, attempt = ?, payload_json = ? WHERE job_id = ? AND state = ? AND updated_at = ?",
          )
          .run(
            after.state,
            after.updatedAt,
            after.attempt,
            normalizeSnapshot(after),
            jobIdParsed.value,
            row.state,
            row.updated_at,
          ) as unknown as {changes:number},
      );
      if (cas.changes === 0) throw new JobStoreError("ERR_JOB_STALE");

      // Append an immutable transition record.
      query(() => this.db
        .prepare("INSERT INTO job_history (job_id, from_state, to_state, attempt, occurred_at, created_at) VALUES (?, ?, ?, ?, ?, ?)")
        .run(jobIdParsed.value, before.state, after.state, after.attempt, after.updatedAt, this.now()));
      return after;
    });
  }

  /** Deterministic get by job id (null if absent). */
  get(jobId: unknown): JobRecord | null {
    const jobIdParsed = parseProtocolId("job", jobId);
    if (!jobIdParsed.ok) throw new JobStoreError("ERR_JOB_INPUT");
    return query<JobRecord | null>(() => {
      const rows = readJobRows(this.db, "SELECT * FROM jobs WHERE job_id = ?", [jobId as SQLInputValue]);
      if (rows.length === 0) return null;
      return decodeJobRow(rows[0] as unknown as JobRow);
    });
  }

  /** Fixed-state list (bounded, ordered by job id). */
  list(state: unknown, limit = 64): readonly JobRecord[] {
    const stateStr = state as string;
    assertJobState(stateStr);
    const limitNum = Number(limit);
    if (!Number.isInteger(limitNum) || limitNum < 0 || limitNum > 1024) throw new JobStoreError("ERR_JOB_STATE");
    return Object.freeze(
      query<JobRecord[]>(() =>
        readJobRows(this.db, "SELECT * FROM jobs WHERE state = ? ORDER BY job_id LIMIT ?", [
          stateStr,
          limitNum as SQLInputValue,
        ]).map((r) => decodeJobRow(r as JobRow)),
      ),
    );
  }

  /** Per-host list (bounded, ordered by job id). */
  listByHost(hostId: unknown, limit = 64): readonly JobRecord[] {
    if (!parseProtocolId("host", hostId).ok) throw new JobStoreError("ERR_JOB_INPUT");
    const limitNum = Number(limit);
    if (!Number.isInteger(limitNum) || limitNum < 0 || limitNum > 1024) throw new JobStoreError("ERR_JOB_STATE");
    return Object.freeze(
      query<JobRecord[]>(() =>
        readJobRows(this.db, "SELECT * FROM jobs WHERE host_id = ? ORDER BY job_id LIMIT ?", [
          hostId as SQLInputValue,
          limitNum as SQLInputValue,
        ]).map((r) => decodeJobRow(r as JobRow)),
      ),
    );
  }

  /** Deterministic transition history (bounded, ordered by created_at, rowid). */
  listHistory(jobId: unknown, limit = 256): readonly HistoryRecord[] {
    if (!parseProtocolId("job", jobId).ok) throw new JobStoreError("ERR_JOB_INPUT");
    const limitNum = Number(limit);
    if (!Number.isInteger(limitNum) || limitNum < 0 || limitNum > 1024) throw new JobStoreError("ERR_JOB_STATE");
    return Object.freeze(
      query<HistoryRecord[]>(() =>
        readJobRows(this.db, "SELECT job_id, from_state, to_state, attempt, occurred_at, created_at FROM job_history WHERE job_id = ? ORDER BY history_id LIMIT ?", [
          jobId as SQLInputValue,
          limitNum as SQLInputValue,
        ]).map((r) => decodeHistoryRow(r as unknown as HistoryRow)),
      ),
    );
  }

  /** True when the snapshot is retryable (idempotent, failed/timed-out, attempt < 100). */
  canRetry(record: JobRecord): boolean {
    return canRetryJob(record.payload);
  }
}

// ---------------------------------------------------------------------------
// AuditRepository (append-only, hash-linked, chain-verified on read)

export class AuditRepository {
  constructor(
    protected readonly db: DatabaseSync,
    protected readonly now: () => string = () => new Date().toISOString(),
  ) {}

  /** Append a validated audit event. Sequence and previous hash are assigned
   *  internally from the tail inside `BEGIN IMMEDIATE` (caller-supplied
   *  sequence/previousHash are ignored). Verifies the persisted chain and
   *  blocks on tamper/gap/reorder/hash mismatch. */
  append(command: unknown): AuditRecord {
    const bodyParsed = this.buildEvent(command);
    if (!bodyParsed.ok) throw new JobStoreError("ERR_AUDIT_APPEND_INPUT", [bodyParsed.error]);
    return runTransaction(this.db, () => {
      // Reject a corrupt already-persisted chain before appending.
      this.verifyPersistedChain();

      // Assign unique contiguous sequence + previousHash from the tail; never
      // trust caller-provided values.
      const tail = this.tailRow();
      const nextSeq = tail === null ? 1 : Number(tail.seq) + 1;
      if (!Number.isSafeInteger(nextSeq) || nextSeq > 10_000) throw new JobStoreError("ERR_AUDIT_INTEGRITY");
      const previousHash = tail?.hash ?? null;
      const finalBody: AuditEventBody = { ...bodyParsed.value, sequence: nextSeq, previousHash };
      const created = createAuditEvent(finalBody);
      if (!created.ok) throw new JobStoreError("ERR_AUDIT_APPEND_INPUT", [created.error]);
      const stored = created.value;

      const createdAt = this.now();
      auditQuery(() => this.db
        .prepare("INSERT INTO audit_events (seq, event_json, body_json, outcome, previous_hash, hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .run(nextSeq, this.canonicalEventJson(stored), this.canonicalBodyJson(stored), stored.outcome, stored.previousHash, stored.hash, createdAt));

      // Re-verify the full chain after insert (fail closed on any tamper/gap).
      this.verifyPersistedChain();
      return this.toRecord(stored, createdAt);
    });
  }

  /** The highest persisted sequence number (0 when empty), verifying integrity
   *  first. Blocks on a corrupt/gapped/reordered chain. */
  lastSequence(): number {
    return auditQuery(() => {
      this.verifyPersistedChain();
      const row = this.db.prepare("SELECT max(seq) AS last FROM audit_events").get() as { last?: number | bigint } | undefined;
      const last = row?.last;
      return typeof last === "bigint" ? Number(last) : (typeof last === "number" ? last : 0);
    });
  }

  /** Total number of persisted events (0 when empty). Integrity is verified
   *  first: a tampered/gapped/reordered chain fails closed instead of returning
   *  an untrustworthy count. */
  count(): number {
    return auditQuery<number>(() => {
      this.verifyPersistedChain();
      const row = this.db
        .prepare("SELECT count(seq) AS c FROM audit_events")
        .get() as { c?: number | bigint } | undefined;
      const c = row?.c;
      return typeof c === "bigint" ? Number(c) : (typeof c === "number" ? c : 0);
    });
  }

  /** The full persisted chain (bounded), verifying integrity first. */
  list(limit = 10_000): readonly AuditRecord[] {
    const limitNum = Number(limit);
    if (!Number.isInteger(limitNum) || limitNum < 0 || limitNum > 100_000) throw new JobStoreError("ERR_JOB_STATE");
    return Object.freeze(
      auditQuery<AuditRecord[]>(() =>
        this.readStoredRowsBounded(limitNum).map((r) => this.toRecordRow(r)),
      ),
    );
  }

  /** The tail event (or null when empty), verifying integrity first. */
  tail(): AuditRecord | null {
    return auditQuery<AuditRecord | null>(() => {
      this.verifyPersistedChain();
      const row = this.tailRow();
      return row === null ? null : this.toRecordRow(row);
    });
  }

  /** Verify (and fail closed on) the complete persisted chain. */
  verifyChain(): void {
    this.verifyPersistedChain();
  }

  // -- internal helpers ----------------------------------------------------

  /** Read stored rows (bounded), verifying chain integrity first. */
  private readStoredRowsBounded(limit: number): StoredRow[] {
    this.verifyPersistedChain();
    return readStoredRows(this.db, limit);
  }

  private tailRow(): StoredRow | null {
    const row = auditQuery(() => this.db.prepare("SELECT * FROM audit_events ORDER BY seq DESC LIMIT 1").get() as StoredRow | undefined);
    return row ?? null;
  }

  private verifyPersistedChain(): void {
    const stored = this.readStoredEventObjects();
    if (!stored.valid) throw new JobStoreError("ERR_AUDIT_INTEGRITY", [...stored.reasons]);
  }

  private readStoredEventObjects():
    | { valid: true; events: readonly AuditEvent[] }
    | { valid: false; reasons: readonly string[] } {
    const rows = readStoredRows(this.db, 100_000);
    if (rows.length === 0) return { valid: true, events: [] };
    const raw: AuditEvent[] = [];
    for (const r of rows) {
      let obj: unknown;
      let body: unknown;
      try {
        obj = JSON.parse(r.event_json);
        body = JSON.parse(r.body_json);
      } catch {
        return { valid: false, reasons: ["invalid-event"] };
      }
      const parsedBody = parseAuditEventBody(body);
      if (!parsedBody.ok || typeof obj !== "object" || obj === null) return { valid: false, reasons: ["invalid-event"] };
      const event = obj as AuditEvent;
      const seq = typeof r.seq === "bigint" ? Number(r.seq) : r.seq;
      if (event.sequence !== seq || parsedBody.value.sequence !== seq || event.hash !== r.hash ||
          event.previousHash !== r.previous_hash || parsedBody.value.previousHash !== r.previous_hash ||
          event.outcome !== r.outcome || r.event_json !== this.canonicalEventJson(event) ||
          r.body_json !== this.canonicalBodyJson(event)) {
        return { valid: false, reasons: ["invalid-event"] };
      }
      raw.push(event);
    }
    try {
      const verified = verifyAuditChain(raw);
      if (!verified.valid) return { valid: false, reasons: [...verified.reasons] } as never;
      return { valid: true, events: verified.events };
    } catch {
      return { valid: false, reasons: ["invalid-event"] };
    }
  }

  private toRecordRow(row: StoredRow): AuditRecord {
    const stored = this.readStoredEventObjects();
    if (stored.valid) {
      const matched = stored.events.find((e) => e.hash === row.hash);
      if (!matched) throw new JobStoreError("ERR_AUDIT_INTEGRITY");
      return this.toRecord(matched, row.created_at);
    }
    throw new JobStoreError("ERR_AUDIT_INTEGRITY", [...stored.reasons]);
  }

  private toRecord(event: AuditEvent, createdAt: string): AuditRecord {
    const parsed = parseUtcTimestamp(createdAt);
    if (!parsed.ok) throw new JobStoreError("ERR_AUDIT_INTEGRITY");
    const createdAtValue = parsed.value;
    const outcome = event.outcome as AuditOutcome;
    if (!["observed", "allowed", "denied", "started", "succeeded", "failed", "cancelled"].includes(outcome)) {
      throw new JobStoreError("ERR_AUDIT_APPEND_INPUT");
    }
    return frozen<AuditRecord>({
      sequence: event.sequence,
      occurredAt: event.occurredAt,
      actorKind: event.actorKind,
      actorId: event.actorId,
      action: event.action as string,
      outcome,
      requestId: event.requestId,
      jobId: event.jobId,
      hostId: event.hostId,
      details: event.details,
      previousHash: event.previousHash,
      hash: event.hash,
      createdAt: createdAtValue,
    });
  }

  private canonicalEventJson(event: AuditEvent): string {
    const combined: Record<string, JsonValue> = {
      sequence: event.sequence,
      occurredAt: event.occurredAt,
      actorKind: event.actorKind,
      actorId: event.actorId,
      action: event.action as JsonValue,
      outcome: event.outcome as JsonValue,
      requestId: event.requestId as unknown as JsonValue,
      jobId: event.jobId as unknown as JsonValue,
      hostId: event.hostId as unknown as JsonValue,
      details: event.details,
      previousHash: event.previousHash as unknown as JsonValue,
      hash: event.hash,
    };
    return JSON.stringify(combined);
  }

  private canonicalBodyJson(event: AuditEvent): string {
    const body: Record<string, JsonValue> = {
      sequence: event.sequence,
      occurredAt: event.occurredAt,
      actorKind: event.actorKind,
      actorId: event.actorId,
      action: event.action as JsonValue,
      outcome: event.outcome as JsonValue,
      requestId: event.requestId as unknown as JsonValue,
      jobId: event.jobId as unknown as JsonValue,
      hostId: event.hostId as unknown as JsonValue,
      details: event.details,
      previousHash: event.previousHash as unknown as JsonValue,
    };
    return JSON.stringify(body);
  }

  /** Build and validate the audit event body from a strict append command.
   *  Caller-supplied sequence/previousHash are intentionally ignored; they are
   *  assigned from the tail during storage (see {@link append}). */
  private buildEvent(command: unknown): ParseResult<AuditEventBody> {
    if (typeof command !== "object" || command === null || Array.isArray(command)) {
      return { ok: false, error: "ERR_AUDIT_FIELD" };
    }
    try {
      const proto = Object.getPrototypeOf(command);
      if (proto !== Object.prototype && proto !== null) {
        return { ok: false, error: "ERR_AUDIT_FIELD" };
      }
      const keys = Reflect.ownKeys(command);
      if (keys.some((k) => typeof k !== "string")) {
        return { ok: false, error: "ERR_AUDIT_FIELD" };
      }
      const required = ["actorKind", "actorId", "action", "outcome", "occurredAt"];
      const hasAllRequired = required.every((k) => keys.includes(k));
      const noExtra = keys.every((k) => ALLOWED_COMMAND_KEYS.includes(k as string));
      if (!hasAllRequired || !noExtra) {
        return { ok: false, error: "ERR_AUDIT_FIELD" };
      }
      const descriptors = Object.getOwnPropertyDescriptors(command);
      const field = (name: string): unknown => {
        const d = descriptors[name];
        return d && "value" in d ? d.value : undefined;
      };

      const actorKind = actorKindField(field("actorKind"));
      const actorId = actorIdField(field("actorId"));
      const actionParsed = parseProtocolMessageType(field("action"));
      const outcome = outcomeField(field("outcome"));
      const requestId = idField("request", field("requestId"));
      const jobId = idField("job", field("jobId"));
      const hostId = idField("host", field("hostId"));
      const details = detailsField(field("details"));
      const occurredParsed = parseUtcTimestamp(field("occurredAt"));
      if (
        !actorKind.ok ||
        !actorId.ok ||
        !actionParsed.ok ||
        !outcome.ok ||
        !requestId.ok ||
        !jobId.ok ||
        !hostId.ok ||
        !details.ok ||
        !occurredParsed.ok
      ) {
        return { ok: false, error: "ERR_AUDIT_FIELD" };
      }

      const body: AuditEventBody = {
        sequence: 1,
        occurredAt: occurredParsed.value,
        actorKind: actorKind.value,
        actorId: actorId.value,
        action: actionParsed.value,
        outcome: outcome.value,
        requestId: requestId.value as unknown as RequestId | null,
        jobId: jobId.value as unknown as JobId | null,
        hostId: hostId.value as unknown as HostId | null,
        details: details.value,
        previousHash: null,
      };
      return { ok: true, value: body };
    } catch {
      return { ok: false, error: "ERR_AUDIT_FIELD" };
    }
  }
}

// ---------------------------------------------------------------------------
// Factory: couples jobs + audit on a single connection.

export function createJobStores(db: DatabaseSync, options: { readonly now?: () => string } = {}): JobStores {
  const now = options.now ?? (() => new Date().toISOString());
  const jobs = new JobRepository(db, now);
  const audit = new AuditRepository(db, now);
  audit.verifyChain();

  const context: CoupledContext = {
    jobs,
    audit,
  };

  return {
    jobs,
    audit,
    withAuditTransaction(mutate: (tx: CoupledContext) => void): void {
      couplingState.set(db, true);
      try {
        db.exec("BEGIN IMMEDIATE");
        try {
          mutate(context);
        } catch (e) {
          try {
            db.exec("ROLLBACK");
          } catch {
            /* already rolled back */
          }
          throw e;
        }
        db.exec("COMMIT");
      } finally {
        couplingState.set(db, false);
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Field parsers + stored-row utilities (inline: invariant-preserving)

function auditQuery<T>(fn: () => T): T {
  try { return fn(); } catch (error) {
    if (error instanceof JobStoreError) throw error;
    throw new JobStoreError("ERR_AUDIT_DATABASE");
  }
}

function readStoredRows(db: DatabaseSync, limit: number): StoredRow[] {
  return auditQuery<StoredRow[]>(() =>
    db
      .prepare("SELECT * FROM audit_events ORDER BY seq LIMIT ?")
      .all(limit as SQLInputValue) as unknown as StoredRow[],
  );
}

function actorKindField(v: unknown): ParseResult<AuditActorKind> {
  if (["owner", "controller", "agent", "system"].includes(v as string)) {
    return { ok: true, value: v as AuditActorKind };
  }
  return { ok: false, error: "ERR_AUDIT_FIELD" };
}
function actorIdField(v: unknown): ParseResult<string> {
  return typeof v === "string" && v.length <= 128 && /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(v)
    ? { ok: true, value: v }
    : { ok: false, error: "ERR_AUDIT_FIELD" };
}
function outcomeField(v: unknown): ParseResult<AuditOutcome> {
  if (["observed", "allowed", "denied", "started", "succeeded", "failed", "cancelled"].includes(v as string)) {
    return { ok: true, value: v as AuditOutcome };
  }
  return { ok: false, error: "ERR_AUDIT_FIELD" };
}
function idField(kind: "request" | "job" | "host", v: unknown): ParseResult<string | null> {
  if (v === null || v === undefined) return { ok: true, value: null };
  const p = parseProtocolId(kind, v);
  return p.ok
    ? { ok: true, value: p.value as unknown as string }
    : { ok: false, error: "ERR_AUDIT_FIELD" };
}
function detailsField(v: unknown): ParseResult<JsonValue> {
  if (v === undefined) return { ok: true, value: (Object.create(null) as Record<string, JsonValue>) };
  const parsed = parseJsonValue(v);
  return parsed.ok
    ? { ok: true, value: parsed.value }
    : { ok: false, error: "ERR_AUDIT_FIELD" };
}
