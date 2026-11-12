import { createHash } from "node:crypto";
import { isProxy } from "node:util/types";

/** Stable versioned domain for the pure terminal-history revision contract. */
export const TERMINAL_REVISION_DOMAIN = "lanmm/native/terminal-revision/v1";

export const TERMINAL_STATES = ["succeeded", "failed", "timed-out", "cancelled"] as const;
export type TerminalJobState = (typeof TERMINAL_STATES)[number];
export const IDENTIFIER_MAX = 128;
export const ATTEMPT_MAX = 100;

const ALL_STATES = ["submitted", "validated", "authorized", "dispatched", "accepted", "running", ...TERMINAL_STATES] as const;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const DIGEST_RE = /^[0-9a-f]{64}$/;
const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MAX_CANONICAL_BYTES = 8192;

/** Explicit server-derived job projection. requestId comes from parsed payload.operation. */
export interface TerminalJobProjection {
  readonly jobId: string;
  readonly requestId: string;
  readonly state: TerminalJobState;
  readonly hostId: string;
  readonly submittedAt: string;
  readonly updatedAt: string;
  readonly attempt: number;
  readonly idempotencyKey: string;
}

/** The latest row selected by the server using maximum history_id. */
export interface JobHistoryProjection {
  readonly historyId: number;
  readonly jobId: string;
  readonly fromState: string;
  readonly toState: TerminalJobState;
  readonly attempt: number;
  readonly occurredAt: string;
  readonly createdAt: string;
}

/** Exact validated command/request bindings; metadata fields are ignored by contract. */
export interface RequestQueueBinding {
  readonly jobId: string;
  readonly hostId: string;
  readonly requestId: string;
  readonly operation: string;
  readonly idempotencyKey: string;
  readonly sequence: number;
  readonly deadline: string;
  /** SHA-256 over the stored validated queue request; separate from authorizationDigest. */
  readonly storedQueueDigest: string;
  /** Command capability authorization digest; never substituted for storedQueueDigest. */
  readonly authorizationDigest: string;
  /** Mutable metadata intentionally excluded from the revision. */
  readonly updatedAt?: unknown;
  /** Audit metadata intentionally excluded from the revision and never traversed. */
  readonly auditTail?: unknown;
}

export interface TerminalRevisionInput {
  readonly job: TerminalJobProjection;
  readonly history: JobHistoryProjection;
  readonly binding: RequestQueueBinding;
}

export type TerminalRevisionResult =
  | Readonly<{ ok: true; domain: string; revision: string; state: TerminalJobState }>
  | Readonly<{ ok: false; code: "invalid-input" | "invalid-field" | "history-mismatch" | "binding-mismatch" | "oversized-projection" }>;

type Data = Record<string, unknown>;

/**
 * Copy an exact set of own data properties without reading the input object.
 * Proxies, accessors, symbols, unexpected keys, arrays and custom prototypes fail closed.
 */
function ownData(input: unknown, required: readonly string[], optional: readonly string[] = []): Data | null {
  if (typeof input !== "object" || input === null || Array.isArray(input) || isProxy(input)) return null;
  try {
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const keys = Reflect.ownKeys(input);
    if (keys.some((key) => typeof key !== "string" || (!required.includes(key) && !optional.includes(key)))) return null;
    if (required.some((key) => !keys.includes(key))) return null;
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const values: Data = Object.create(null) as Data;
    for (const key of keys as string[]) {
      const descriptor = descriptors[key];
      if (!descriptor || !("value" in descriptor)) return null;
      values[key] = descriptor.value as unknown;
    }
    return values;
  } catch {
    return null;
  }
}

function validId(value: unknown): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= IDENTIFIER_MAX && ID_RE.test(value);
}

function validTime(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 24 || !TIME_RE.test(value)) return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function validAttempt(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1 && value <= ATTEMPT_MAX;
}

function validSequence(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1;
}

function validState(value: unknown): value is string {
  return typeof value === "string" && (ALL_STATES as readonly string[]).includes(value);
}

function validTerminal(value: unknown): value is TerminalJobState {
  return typeof value === "string" && (TERMINAL_STATES as readonly string[]).includes(value);
}

function validDigest(value: unknown): value is string {
  return typeof value === "string" && DIGEST_RE.test(value);
}

const fail = (code: Extract<TerminalRevisionResult, { ok: false }>["code"]): TerminalRevisionResult =>
  Object.freeze({ ok: false as const, code });

/**
 * Derive a deterministic digest from exact fixed-order projections. This helper
 * neither reads a database nor proves the caller actually selected the latest row.
 * The future caller must obtain/validate these projections from authoritative storage.
 */
export function computeTerminalRevision(input: unknown): TerminalRevisionResult {
  const top = ownData(input, ["job", "history", "binding"]);
  if (!top) return fail("invalid-input");
  const job = ownData(top.job, ["jobId", "requestId", "state", "hostId", "submittedAt", "updatedAt", "attempt", "idempotencyKey"]);
  const history = ownData(top.history, ["historyId", "jobId", "fromState", "toState", "attempt", "occurredAt", "createdAt"]);
  const binding = ownData(top.binding,
    ["jobId", "hostId", "requestId", "operation", "idempotencyKey", "sequence", "deadline", "storedQueueDigest", "authorizationDigest"],
    ["updatedAt", "auditTail"]);
  if (!job || !history || !binding) return fail("invalid-input");

  if (![job.jobId, job.requestId, job.hostId, job.idempotencyKey, history.jobId, binding.jobId, binding.hostId,
    binding.requestId, binding.operation, binding.idempotencyKey].every(validId)) return fail("invalid-field");
  if (!validTerminal(job.state) || !validTerminal(history.toState) || !validState(history.fromState)) return fail("invalid-field");
  if (!validAttempt(job.attempt) || !validAttempt(history.attempt) || !validSequence(binding.sequence) ||
      typeof history.historyId !== "number" || !Number.isSafeInteger(history.historyId) || history.historyId < 1) return fail("invalid-field");
  if (![job.submittedAt, job.updatedAt, history.occurredAt, history.createdAt, binding.deadline].every(validTime)) return fail("invalid-field");
  if (!validDigest(binding.storedQueueDigest) || !validDigest(binding.authorizationDigest)) return fail("invalid-field");

  const jobSubmittedAt = job.submittedAt as string;
  const jobUpdatedAt = job.updatedAt as string;
  const historyOccurredAt = history.occurredAt as string;
  if (history.jobId !== job.jobId || history.toState !== job.state || history.attempt !== job.attempt ||
      historyOccurredAt !== jobUpdatedAt || historyOccurredAt < jobSubmittedAt) return fail("history-mismatch");
  if (binding.jobId !== job.jobId || binding.hostId !== job.hostId || binding.requestId !== job.requestId ||
      binding.idempotencyKey !== job.idempotencyKey) return fail("binding-mismatch");

  // Positional JSON tuple: no object spread, unstable key order, or caller-controlled properties.
  const projection = [
    TERMINAL_REVISION_DOMAIN,
    job.jobId, job.requestId, job.state, job.hostId, job.submittedAt, job.updatedAt, job.attempt, job.idempotencyKey,
    history.historyId, history.jobId, history.fromState, history.toState, history.attempt, history.occurredAt, history.createdAt,
    binding.jobId, binding.hostId, binding.requestId, binding.operation, binding.idempotencyKey, binding.sequence,
    binding.deadline, binding.storedQueueDigest, binding.authorizationDigest,
  ] as const;
  const bytes = Buffer.from(JSON.stringify(projection), "utf8");
  if (bytes.length > MAX_CANONICAL_BYTES) return fail("oversized-projection");
  const revision = createHash("sha256")
    .update(`${TERMINAL_REVISION_DOMAIN}\0`, "utf8")
    .update(bytes)
    .digest("hex");
  return Object.freeze({ ok: true as const, domain: TERMINAL_REVISION_DOMAIN, revision, state: job.state });
}

export default computeTerminalRevision;
