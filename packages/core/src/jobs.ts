import type { MutationAction } from "./local-policy.js";
import { parseProtocolId, parseUtcTimestamp, type HostId, type JobId, type ParseResult, type RequestId, type UtcTimestamp } from "./protocol.js";

export type JobState = "submitted" | "validated" | "authorized" | "dispatched" | "accepted" | "running" | "succeeded" | "failed" | "timed-out" | "cancelled";
export interface JobOperation { readonly jobId: JobId; readonly requestId: RequestId; readonly action: MutationAction; readonly hostId: HostId; readonly submittedAt: UtcTimestamp; readonly manifestRevision: string | null; readonly idempotencyKey: string; readonly idempotent: boolean; }
export interface JobSnapshot { readonly operation: JobOperation; readonly state: JobState; readonly updatedAt: UtcTimestamp; readonly progressPercent: number | null; readonly attempt: number; readonly terminalCode: string | null; readonly terminalMessage: string | null; }
export interface JobSnapshotPatch { readonly progressPercent?: number | null; readonly terminalCode?: string | null; readonly terminalMessage?: string | null; }

const fail = <T>(error: string): ParseResult<T> => ({ ok: false, error });
const ACTIONS = new Set<unknown>(["load", "set-options", "drain", "unload", "install", "remove-managed-artifact", "evict-temporary"]);
const STATES = new Set<unknown>(["submitted", "validated", "authorized", "dispatched", "accepted", "running", "succeeded", "failed", "timed-out", "cancelled"]);
const TERMINAL = new Set<JobState>(["succeeded", "failed", "timed-out", "cancelled"]);
const MACHINE_CODE = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/;
const OPAQUE = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const SAFE_MESSAGE = /^[^\u0000-\u001f\u007f]+$/;
const GRAPH: Readonly<Record<JobState, readonly JobState[]>> = {
  submitted: ["validated", "cancelled"], validated: ["authorized", "failed", "cancelled"],
  authorized: ["dispatched", "failed", "cancelled"], dispatched: ["accepted", "failed", "timed-out", "cancelled"],
  accepted: ["running", "failed", "timed-out", "cancelled"], running: ["succeeded", "failed", "timed-out", "cancelled"],
  succeeded: [], failed: [], "timed-out": [], cancelled: [],
};

function fields(input: unknown, keys: readonly string[], error: string): ParseResult<Record<string, PropertyDescriptor>> {
  if (typeof input !== "object" || input === null) return fail(error);
  try {
    if (Array.isArray(input)) return fail(error);
    const prototype = Object.getPrototypeOf(input); if (prototype !== Object.prototype && prototype !== null) return fail(error);
    const own = Reflect.ownKeys(input); if (own.length !== keys.length || own.some((key) => typeof key !== "string" || !keys.includes(key))) return fail(error);
    const descriptors = Object.getOwnPropertyDescriptors(input); if (keys.some((key) => !descriptors[key] || !("value" in descriptors[key]))) return fail(error);
    return { ok: true, value: descriptors };
  } catch { return fail(error); }
}
function opaque(input: unknown, nullable = false): ParseResult<string | null> {
  if (nullable && input === null) return { ok: true, value: null };
  return typeof input === "string" && input.length >= 1 && input.length <= 128 && OPAQUE.test(input) ? { ok: true, value: input } : fail("ERR_OPAQUE_ID");
}
function frozen<T>(values: Record<string, unknown>): T { return Object.freeze(Object.assign(Object.create(null), values)) as T; }

export function parseJobOperation(input: unknown): ParseResult<JobOperation> {
  const parsed = fields(input, ["jobId", "requestId", "action", "hostId", "submittedAt", "manifestRevision", "idempotencyKey", "idempotent"], "ERR_JOB_OPERATION"); if (!parsed.ok) return parsed;
  const job = parseProtocolId("job", parsed.value.jobId?.value as unknown); const request = parseProtocolId("request", parsed.value.requestId?.value as unknown); const host = parseProtocolId("host", parsed.value.hostId?.value as unknown);
  const submitted = parseUtcTimestamp(parsed.value.submittedAt?.value as unknown); const revision = opaque(parsed.value.manifestRevision?.value as unknown, true); const key = opaque(parsed.value.idempotencyKey?.value as unknown);
  const action = parsed.value.action?.value as unknown; const idempotent = parsed.value.idempotent?.value as unknown;
  if (!job.ok || !request.ok || !host.ok || !submitted.ok || !revision.ok || !key.ok || !ACTIONS.has(action) || typeof idempotent !== "boolean") return fail("ERR_JOB_OPERATION_FIELD");
  return { ok: true, value: frozen<JobOperation>({ jobId: job.value, requestId: request.value, action, hostId: host.value, submittedAt: submitted.value, manifestRevision: revision.value, idempotencyKey: key.value, idempotent }) };
}

function validateSnapshot(state: JobState, progress: number | null, code: string | null, message: string | null): ParseResult<true> {
  if (progress !== null && (typeof progress !== "number" || !Number.isInteger(progress) || progress < 0 || progress > 100)) return fail("ERR_JOB_PROGRESS");
  if ((state === "submitted" || state === "validated" || state === "authorized" || state === "dispatched") && progress !== null) return fail("ERR_JOB_PROGRESS");
  if ((state === "accepted" || state === "running") && (progress === null || progress > 99)) return fail("ERR_JOB_PROGRESS");
  if (state === "succeeded" && progress !== 100) return fail("ERR_JOB_PROGRESS");
  if ((state === "failed" || state === "timed-out" || state === "cancelled") && progress !== null) return fail("ERR_JOB_PROGRESS");
  if (state === "failed" || state === "timed-out" || state === "cancelled") {
    if (typeof code !== "string" || code.length > 64 || !MACHINE_CODE.test(code) || typeof message !== "string" || message.length < 1 || message.length > 1024 || !SAFE_MESSAGE.test(message)) return fail("ERR_JOB_TERMINAL");
  } else if (code !== null || message !== null) return fail("ERR_JOB_TERMINAL");
  return { ok: true, value: true };
}

export function parseJobSnapshot(input: unknown): ParseResult<JobSnapshot> {
  const parsed = fields(input, ["operation", "state", "updatedAt", "progressPercent", "attempt", "terminalCode", "terminalMessage"], "ERR_JOB_SNAPSHOT"); if (!parsed.ok) return parsed;
  const operation = parseJobOperation(parsed.value.operation?.value as unknown); const state = parsed.value.state?.value as unknown; const updated = parseUtcTimestamp(parsed.value.updatedAt?.value as unknown);
  const progress = parsed.value.progressPercent?.value as unknown; const attempt = parsed.value.attempt?.value as unknown; const code = parsed.value.terminalCode?.value as unknown; const message = parsed.value.terminalMessage?.value as unknown;
  if (!operation.ok || !STATES.has(state) || !updated.ok || updated.value < (operation.ok ? operation.value.submittedAt : "") || typeof attempt !== "number" || !Number.isInteger(attempt) || attempt < 1 || attempt > 100) return fail("ERR_JOB_SNAPSHOT_FIELD");
  if (progress !== null && typeof progress !== "number") return fail("ERR_JOB_PROGRESS"); if (code !== null && typeof code !== "string") return fail("ERR_JOB_TERMINAL"); if (message !== null && typeof message !== "string") return fail("ERR_JOB_TERMINAL");
  const invariant = validateSnapshot(state as JobState, progress as number | null, code as string | null, message as string | null); if (!invariant.ok) return invariant;
  return { ok: true, value: frozen<JobSnapshot>({ operation: operation.value, state, updatedAt: updated.value, progressPercent: progress, attempt, terminalCode: code, terminalMessage: message }) };
}

function parsePatch(input: unknown): ParseResult<JobSnapshotPatch> {
  if (input === undefined) return { ok: true, value: Object.freeze({}) };
  if (typeof input !== "object" || input === null) return fail("ERR_JOB_PATCH");
  try {
    if (Array.isArray(input)) return fail("ERR_JOB_PATCH"); const prototype = Object.getPrototypeOf(input); if (prototype !== Object.prototype && prototype !== null) return fail("ERR_JOB_PATCH");
    const allowed = ["progressPercent", "terminalCode", "terminalMessage"]; const own = Reflect.ownKeys(input); if (own.some((key) => typeof key !== "string" || !allowed.includes(key))) return fail("ERR_JOB_PATCH");
    const descriptors = Object.getOwnPropertyDescriptors(input); if (own.some((key) => typeof key !== "string" || !descriptors[key] || !("value" in descriptors[key]))) return fail("ERR_JOB_PATCH");
    return { ok: true, value: frozen<JobSnapshotPatch>(Object.fromEntries(own.map((key) => [key as string, descriptors[key as string]?.value as unknown]))) };
  } catch { return fail("ERR_JOB_PATCH"); }
}

function defaults(state: JobState): Pick<JobSnapshot, "progressPercent" | "terminalCode" | "terminalMessage"> {
  if (state === "accepted" || state === "running") return { progressPercent: 0, terminalCode: null, terminalMessage: null };
  if (state === "succeeded") return { progressPercent: 100, terminalCode: null, terminalMessage: null };
  return { progressPercent: null, terminalCode: null, terminalMessage: null };
}

export function transitionJob(currentInput: unknown, targetInput: unknown, updatedInput: unknown, patchInput?: unknown): ParseResult<JobSnapshot> {
  const current = parseJobSnapshot(currentInput); const updated = parseUtcTimestamp(updatedInput); const patch = parsePatch(patchInput);
  if (!current.ok || !updated.ok || !patch.ok || !STATES.has(targetInput)) return fail("ERR_JOB_TRANSITION_INPUT");
  const target = targetInput as JobState; if (updated.value < current.value.updatedAt) return fail("ERR_JOB_TIME_REGRESSION");
  const sameRetry = target === current.value.state;
  if (sameRetry) {
    if (!(target === "dispatched" || target === "accepted" || target === "running") || !current.value.operation.idempotent || current.value.attempt >= 100) return fail("ERR_JOB_TRANSITION");
  } else if (!GRAPH[current.value.state].includes(target)) return fail(TERMINAL.has(current.value.state) ? "ERR_JOB_TERMINAL_STATE" : "ERR_JOB_TRANSITION");
  const base = defaults(target); const progress = patch.value.progressPercent === undefined ? base.progressPercent : patch.value.progressPercent; const code = patch.value.terminalCode === undefined ? base.terminalCode : patch.value.terminalCode; const message = patch.value.terminalMessage === undefined ? base.terminalMessage : patch.value.terminalMessage;
  return parseJobSnapshot({ operation: current.value.operation, state: target, updatedAt: updated.value, progressPercent: progress, attempt: sameRetry ? current.value.attempt + 1 : current.value.attempt, terminalCode: code, terminalMessage: message });
}

export function canRetryJob(snapshot: JobSnapshot): boolean { return (snapshot.state === "failed" || snapshot.state === "timed-out") && snapshot.operation.idempotent && snapshot.attempt < 100; }
