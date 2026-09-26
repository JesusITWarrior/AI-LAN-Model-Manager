import { createHash } from "node:crypto";
import {
  parseJsonValue, parseProtocolId, parseProtocolMessageType, parseUtcTimestamp,
  type HostId, type JobId, type JsonValue, type ParseResult, type ProtocolMessageType,
  type RequestId, type UtcTimestamp,
} from "./protocol.js";

export type AuditActorKind = "owner" | "controller" | "agent" | "system";
export type AuditOutcome = "observed" | "allowed" | "denied" | "started" | "succeeded" | "failed" | "cancelled";
export type AuditVerificationReason = "invalid-event" | "hash-mismatch" | "previous-hash-mismatch" | "sequence-mismatch";
export interface AuditEventBody {
  readonly sequence: number; readonly occurredAt: UtcTimestamp; readonly actorKind: AuditActorKind;
  readonly actorId: string; readonly action: ProtocolMessageType; readonly outcome: AuditOutcome;
  readonly requestId: RequestId | null; readonly jobId: JobId | null; readonly hostId: HostId | null;
  readonly details: JsonValue; readonly previousHash: string | null;
}
export interface AuditEvent extends AuditEventBody { readonly hash: string; }
export type AuditVerification = { readonly valid: true; readonly event: AuditEvent } | { readonly valid: false; readonly reasons: readonly AuditVerificationReason[] };
export type AuditChainVerification = { readonly valid: true; readonly events: readonly AuditEvent[] } | { readonly valid: false; readonly index: number; readonly reasons: readonly AuditVerificationReason[] };

const BODY_KEYS = ["sequence", "occurredAt", "actorKind", "actorId", "action", "outcome", "requestId", "jobId", "hostId", "details", "previousHash"] as const;
const EVENT_KEYS = [...BODY_KEYS, "hash"] as const;
const ACTORS = new Set<unknown>(["owner", "controller", "agent", "system"]);
const OUTCOMES = new Set<unknown>(["observed", "allowed", "denied", "started", "succeeded", "failed", "cancelled"]);
const HASH = /^[0-9a-f]{64}$/;
const ACTOR_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const fail = <T>(error: string): ParseResult<T> => ({ ok: false, error });

function fields(input: unknown, keys: readonly string[]): ParseResult<Record<string, PropertyDescriptor>> {
  if (typeof input !== "object" || input === null) return fail("ERR_AUDIT_OBJECT");
  try {
    if (Array.isArray(input)) return fail("ERR_AUDIT_OBJECT");
    const prototype = Object.getPrototypeOf(input); if (prototype !== Object.prototype && prototype !== null) return fail("ERR_AUDIT_OBJECT");
    const own = Reflect.ownKeys(input); if (own.length !== keys.length || own.some((key) => typeof key !== "string" || !keys.includes(key))) return fail("ERR_AUDIT_KEYS");
    const descriptors = Object.getOwnPropertyDescriptors(input); if (keys.some((key) => !descriptors[key] || !("value" in descriptors[key]))) return fail("ERR_AUDIT_ACCESSOR");
    return { ok: true, value: descriptors };
  } catch { return fail("ERR_AUDIT_OBJECT"); }
}
function nullableId(kind: "request" | "job" | "host", input: unknown): ParseResult<RequestId | JobId | HostId | null> {
  if (input === null) return { ok: true, value: null };
  return parseProtocolId(kind, input);
}
function frozen<T>(values: Record<string, unknown>): T { return Object.freeze(Object.assign(Object.create(null), values)) as T; }

export function parseAuditEventBody(input: unknown): ParseResult<AuditEventBody> {
  const parsed = fields(input, BODY_KEYS); if (!parsed.ok) return parsed;
  const sequence = parsed.value.sequence?.value as unknown; const occurred = parseUtcTimestamp(parsed.value.occurredAt?.value as unknown);
  const actorKind = parsed.value.actorKind?.value as unknown; const actorId = parsed.value.actorId?.value as unknown;
  const action = parseProtocolMessageType(parsed.value.action?.value as unknown); const outcome = parsed.value.outcome?.value as unknown;
  const requestId = nullableId("request", parsed.value.requestId?.value as unknown); const jobId = nullableId("job", parsed.value.jobId?.value as unknown); const hostId = nullableId("host", parsed.value.hostId?.value as unknown);
  const details = parseJsonValue(parsed.value.details?.value as unknown); const previousHash = parsed.value.previousHash?.value as unknown;
  if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 1) return fail("ERR_AUDIT_SEQUENCE");
  if (!occurred.ok || !ACTORS.has(actorKind) || typeof actorId !== "string" || actorId.length < 1 || actorId.length > 128 || !ACTOR_ID.test(actorId) || !action.ok || !OUTCOMES.has(outcome) || !requestId.ok || !jobId.ok || !hostId.ok || !details.ok) return fail("ERR_AUDIT_FIELD");
  if (previousHash !== null && (typeof previousHash !== "string" || !HASH.test(previousHash))) return fail("ERR_AUDIT_PREVIOUS_HASH");
  if ((sequence === 1) !== (previousHash === null)) return fail("ERR_AUDIT_LINK");
  return { ok: true, value: frozen<AuditEventBody>({ sequence, occurredAt: occurred.value, actorKind, actorId, action: action.value, outcome, requestId: requestId.value, jobId: jobId.value, hostId: hostId.value, details: details.value, previousHash }) };
}

function canonical(value: JsonValue): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") return Object.is(value, -0) ? "0" : JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const object = value as { readonly [key: string]: JsonValue };
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonical(object[key]!)}`).join(",")}}`;
}
function bodyAsJson(body: AuditEventBody): JsonValue {
  const output = Object.create(null) as Record<string, JsonValue>;
  for (const key of BODY_KEYS) output[key] = body[key] as JsonValue;
  return output;
}
export function computeAuditHash(bodyInput: unknown): ParseResult<string> {
  const body = parseAuditEventBody(bodyInput); if (!body.ok) return body;
  return { ok: true, value: createHash("sha256").update(canonical(bodyAsJson(body.value)), "utf8").digest("hex") };
}
export function createAuditEvent(bodyInput: unknown): ParseResult<AuditEvent> {
  const body = parseAuditEventBody(bodyInput); if (!body.ok) return body;
  const hash = computeAuditHash(body.value); if (!hash.ok) return hash;
  return { ok: true, value: frozen<AuditEvent>({ ...body.value, hash: hash.value }) };
}

function parseAuditEvent(input: unknown): ParseResult<AuditEvent> {
  const parsed = fields(input, EVENT_KEYS); if (!parsed.ok) return parsed;
  const rawBody = Object.create(null) as Record<string, unknown>; for (const key of BODY_KEYS) rawBody[key] = parsed.value[key]?.value as unknown;
  const body = parseAuditEventBody(rawBody); const hash = parsed.value.hash?.value as unknown;
  if (!body.ok || typeof hash !== "string" || !HASH.test(hash)) return fail("ERR_AUDIT_EVENT");
  return { ok: true, value: frozen<AuditEvent>({ ...body.value, hash }) };
}
function invalid(reasons: AuditVerificationReason[]): AuditVerification { return { valid: false, reasons: Object.freeze(reasons) }; }
export function verifyAuditEvent(eventInput: unknown, expectedPreviousHash?: unknown, expectedSequence?: unknown): AuditVerification {
  const event = parseAuditEvent(eventInput); if (!event.ok) return invalid(["invalid-event"]);
  const reasons: AuditVerificationReason[] = [];
  const rawBody = Object.create(null) as Record<string, unknown>;
  for (const key of BODY_KEYS) rawBody[key] = event.value[key];
  const computed = computeAuditHash(rawBody); if (!computed.ok || computed.value !== event.value.hash) reasons.push("hash-mismatch");
  if (expectedPreviousHash !== undefined && ((expectedPreviousHash !== null && (typeof expectedPreviousHash !== "string" || !HASH.test(expectedPreviousHash))) || event.value.previousHash !== expectedPreviousHash)) reasons.push("previous-hash-mismatch");
  if (expectedSequence !== undefined && (typeof expectedSequence !== "number" || !Number.isSafeInteger(expectedSequence) || expectedSequence < 1 || event.value.sequence !== expectedSequence)) reasons.push("sequence-mismatch");
  return reasons.length ? invalid(reasons) : { valid: true, event: event.value };
}

export function verifyAuditChain(input: unknown): AuditChainVerification {
  try {
    if (!Array.isArray(input)) return { valid: false, index: -1, reasons: Object.freeze(["invalid-event"]) };
    const descriptors = Object.getOwnPropertyDescriptors(input); const lengthDescriptor: PropertyDescriptor | undefined = Object.getOwnPropertyDescriptor(input, "length"); const length = lengthDescriptor?.value as unknown;
    const keys = Reflect.ownKeys(input); if (!Number.isSafeInteger(length) || (length as number) < 0 || (length as number) > 10_000 || keys.some((key) => typeof key !== "string" || (key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key)))) return { valid: false, index: -1, reasons: Object.freeze(["invalid-event"]) };
    const output: AuditEvent[] = []; let previous: string | null = null;
    for (let index = 0; index < (length as number); index += 1) {
      const descriptor = descriptors[String(index)]; if (!descriptor || !("value" in descriptor)) return { valid: false, index, reasons: Object.freeze(["invalid-event"]) };
      const verified = verifyAuditEvent(descriptor.value as unknown, previous, index + 1); if (!verified.valid) return { valid: false, index, reasons: verified.reasons };
      output.push(verified.event); previous = verified.event.hash;
    }
    return { valid: true, events: Object.freeze(output) };
  } catch { return { valid: false, index: -1, reasons: Object.freeze(["invalid-event"]) }; }
}
