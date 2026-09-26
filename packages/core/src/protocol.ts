/**
 * Protocol version handling and runtime-validated opaque IDs.
 *
 * Every boundary function in this module is non-throwing: validation failures
 * are reported through a discriminated `{ ok: false; error }` result whose
 * `error` is a stable short machine code (never a raw echo of untrusted input,
 * and never a thrown exception).
 */

/** A protocol version: a pair of non-negative safe integers. */
export type ProtocolVersion = Readonly<{ readonly major: number; readonly minor: number }>;

/** The protocol version this package currently targets. */
export const CURRENT_PROTOCOL_VERSION: ProtocolVersion = Object.freeze({ major: 1, minor: 0 });

/** Result of a non-throwing validation: either a value or a stable machine-code error. */
export type ParseResult<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: string };

// Stable machine codes. Never echo raw input; never throw.
const ERR_INVALID_TYPE = "ERR_INVALID_TYPE";
const ERR_MISSING_KEY = "ERR_MISSING_KEY";
const ERR_EXTRA_KEY = "ERR_EXTRA_KEY";
const ERR_NON_FINITE = "ERR_NON_FINITE";
const ERR_NON_INTEGER = "ERR_NON_INTEGER";
const ERR_NEGATIVE_VALUE = "ERR_NEGATIVE_VALUE";
const ERR_OUT_OF_RANGE = "ERR_OUT_OF_RANGE";
const ERR_INVALID_LENGTH = "ERR_INVALID_LENGTH";
const ERR_INVALID_FORMAT = "ERR_INVALID_FORMAT";
const ERR_UNSUPPORTED_TYPE = "ERR_UNSUPPORTED_TYPE";

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const UTC_TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;

/**
 * Parse an unknown value into a {@link ProtocolVersion}.
 *
 * Accepts ONLY plain objects (prototype `null` or `Object.prototype`) with
 * exactly the keys `major` and `minor`, each a finite, non-negative, integer
 * value within the safe-integer range.
 */
export function parseProtocolVersion(input: unknown): ParseResult<ProtocolVersion> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return { ok: false, error: ERR_INVALID_TYPE };
  }

  try {
    const proto = Object.getPrototypeOf(input);
    if (proto !== Object.prototype && proto !== null) {
      return { ok: false, error: ERR_INVALID_TYPE };
    }

    const ownKeys = Reflect.ownKeys(input);
    if (ownKeys.some((key) => typeof key !== "string" || (key !== "major" && key !== "minor"))) {
      return { ok: false, error: ERR_EXTRA_KEY };
    }
    if (!ownKeys.includes("major") || !ownKeys.includes("minor")) {
      return { ok: false, error: ERR_MISSING_KEY };
    }

    const descriptors = Object.getOwnPropertyDescriptors(input);
    const majorDescriptor = descriptors.major;
    const minorDescriptor = descriptors.minor;
    if (!majorDescriptor || !minorDescriptor || !("value" in majorDescriptor) || !("value" in minorDescriptor)) {
      return { ok: false, error: ERR_INVALID_TYPE };
    }

    const major = majorDescriptor.value as unknown;
    const minor = minorDescriptor.value as unknown;
    const majorError = validateNumericField(major);
    if (majorError) {
      return { ok: false, error: majorError };
    }
    const minorError = validateNumericField(minor);
    if (minorError) {
      return { ok: false, error: minorError };
    }

    return {
      ok: true,
      value: Object.freeze({ major: major as number, minor: minor as number }),
    };
  } catch {
    return { ok: false, error: ERR_INVALID_TYPE };
  }
}

/** Validate a single numeric field against the "finite, non-negative, safe integer" rule. */
function validateNumericField(value: unknown): string | null {
  if (typeof value !== "number") {
    return ERR_INVALID_TYPE;
  }
  if (!Number.isFinite(value)) {
    return ERR_NON_FINITE;
  }
  if (!Number.isInteger(value)) {
    return ERR_NON_INTEGER;
  }
  if (value < 0) {
    return ERR_NEGATIVE_VALUE;
  }
  if (value > Number.MAX_SAFE_INTEGER) {
    return ERR_OUT_OF_RANGE;
  }
  return null;
}

/**
 * Non-throwing compatibility check between a local and a peer version.
 *
 * Both inputs are treated as untrusted: each must parse successfully. A peer is
 * compatible only when the majors match and `peer.minor <= local.minor`.
 */
export function isProtocolVersionCompatible(local: unknown, peer: unknown): boolean {
  const localResult = parseProtocolVersion(local);
  if (!localResult.ok) {
    return false;
  }
  const peerResult = parseProtocolVersion(peer);
  if (!peerResult.ok) {
    return false;
  }
  return localResult.value.major === peerResult.value.major && peerResult.value.minor <= localResult.value.minor;
}

// ---------------------------------------------------------------------------
// Branded opaque IDs
// ---------------------------------------------------------------------------

// Phantom brand markers: `unique symbol`s that only this module can name, so
// callers cannot construct a branded id value by hand.
declare const brandRequestId: unique symbol;
declare const brandJobId: unique symbol;
declare const brandHostId: unique symbol;
declare const brandCorrelationId: unique symbol;

/** Opaque request identifier. */
export type RequestId = string & { readonly __brand: typeof brandRequestId };
/** Opaque job identifier. */
export type JobId = string & { readonly __brand: typeof brandJobId };
/** Opaque host identifier. */
export type HostId = string & { readonly __brand: typeof brandHostId };
/** Opaque correlation identifier. */
export type CorrelationId = string & { readonly __brand: typeof brandCorrelationId };

type IdKind = "request" | "job" | "host" | "correlation";

/** Map an id kind to its branded type. */
type KindToId<K extends IdKind> = K extends "request"
  ? RequestId
  : K extends "job"
    ? JobId
    : K extends "host"
      ? HostId
      : K extends "correlation"
        ? CorrelationId
        : never;

/**
 * Non-throwing parser for branded opaque IDs.
 *
 * Input must be a string of 1..128 ASCII characters matching
 * `^[A-Za-z0-9][A-Za-z0-9._:-]*$` (whitespace, control chars, slash, backslash,
 * query/hash delimiters, percent encoding, and non-ASCII are all rejected).
 * No coercion or trimming is performed: non-string input is rejected immediately.
 */
export function parseProtocolId<K extends IdKind>(
  kind: K,
  input: unknown,
): ParseResult<KindToId<K>> {
  if (typeof input !== "string") {
    return { ok: false, error: ERR_INVALID_TYPE };
  }
  if (input.length < 1 || input.length > 128) {
    return { ok: false, error: ERR_INVALID_LENGTH };
  }
  if (!ID_PATTERN.test(input)) {
    return { ok: false, error: ERR_INVALID_FORMAT };
  }
  return { ok: true, value: input as unknown as KindToId<K> };
}

// ---------------------------------------------------------------------------
// Branded opaque UTC timestamps
// ---------------------------------------------------------------------------

declare const brandUtcTimestamp: unique symbol;

/** Opaque UTC timestamp: exactly `YYYY-MM-DDTHH:mm:ss.sssZ` that round-trips through Date. */
export type UtcTimestamp = string & { readonly __brand: typeof brandUtcTimestamp };

/**
 * Parse an unknown value into a {@link UtcTimestamp}.
 *
 * Accepts ONLY strings matching exactly `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`
 * AND for which `new Date(input)` is valid (not NaN) AND `.toISOString() === input`.
 * This four-step gate rejects: non-strings, wrong format, invalid calendar dates, timezone
 * offsets, missing/short/long ms digits, lowercase t/z, date-only values, whitespace,
 * expanded/signed years, null/number/object inputs. No trim/coercion. Never throws.
 */
export function parseUtcTimestamp(input: unknown): ParseResult<UtcTimestamp> {
  if (typeof input !== "string") {
    return { ok: false, error: ERR_INVALID_TYPE };
  }

  // Step 1: exact ASCII format — four-digit year, T separator, three ms digits, Z suffix.
  if (!UTC_TIMESTAMP_PATTERN.test(input)) {
    return { ok: false, error: ERR_INVALID_FORMAT };
  }

  // Step 2: construct Date — must not be NaN.
  const date = new Date(input);
  if (Number.isNaN(date.getTime())) {
    return { ok: false, error: ERR_OUT_OF_RANGE };
  }

  // Step 3: round-trip through toISOString must equal the original input exactly.
  if (date.toISOString() !== input) {
    return { ok: false, error: ERR_INVALID_FORMAT };
  }

  return { ok: true, value: input as unknown as UtcTimestamp };
}

// ---------------------------------------------------------------------------
// Bounded JSON values
// ---------------------------------------------------------------------------

export type JsonPrimitive = null | boolean | number | string;
export type JsonArray = readonly JsonValue[];
export type JsonObject = { readonly [key: string]: JsonValue };
export type JsonValue = JsonPrimitive | JsonArray | JsonObject;

export interface JsonValueLimits {
  readonly maxDepth: number;
  readonly maxNodes: number;
  readonly maxObjectKeys: number;
  readonly maxArrayLength: number;
  readonly maxStringLength: number;
}

const DEFAULT_JSON_LIMITS: JsonValueLimits = Object.freeze({
  maxDepth: 8,
  maxNodes: 1024,
  maxObjectKeys: 128,
  maxArrayLength: 256,
  maxStringLength: 4096,
});

const JSON_LIMIT_CAPS: JsonValueLimits = Object.freeze({
  maxDepth: 64,
  maxNodes: 100_000,
  maxObjectKeys: 10_000,
  maxArrayLength: 10_000,
  maxStringLength: 1_000_000,
});

const JSON_LIMIT_KEYS = Object.freeze([
  "maxDepth",
  "maxNodes",
  "maxObjectKeys",
  "maxArrayLength",
  "maxStringLength",
] as const);

const ERR_INVALID_LIMITS = "ERR_INVALID_LIMITS";
const ERR_LIMIT_EXCEEDED = "ERR_LIMIT_EXCEEDED";
const ERR_INVALID_STRUCTURE = "ERR_INVALID_STRUCTURE";

type JsonParseInternal =
  | { readonly ok: true; readonly value: JsonValue }
  | { readonly ok: false; readonly error: string };

function safelyDetectArray(input: unknown): boolean | null {
  try {
    return Array.isArray(input);
  } catch {
    return null;
  }
}

function parseJsonLimits(input: unknown): ParseResult<JsonValueLimits> {
  if (input === undefined) {
    return { ok: true, value: DEFAULT_JSON_LIMITS };
  }
  const isArray = safelyDetectArray(input);
  if (isArray === null || typeof input !== "object" || input === null || isArray) {
    return { ok: false, error: ERR_INVALID_LIMITS };
  }

  try {
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) {
      return { ok: false, error: ERR_INVALID_LIMITS };
    }
    const keys = Reflect.ownKeys(input);
    if (
      keys.length !== JSON_LIMIT_KEYS.length ||
      keys.some((key) => typeof key !== "string" || !JSON_LIMIT_KEYS.includes(key as (typeof JSON_LIMIT_KEYS)[number]))
    ) {
      return { ok: false, error: ERR_INVALID_LIMITS };
    }

    const descriptors = Object.getOwnPropertyDescriptors(input);
    const parsed: Record<(typeof JSON_LIMIT_KEYS)[number], number> = {
      maxDepth: 0,
      maxNodes: 0,
      maxObjectKeys: 0,
      maxArrayLength: 0,
      maxStringLength: 0,
    };
    for (const key of JSON_LIMIT_KEYS) {
      const descriptor = descriptors[key];
      if (!descriptor || !("value" in descriptor)) {
        return { ok: false, error: ERR_INVALID_LIMITS };
      }
      const value = descriptor.value as unknown;
      if (
        typeof value !== "number" ||
        !Number.isSafeInteger(value) ||
        value <= 0 ||
        value > JSON_LIMIT_CAPS[key]
      ) {
        return { ok: false, error: ERR_INVALID_LIMITS };
      }
      parsed[key] = value;
    }
    return { ok: true, value: Object.freeze(parsed) };
  } catch {
    return { ok: false, error: ERR_INVALID_LIMITS };
  }
}

interface JsonParseContext {
  readonly limits: JsonValueLimits;
  readonly seen: WeakSet<object>;
  nodes: number;
}

function parseJsonNode(input: unknown, depth: number, context: JsonParseContext): JsonParseInternal {
  if (depth > context.limits.maxDepth) {
    return { ok: false, error: ERR_LIMIT_EXCEEDED };
  }
  context.nodes += 1;
  if (context.nodes > context.limits.maxNodes) {
    return { ok: false, error: ERR_LIMIT_EXCEEDED };
  }

  if (input === null || typeof input === "boolean") {
    return { ok: true, value: input };
  }
  if (typeof input === "number") {
    return Number.isFinite(input)
      ? { ok: true, value: input }
      : { ok: false, error: ERR_NON_FINITE };
  }
  if (typeof input === "string") {
    return input.length <= context.limits.maxStringLength
      ? { ok: true, value: input }
      : { ok: false, error: ERR_LIMIT_EXCEEDED };
  }
  if (typeof input !== "object" || input === null) {
    return { ok: false, error: ERR_INVALID_TYPE };
  }
  const isArray = safelyDetectArray(input);
  if (isArray === null) {
    return { ok: false, error: ERR_INVALID_STRUCTURE };
  }
  if (!isArray) {
    // --- plain object support ---

    // Prototype check via reflection.
    let proto: unknown | null;
    try {
      proto = Object.getPrototypeOf(input);
    } catch {
      return { ok: false, error: ERR_INVALID_TYPE };
    }
    if (proto !== Object.prototype && proto !== null) {
      return { ok: false, error: ERR_INVALID_TYPE };
    }

    // Own keys inspection.
    let ownKeysResult: PropertyKey[];
    try {
      ownKeysResult = Reflect.ownKeys(input);
    } catch {
      return { ok: false, error: ERR_INVALID_STRUCTURE };
    }

    // Filter to string-keyed own properties; reject symbol keys.
    const stringKeys: string[] = [];
    for (const key of ownKeysResult) {
      if (typeof key === "string") {
        stringKeys.push(key);
      } else {
        return { ok: false, error: ERR_INVALID_STRUCTURE };
      }
    }

    // maxObjectKeys enforcement at exact boundary.
    if (stringKeys.length > context.limits.maxObjectKeys) {
      return { ok: false, error: ERR_LIMIT_EXCEEDED };
    }

    // Descriptor inspection WITHOUT invoking getters.
    let descriptorsResult: Record<string | symbol, PropertyDescriptor>;
    try {
      descriptorsResult = Object.getOwnPropertyDescriptors(input);
    } catch {
      return { ok: false, error: ERR_INVALID_STRUCTURE };
    }

    // Key length check (maxStringLength on object keys).
    for (const key of stringKeys) {
      if (key.length > context.limits.maxStringLength) {
        return { ok: false, error: ERR_LIMIT_EXCEEDED };
      }
    }

    // Cycle detection via shared WeakSet.
    try {
      if (context.seen.has(input)) {
        return { ok: false, error: ERR_INVALID_STRUCTURE };
      }
      context.seen.add(input);
    } catch {
      return { ok: false, error: ERR_INVALID_STRUCTURE };
    }

    // Clone into Object.create(null), recursively parse children.
    const output = Object.create(null) as Record<string, JsonValue>;
    for (const key of stringKeys) {
      const descriptor = descriptorsResult[key];
      if (!descriptor || !("value" in descriptor)) {
        return { ok: false, error: ERR_INVALID_STRUCTURE };
      }
      const child = parseJsonNode(descriptor.value as unknown, depth + 1, context);
      if (!child.ok) {
        return child;
      }
      output[key] = child.value;
    }

    // Freeze result.
    try {
      Object.freeze(output);
    } catch {
      return { ok: false, error: ERR_INVALID_STRUCTURE };
    }

    return { ok: true, value: output as JsonObject };
  }

  const arrayInput = input as unknown[];
  try {
    if (context.seen.has(arrayInput)) {
      return { ok: false, error: ERR_INVALID_STRUCTURE };
    }
    context.seen.add(arrayInput);

    const keys = Reflect.ownKeys(arrayInput);
    const descriptors = Object.getOwnPropertyDescriptors(arrayInput);
    const lengthDescriptor: PropertyDescriptor | undefined = Object.getOwnPropertyDescriptor(arrayInput, "length");
    if (!lengthDescriptor || !Object.prototype.hasOwnProperty.call(lengthDescriptor, "value")) {
      return { ok: false, error: ERR_INVALID_STRUCTURE };
    }
    const length = lengthDescriptor.value as unknown;
    if (!Number.isSafeInteger(length) || (length as number) < 0) {
      return { ok: false, error: ERR_INVALID_STRUCTURE };
    }
    if ((length as number) > context.limits.maxArrayLength) {
      return { ok: false, error: ERR_LIMIT_EXCEEDED };
    }
    if (keys.some((key) => typeof key !== "string" || (key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key)))) {
      return { ok: false, error: ERR_INVALID_STRUCTURE };
    }

    const output: JsonValue[] = [];
    for (let index = 0; index < (length as number); index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !("value" in descriptor)) {
        return { ok: false, error: ERR_INVALID_STRUCTURE };
      }
      const child = parseJsonNode(descriptor.value as unknown, depth + 1, context);
      if (!child.ok) {
        return child;
      }
      output.push(child.value);
    }
    return { ok: true, value: Object.freeze(output) };
  } catch {
    return { ok: false, error: ERR_INVALID_STRUCTURE };
  }
}

/** Parse a bounded JSON value into an immutable, detached value. */
export function parseJsonValue(input: unknown, limitsInput?: unknown): ParseResult<JsonValue> {
  const limits = parseJsonLimits(limitsInput);
  if (!limits.ok) {
    return limits;
  }
  return parseJsonNode(input, 0, { limits: limits.value, seen: new WeakSet<object>(), nodes: 0 });
}


// ---------------------------------------------------------------------------
// Strict request envelopes
// ---------------------------------------------------------------------------

declare const brandProtocolMessageType: unique symbol;
export type ProtocolMessageType = string & { readonly __brand: typeof brandProtocolMessageType };

const PROTOCOL_MESSAGE_TYPE_PATTERN = /^[A-Za-z][A-Za-z0-9]*(?:[._:-][A-Za-z0-9]+)*$/;
const REQUEST_REQUIRED_KEYS = Object.freeze([
  "protocolVersion", "messageType", "requestId", "sentAt", "payload",
] as const);
const REQUEST_ALLOWED_KEYS = new Set<string>([...REQUEST_REQUIRED_KEYS, "correlationId"]);

const ERR_ENVELOPE = "ERR_ENVELOPE";
const ERR_ENVELOPE_VERSION = "ERR_ENVELOPE_VERSION";
const ERR_ENVELOPE_MESSAGE_TYPE = "ERR_ENVELOPE_MESSAGE_TYPE";
const ERR_ENVELOPE_REQUEST_ID = "ERR_ENVELOPE_REQUEST_ID";
const ERR_ENVELOPE_CORRELATION_ID = "ERR_ENVELOPE_CORRELATION_ID";
const ERR_ENVELOPE_SENT_AT = "ERR_ENVELOPE_SENT_AT";
const ERR_ENVELOPE_PAYLOAD = "ERR_ENVELOPE_PAYLOAD";
const ERR_ENVELOPE_OK = "ERR_ENVELOPE_OK";
const ERR_ENVELOPE_RESULT = "ERR_ENVELOPE_RESULT";

export function parseProtocolMessageType(input: unknown): ParseResult<ProtocolMessageType> {
  if (typeof input !== "string") return { ok: false, error: ERR_INVALID_TYPE };
  if (input.length < 1 || input.length > 128) return { ok: false, error: ERR_INVALID_LENGTH };
  return PROTOCOL_MESSAGE_TYPE_PATTERN.test(input)
    ? { ok: true, value: input as ProtocolMessageType }
    : { ok: false, error: ERR_INVALID_FORMAT };
}

export interface ProtocolRequest<T extends JsonValue = JsonValue> {
  readonly protocolVersion: ProtocolVersion;
  readonly messageType: ProtocolMessageType;
  readonly requestId: RequestId;
  readonly correlationId?: CorrelationId;
  readonly sentAt: UtcTimestamp;
  readonly payload: T;
}

export interface ProtocolSuccessResponse<T extends JsonValue = JsonValue> {
  readonly protocolVersion: ProtocolVersion;
  readonly messageType: ProtocolMessageType;
  readonly requestId: RequestId;
  readonly sentAt: UtcTimestamp;
  readonly ok: true;
  readonly result: T;
}

function requestDescriptors(input: unknown): ParseResult<Record<string, PropertyDescriptor>> {
  if (typeof input !== "object" || input === null) return { ok: false, error: ERR_ENVELOPE };
  try {
    if (Array.isArray(input)) return { ok: false, error: ERR_ENVELOPE };
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) {
      return { ok: false, error: ERR_ENVELOPE };
    }
    const keys = Reflect.ownKeys(input);
    if (keys.some((key) => typeof key !== "string" || !REQUEST_ALLOWED_KEYS.has(key))) {
      return { ok: false, error: ERR_ENVELOPE };
    }
    if (REQUEST_REQUIRED_KEYS.some((key) => !keys.includes(key))) {
      return { ok: false, error: ERR_ENVELOPE };
    }
    const descriptors = Object.getOwnPropertyDescriptors(input);
    if (keys.some((key) => typeof key !== "string" || !descriptors[key] || !("value" in descriptors[key]))) {
      return { ok: false, error: ERR_ENVELOPE };
    }
    return { ok: true, value: descriptors };
  } catch {
    return { ok: false, error: ERR_ENVELOPE };
  }
}

/** Parse, detach, and freeze a strict protocol request envelope. */
export function parseProtocolRequest(input: unknown): ParseResult<ProtocolRequest> {
  const parsedDescriptors = requestDescriptors(input);
  if (!parsedDescriptors.ok) return parsedDescriptors;
  const descriptors = parsedDescriptors.value;

  const version = parseProtocolVersion(descriptors.protocolVersion?.value as unknown);
  if (!version.ok || !isProtocolVersionCompatible(CURRENT_PROTOCOL_VERSION, version.value)) {
    return { ok: false, error: ERR_ENVELOPE_VERSION };
  }
  const messageType = parseProtocolMessageType(descriptors.messageType?.value as unknown);
  if (!messageType.ok) return { ok: false, error: ERR_ENVELOPE_MESSAGE_TYPE };
  const requestId = parseProtocolId("request", descriptors.requestId?.value as unknown);
  if (!requestId.ok) return { ok: false, error: ERR_ENVELOPE_REQUEST_ID };
  const sentAt = parseUtcTimestamp(descriptors.sentAt?.value as unknown);
  if (!sentAt.ok) return { ok: false, error: ERR_ENVELOPE_SENT_AT };
  const payload = parseJsonValue(descriptors.payload?.value as unknown);
  if (!payload.ok) return { ok: false, error: ERR_ENVELOPE_PAYLOAD };

  let correlationId: CorrelationId | undefined;
  if (Object.prototype.hasOwnProperty.call(descriptors, "correlationId")) {
    const parsed = parseProtocolId("correlation", descriptors.correlationId?.value as unknown);
    if (!parsed.ok) return { ok: false, error: ERR_ENVELOPE_CORRELATION_ID };
    correlationId = parsed.value;
  }

  const output = Object.create(null) as Record<string, unknown>;
  output.protocolVersion = version.value;
  output.messageType = messageType.value;
  output.requestId = requestId.value;
  if (correlationId !== undefined) output.correlationId = correlationId;
  output.sentAt = sentAt.value;
  output.payload = payload.value;
  return { ok: true, value: Object.freeze(output) as unknown as ProtocolRequest };
}

// ---------------------------------------------------------------------------
// Strict success responses
// ---------------------------------------------------------------------------

const SUCCESS_RESPONSE_REQUIRED_KEYS = Object.freeze([
  "protocolVersion", "messageType", "requestId", "sentAt", "ok", "result",
] as const);

function successResponseDescriptors(input: unknown): ParseResult<Record<string, PropertyDescriptor>> {
  if (typeof input !== "object" || input === null) return { ok: false, error: ERR_ENVELOPE };
  try {
    if (Array.isArray(input)) return { ok: false, error: ERR_ENVELOPE };
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) {
      return { ok: false, error: ERR_ENVELOPE };
    }
    const keys = Reflect.ownKeys(input);
    if (keys.some((key) => typeof key !== "string" || !SUCCESS_RESPONSE_REQUIRED_KEYS.includes(key as (typeof SUCCESS_RESPONSE_REQUIRED_KEYS)[number]))) {
      return { ok: false, error: ERR_ENVELOPE };
    }
    if (!SUCCESS_RESPONSE_REQUIRED_KEYS.every((key) => keys.includes(key))) {
      return { ok: false, error: ERR_ENVELOPE };
    }
    const descriptors = Object.getOwnPropertyDescriptors(input);
    if (keys.some((key) => typeof key !== "string" || !descriptors[key] || !("value" in descriptors[key]))) {
      return { ok: false, error: ERR_ENVELOPE };
    }
    return { ok: true, value: descriptors };
  } catch {
    return { ok: false, error: ERR_ENVELOPE };
  }
}

/** Parse, detach, and freeze a strict protocol success response. */
export function parseProtocolSuccessResponse(input: unknown): ParseResult<ProtocolSuccessResponse> {
  const parsedDescriptors = successResponseDescriptors(input);
  if (!parsedDescriptors.ok) return parsedDescriptors;
  const descriptors = parsedDescriptors.value;

  const version = parseProtocolVersion(descriptors.protocolVersion?.value as unknown);
  if (!version.ok || !isProtocolVersionCompatible(CURRENT_PROTOCOL_VERSION, version.value)) {
    return { ok: false, error: ERR_ENVELOPE_VERSION };
  }
  const messageType = parseProtocolMessageType(descriptors.messageType?.value as unknown);
  if (!messageType.ok) return { ok: false, error: ERR_ENVELOPE_MESSAGE_TYPE };
  const requestId = parseProtocolId("request", descriptors.requestId?.value as unknown);
  if (!requestId.ok) return { ok: false, error: ERR_ENVELOPE_REQUEST_ID };
  const sentAt = parseUtcTimestamp(descriptors.sentAt?.value as unknown);
  if (!sentAt.ok) return { ok: false, error: ERR_ENVELOPE_SENT_AT };

  // ok must be literal boolean true — no coercion.
  const okValue = descriptors.ok?.value;
  if (typeof okValue !== "boolean" || okValue !== true) {
    return { ok: false, error: ERR_ENVELOPE_OK };
  }

  const result = parseJsonValue(descriptors.result?.value as unknown);
  if (!result.ok) return { ok: false, error: ERR_ENVELOPE_RESULT };

  const output = Object.create(null) as Record<string, unknown>;
  output.protocolVersion = version.value;
  output.messageType = messageType.value;
  output.requestId = requestId.value;
  output.sentAt = sentAt.value;
  output.ok = true;
  output.result = result.value;
  return { ok: true, value: Object.freeze(output) as unknown as ProtocolSuccessResponse };
}

// ---------------------------------------------------------------------------
// Bounded public errors and strict error responses
// ---------------------------------------------------------------------------

declare const brandErrorCode: unique symbol;
export type ErrorCode = string & { readonly __brand: typeof brandErrorCode };

const ERROR_CODE_PATTERN = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/;
const PUBLIC_ERROR_REQUIRED_KEYS = Object.freeze(["code", "message", "retryable"] as const);
const PUBLIC_ERROR_ALLOWED_KEYS = new Set<string>([...PUBLIC_ERROR_REQUIRED_KEYS, "details"]);
const ERROR_RESPONSE_KEYS = Object.freeze([
  "protocolVersion", "messageType", "requestId", "sentAt", "ok", "error",
] as const);

const ERR_PUBLIC_ERROR_CODE = "ERR_PUBLIC_ERROR_CODE";
const ERR_PUBLIC_ERROR_MESSAGE = "ERR_PUBLIC_ERROR_MESSAGE";
const ERR_PUBLIC_ERROR_RETRYABLE = "ERR_PUBLIC_ERROR_RETRYABLE";
const ERR_PUBLIC_ERROR_DETAILS = "ERR_PUBLIC_ERROR_DETAILS";
const ERR_ERROR_RESPONSE_VERSION = "ERR_ERROR_RESPONSE_VERSION";
const ERR_ERROR_RESPONSE_MESSAGE_TYPE = "ERR_ERROR_RESPONSE_MESSAGE_TYPE";
const ERR_ERROR_RESPONSE_REQUEST_ID = "ERR_ERROR_RESPONSE_REQUEST_ID";
const ERR_ERROR_RESPONSE_SENT_AT = "ERR_ERROR_RESPONSE_SENT_AT";
const ERR_ERROR_RESPONSE_OK = "ERR_ERROR_RESPONSE_OK";
const ERR_ERROR_RESPONSE_ERROR = "ERR_ERROR_RESPONSE_ERROR";

export function parseErrorCode(input: unknown): ParseResult<ErrorCode> {
  if (typeof input !== "string") return { ok: false, error: ERR_INVALID_TYPE };
  if (input.length < 1 || input.length > 64) return { ok: false, error: ERR_INVALID_LENGTH };
  return ERROR_CODE_PATTERN.test(input)
    ? { ok: true, value: input as ErrorCode }
    : { ok: false, error: ERR_INVALID_FORMAT };
}

export interface ProtocolPublicError {
  readonly code: ErrorCode;
  readonly message: string;
  readonly retryable: boolean;
  readonly details?: JsonValue;
}

function exactDataDescriptors(
  input: unknown,
  required: readonly string[],
  allowed: ReadonlySet<string>,
): ParseResult<Record<string, PropertyDescriptor>> {
  if (typeof input !== "object" || input === null) return { ok: false, error: ERR_ENVELOPE };
  try {
    if (Array.isArray(input)) return { ok: false, error: ERR_ENVELOPE };
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) return { ok: false, error: ERR_ENVELOPE };
    const keys = Reflect.ownKeys(input);
    if (keys.some((key) => typeof key !== "string" || !allowed.has(key))) {
      return { ok: false, error: ERR_EXTRA_KEY };
    }
    if (required.some((key) => !keys.includes(key))) return { ok: false, error: ERR_MISSING_KEY };
    const descriptors = Object.getOwnPropertyDescriptors(input);
    if (keys.some((key) => typeof key !== "string" || !descriptors[key] || !("value" in descriptors[key]))) {
      return { ok: false, error: ERR_ENVELOPE };
    }
    return { ok: true, value: descriptors };
  } catch {
    return { ok: false, error: ERR_ENVELOPE };
  }
}

export function parseProtocolPublicError(input: unknown): ParseResult<ProtocolPublicError> {
  const descriptorsResult = exactDataDescriptors(input, PUBLIC_ERROR_REQUIRED_KEYS, PUBLIC_ERROR_ALLOWED_KEYS);
  if (!descriptorsResult.ok) return descriptorsResult;
  const descriptors = descriptorsResult.value;

  const code = parseErrorCode(descriptors.code?.value as unknown);
  if (!code.ok) return { ok: false, error: ERR_PUBLIC_ERROR_CODE };
  const message = descriptors.message?.value as unknown;
  if (
    typeof message !== "string" ||
    message.length < 1 ||
    message.length > 1024 ||
    /[\u0000-\u001f\u007f]/.test(message)
  ) {
    return { ok: false, error: ERR_PUBLIC_ERROR_MESSAGE };
  }
  const retryable = descriptors.retryable?.value as unknown;
  if (typeof retryable !== "boolean") return { ok: false, error: ERR_PUBLIC_ERROR_RETRYABLE };

  let details: JsonValue | undefined;
  if (Object.prototype.hasOwnProperty.call(descriptors, "details")) {
    const parsed = parseJsonValue(descriptors.details?.value as unknown);
    if (!parsed.ok) return { ok: false, error: ERR_PUBLIC_ERROR_DETAILS };
    details = parsed.value;
  }

  const output = Object.create(null) as Record<string, unknown>;
  output.code = code.value;
  output.message = message;
  output.retryable = retryable;
  if (details !== undefined) output.details = details;
  return { ok: true, value: Object.freeze(output) as unknown as ProtocolPublicError };
}

export interface ProtocolErrorResponse {
  readonly protocolVersion: ProtocolVersion;
  readonly messageType: ProtocolMessageType;
  readonly requestId: RequestId;
  readonly sentAt: UtcTimestamp;
  readonly ok: false;
  readonly error: ProtocolPublicError;
}

export function parseProtocolErrorResponse(input: unknown): ParseResult<ProtocolErrorResponse> {
  const allowed = new Set<string>(ERROR_RESPONSE_KEYS);
  const descriptorsResult = exactDataDescriptors(input, ERROR_RESPONSE_KEYS, allowed);
  if (!descriptorsResult.ok) return descriptorsResult;
  const descriptors = descriptorsResult.value;

  const version = parseProtocolVersion(descriptors.protocolVersion?.value as unknown);
  if (!version.ok || !isProtocolVersionCompatible(CURRENT_PROTOCOL_VERSION, version.value)) {
    return { ok: false, error: ERR_ERROR_RESPONSE_VERSION };
  }
  const messageType = parseProtocolMessageType(descriptors.messageType?.value as unknown);
  if (!messageType.ok) return { ok: false, error: ERR_ERROR_RESPONSE_MESSAGE_TYPE };
  const requestId = parseProtocolId("request", descriptors.requestId?.value as unknown);
  if (!requestId.ok) return { ok: false, error: ERR_ERROR_RESPONSE_REQUEST_ID };
  const sentAt = parseUtcTimestamp(descriptors.sentAt?.value as unknown);
  if (!sentAt.ok) return { ok: false, error: ERR_ERROR_RESPONSE_SENT_AT };
  if (descriptors.ok?.value !== false) return { ok: false, error: ERR_ERROR_RESPONSE_OK };
  const error = parseProtocolPublicError(descriptors.error?.value as unknown);
  if (!error.ok) return { ok: false, error: ERR_ERROR_RESPONSE_ERROR };

  const output = Object.create(null) as Record<string, unknown>;
  output.protocolVersion = version.value;
  output.messageType = messageType.value;
  output.requestId = requestId.value;
  output.sentAt = sentAt.value;
  output.ok = false;
  output.error = error.value;
  return { ok: true, value: Object.freeze(output) as unknown as ProtocolErrorResponse };
}
