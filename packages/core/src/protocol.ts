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

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;

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
