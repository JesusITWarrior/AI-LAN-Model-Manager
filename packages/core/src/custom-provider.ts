/**
 * Strict, bounded custom provider manifest schema and parser.
 *
 * This unit is DATA ONLY. It never executes anything, resolves paths, touches
 * the filesystem or network, spawns processes, interpolates templates, or adds
 * adapter behaviour. It parses and validates a declarative manifest describing a
 * provider and a bounded set of supported action templates, then returns a
 * fully detached, deeply frozen, normalised value.
 *
 * Boundary functions are non-throwing. Every failure is reported through the
 * single stable machine-code error {@link ERR_CUSTOM_PROVIDER_MANIFEST} — never
 * an echo of untrusted input, and never a thrown exception.
 */

import { posix, win32 } from "node:path";
import { parseByteAmount, type ByteAmount } from "./observations.js";
import type { ParseResult } from "./protocol.js";

/** The only stable machine code this module emits. */
export const ERR_CUSTOM_PROVIDER_MANIFEST = "ERR_CUSTOM_PROVIDER_MANIFEST";

/** Declarative schema version. Now the only accepted value. */
export const CUSTOM_PROVIDER_SCHEMA_VERSION = 1;

/** Total number of supported action templates. */
export const MAX_ACTIONS = 16;
/** Entries permitted in a single action's argv template. */
export const MAX_ARGV_ENTRIES = 8;
/** Byte length of a single argv entry. */
export const MAX_ARGV_ENTRY_LENGTH = 100;
/** Byte length of an exact executable path. */
export const MAX_EXECUTABLE_LENGTH = 200;
/** Entries permitted in an action's explicit environment map. */
export const MAX_ENV_ENTRIES = 8;
/** Byte length of a single environment variable name. */
export const MAX_ENV_NAME_LENGTH = 32;
/** Byte length of a single environment variable value. */
export const MAX_ENV_VALUE_LENGTH = 100;
/** Milliseconds permitted for an action's timeout. */
export const MAX_TIMEOUT_MS = 60_000;
/** Output bytes permitted for an action. */
export const MAX_OUTPUT_BYTES = 1_048_576;
/** Aggregate size budget for the whole manifest, in bytes. */
export const MAX_MANIFEST_SIZE_BYTES = 20_000;
/** Per-action structural overhead folded into the aggregate size budget. */
export const MAX_ITEM_OVERHEAD_BYTES = 64;

export type CustomProviderKind = "host" | "inference" | "management" | "artifact";

/** One supported action template: an exact executable plus validated parts. */
export interface CustomActionTemplate {
  /** Bounded, identifier-form action name. */
  readonly actionId: string;
  /** Exact, absolute executable path; no shell, no interpolation. */
  readonly executable: string;
  /** Bounded argv template: exact string entries, no shell metacharacters. */
  readonly argv: readonly string[];
  /** Explicit environment map: strict names and safe values. */
  readonly env: Readonly<Record<string, string>>;
  /** Positive, bounded timeout in milliseconds. */
  readonly timeoutMs: ByteAmount;
  /** Positive, bounded output in bytes. */
  readonly maxOutputBytes: ByteAmount;
}

/** A versioned, bounded provider manifest describing supported actions. */
export interface CustomProviderManifest {
  /** Fixed schema version. */
  readonly schemaVersion: 1;
  /** Bounded provider identifier. */
  readonly providerId: string;
  /** Provider kind: a small closed enum. */
  readonly kind: CustomProviderKind;
  /** Bounded set of supported action templates. */
  readonly actions: readonly CustomActionTemplate[];
}

/** Result of {@link parseCustomProviderManifest}. */
export type ParseCustomProviderManifestResult = ParseResult<CustomProviderManifest>;

/** Result of parsing the top-level manifest actions field. */
export type ParseActionsResult =
  | { readonly ok: true; readonly value: { readonly actions: CustomActionTemplate[]; readonly estimatedSize: number } }
  | { readonly ok: false; readonly error: string };

/** Result of parsing a single action template. */
export type ParseActionResult =
  | { readonly ok: true; readonly value: { readonly action: CustomActionTemplate; readonly estimatedSize: number } }
  | { readonly ok: false; readonly error: string };

/** Result of parsing an argv template. */
export type ParseArgvResult =
  | { readonly ok: true; readonly value: { readonly entries: string[]; readonly size: number } }
  | { readonly ok: false; readonly error: string };

/** Result of parsing an environment map. */
export type ParseEnvResult =
  | { readonly ok: true; readonly value: { readonly map: Record<string, string>; readonly size: number } }
  | { readonly ok: false; readonly error: string };

/** Result of parsing a positive bounded numeric limit. */
export type ParseBoundedResult =
  | { readonly ok: true; readonly value: ByteAmount }
  | { readonly ok: false; readonly error: string };

const fail = <T>(error: string): ParseResult<T> => ({ ok: false, error });

// --- Identifier / kind patterns -------------------------------------------

// Branded opaque IDs reuse the repository-wide idiom: `^[A-Za-z0-9][A-Za-z0-9._:-]*$`.
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
// Standard environment variable names: uppercase, digits, underscore.
const ENV_NAME_PATTERN = /^[A-Z][A-Z0-9_]*$/;

// Control characters and shell / interpolation / substitution metacharacters.
const CONTROL_SHELL = /[\x00-\x1f\x7f;|&`<>(){}\[\]\\'"$]/;
// As above but also whitespace (paths never legitimately contain spaces).
const PATH_META = /[\x00-\x1f\x7f;|&`<>(){}\[\]\\'"$ ]/;

// --- Sensitive-public-value filters ----------------------------------------

// Credential / secret tokens (case-insensitive substring match).
const CRED_TOKEN =
  /(?:pass(word|wd)?|passwd|pwd|secret|token|api[-_]?key|access[-_]?key|secret[-_]?key|private[-_]?key|authori[sz]ation|bearer|credential|login|username)/i;
// Endpoint forms: scheme-qualified URLs, embedded userinfo, network schemes.
const URL_FORM = /:\/\/|@|^(?:https?|wss?|ftp|file|data|javascript|ldap|ws|gopher):/i;
// Local area network destinations: names, loopback, and private ranges.
const LAN_TOKEN =
  /localhost|\.local|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|169\.254\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|::1|\[::1\]|fe80::|fd:/;

/**
 * Return true when a string is an endpoint, URL, credential, token, secret, or
 * a LAN address. Public manifest values must never contain any of these.
 */
function isSensitivePublicValue(value: string): boolean {
  return CRED_TOKEN.test(value) || URL_FORM.test(value) || LAN_TOKEN.test(value);
}

// --- Reflection helpers ----------------------------------------------------

/**
 * Inspect an untrusted value's own, data-only properties without ever invoking
 * a getter. Returns descriptors keyed by the required string keys, or null on
 * any structural deviation: non-object, custom prototype, symbol keys,
 * extra/missing keys, accessor descriptors, or a throwing (revoked) Proxy.
 */
function exactKeys(
  input: unknown,
  keys: readonly string[],
): { readonly ok: true; readonly value: Record<string, PropertyDescriptor> } | { readonly ok: false; readonly error: string } {
  try {
    if (typeof input !== "object" || input === null || Array.isArray(input)) {
      return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
    }
    // Custom prototypes (including inherited accessors) are rejected outright.
    const proto = Object.getPrototypeOf(input);
    if (proto !== Object.prototype && proto !== null) {
      return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
    }
    const own = Reflect.ownKeys(input);
    if (own.length !== keys.length) {
      return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
    }
    for (const key of own) {
      if (typeof key !== "string" || !keys.includes(key)) {
        return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
      }
    }
    const descriptors = Object.getOwnPropertyDescriptors(input);
    // Require a plain `value` for every key: accessor descriptors (getters/set)
    // have no `value` key, so they are rejected WITHOUT being invoked.
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!descriptor || !("value" in descriptor)) {
        return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
      }
    }
    return { ok: true, value: descriptors };
  } catch {
    // A revoked or hostile Proxy throws when inspected. Fail closed.
    return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
  }
}

// --- Field parsers ---------------------------------------------------------

/** Parse a bounded opaque identifier (1..128 chars, id form). */
function parseId(value: unknown): string | null {
  if (typeof value !== "string") return null;
  if (value.length < 1 || value.length > 128) return null;
  if (!ID_PATTERN.test(value)) return null;
  if (isSensitivePublicValue(value)) return null;
  return value;
}

/** Parse a provider kind against the closed enum. */
function parseKind(value: unknown): CustomProviderKind | null {
  if (
    value === "host" ||
    value === "inference" ||
    value === "management" ||
    value === "artifact"
  ) {
    return value as CustomProviderKind;
  }
  return null;
}

/**
 * Parse an exact executable path: absolute (leading `/`), free of shell,
 * control, and whitespace metacharacters, parent traversal (`..`),
 // doubled slashes, and any endpoint, credential, or LAN token.
 */
function parseExecutable(value: unknown): string | null {
  if (typeof value !== "string" || value.length < 1 || Buffer.byteLength(value) > MAX_EXECUTABLE_LENGTH) return null;
  if (CONTROL_SHELL.test(value.replaceAll("\\", "")) || /[\x00-\x1f\x7f]/.test(value) || isSensitivePublicValue(value)) return null;
  if (value.startsWith("/")) {
    if (value.includes("\\") || posix.normalize(value) !== value || value === "/" || value.endsWith("/") || value.includes("//")) return null;
    return value.split("/").some(part => part === "." || part === "..") ? null : value;
  }
  if (!/^[A-Za-z]:\\/.test(value) || value.includes("/") || value.startsWith("\\\\") || win32.normalize(value) !== value || value.endsWith("\\")) return null;
  const parts = value.slice(3).split("\\");
  if (parts.some(part => !part || part === "." || part === ".." || /[<>:"|?*]/.test(part) || /[. ]$/.test(part) || /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$/i.test(part))) return null;
  return value;
}

/** Parse a single argv entry (no shell/control metacharacters). */
function parseArgEntry(value: unknown): string | null {
  if (typeof value !== "string") return null;
  if (value.length < 1 || value.length > MAX_ARGV_ENTRY_LENGTH) return null;
  if (CONTROL_SHELL.test(value)) return null;
  if (isSensitivePublicValue(value)) return null;
  return value;
}

/** Parse an environment variable name (strict uppercase form). */
function parseEnvName(name: string): boolean {
  return name.length >= 1 && name.length <= MAX_ENV_NAME_LENGTH && ENV_NAME_PATTERN.test(name);
}

/** Parse a safe environment variable value. */
function parseEnvValue(value: unknown): string | null {
  if (typeof value !== "string") return null;
  if (value.length < 1 || value.length > MAX_ENV_VALUE_LENGTH) return null;
  if (CONTROL_SHELL.test(value)) return null;
  if (isSensitivePublicValue(value)) return null;
  return value;
}

/** Parse a positive, bounded numeric limit in `[1, max]`. */
function parsePositiveBounded(value: unknown, max: number): ParseBoundedResult {
  const parsed = parseByteAmount(value);
  if (!parsed.ok) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
  if (parsed.value < 1 || parsed.value > max) {
    return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
  }
  return { ok: true, value: parsed.value };
}

function parseArgv(value: unknown): ParseArgvResult {
  try {
    if (!Array.isArray(value)) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
    const length = value.length;
    if (!Number.isSafeInteger(length) || length > MAX_ARGV_ENTRIES) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
    const descriptors = Object.getOwnPropertyDescriptors(value), own = Reflect.ownKeys(value);
    if (own.length !== length + 1 || !own.includes("length")) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
    const entries: string[] = [];
    let size = 0;
    for (let index = 0; index < length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !("value" in descriptor)) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
      const parsed = parseArgEntry(descriptor.value);
      if (parsed === null) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
      size += Buffer.byteLength(parsed);
      entries.push(parsed);
    }
    return { ok: true, value: { entries, size } };
  } catch { return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST }; }
}

function parseEnv(value: unknown): ParseEnvResult {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
    const keys = Reflect.ownKeys(value);
    if (keys.length > MAX_ENV_ENTRIES || keys.some(key => typeof key !== "string")) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
    const descriptors = Object.getOwnPropertyDescriptors(value), map: Record<string, string> = Object.create(null);
    let size = 0;
    for (const name of keys as string[]) {
      const descriptor = descriptors[name];
      if (!descriptor || !("value" in descriptor) || !parseEnvName(name)) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
      const parsed = parseEnvValue(descriptor.value);
      if (parsed === null) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
      size += Buffer.byteLength(name) + Buffer.byteLength(parsed);
      map[name] = parsed;
    }
    return { ok: true, value: { map, size } };
  } catch { return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST }; }
}

function parseAction(value: unknown): ParseActionResult {
  const d = exactKeys(value, ["actionId", "executable", "argv", "env", "timeoutMs", "maxOutputBytes"]);
  if (!d.ok) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
  const fields = d.value;

  const actionId = parseId(fields.actionId!.value);
  if (actionId === null) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
  const executable = parseExecutable(fields.executable!.value);
  if (executable === null) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
  const argv = parseArgv(fields.argv!.value);
  if (!argv.ok) return argv;
  const env = parseEnv(fields.env!.value);
  if (!env.ok) return env;
  const timeout = parsePositiveBounded(fields.timeoutMs!.value, MAX_TIMEOUT_MS);
  if (!timeout.ok) return timeout;
  const output = parsePositiveBounded(fields.maxOutputBytes!.value, MAX_OUTPUT_BYTES);
  if (!output.ok) return output;

  const estimatedSize =
    MAX_ITEM_OVERHEAD_BYTES +
    Buffer.byteLength(actionId) +
    Buffer.byteLength(executable) +
    argv.value.size +
    env.value.size;
  const action: CustomActionTemplate = {
    actionId,
    executable,
    argv: argv.value.entries,
    env: env.value.map,
    timeoutMs: timeout.value,
    maxOutputBytes: output.value,
  };
  return { ok: true, value: { action, estimatedSize } };
}

function parseActions(value: unknown): ParseActionsResult {
  try {
    if (!Array.isArray(value)) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
    const length = value.length;
    if (!Number.isSafeInteger(length) || length < 1 || length > MAX_ACTIONS) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
    const descriptors = Object.getOwnPropertyDescriptors(value), own = Reflect.ownKeys(value);
    if (own.length !== length + 1 || !own.includes("length")) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
    const actions: CustomActionTemplate[] = [], ids = new Set<string>();
    let estimatedSize = 0;
    for (let index = 0; index < length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !("value" in descriptor)) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
      const parsed = parseAction(descriptor.value);
      if (!parsed.ok || ids.has(parsed.value.action.actionId)) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
      ids.add(parsed.value.action.actionId);
      estimatedSize += parsed.value.estimatedSize;
      actions.push(parsed.value.action);
    }
    return { ok: true, value: { actions, estimatedSize } };
  } catch { return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST }; }
}

/**
 * Recursively clone an already-normalised value into null-prototype / frozen
 * structures so that no caller-owned nested reference stays mutable. Primitives
 * are immutable and pass through; arrays and objects are freshly cloned and
 * frozen.
 */
function detach(value: unknown): unknown {
  if (value === null) return null;
  const type = typeof value;
  if (type === "string" || type === "number" || type === "boolean") {
    return value;
  }
  if (Array.isArray(value)) {
    return Object.freeze(value.map((entry) => detach(entry)));
  }
  const record = value as Record<string, unknown>;
  const output: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(record)) {
    if (typeof key === "string") {
      output[key] = detach(record[key]);
    }
  }
  return Object.freeze(output);
}

/**
 * Parse, validate, detach, and deeply freeze a strict custom provider manifest.
 *
 * Fails closed on any structural deviation (unknown/missing/symbol keys, custom
 * prototypes, accessor descriptors, arrays where objects are expected, hostile
 * or revoked Proxies) and on any invalid bounded field. Succeeds only with a
 * fully normalised, detached, frozen value.
 */
export function parseCustomProviderManifest(input: unknown): ParseCustomProviderManifestResult {
  try {
  const d = exactKeys(input, ["schemaVersion", "providerId", "kind", "actions"]);
  if (!d.ok) return { ok: false, error: ERR_CUSTOM_PROVIDER_MANIFEST };
  const fields = d.value;

  if (fields.schemaVersion!.value !== CUSTOM_PROVIDER_SCHEMA_VERSION) {
    return fail(ERR_CUSTOM_PROVIDER_MANIFEST);
  }
  const providerId = parseId(fields.providerId!.value);
  if (providerId === null) return fail(ERR_CUSTOM_PROVIDER_MANIFEST);
  const kind = parseKind(fields.kind!.value);
  if (kind === null) return fail(ERR_CUSTOM_PROVIDER_MANIFEST);

  const actions = parseActions(fields.actions!.value);
  if (!actions.ok) return actions;

  // Enforce an aggregate size budget WITHOUT serialising untrusted input: sum
  // measured string byte lengths plus folded structural overhead.
  const estimatedTotal =
    MAX_ITEM_OVERHEAD_BYTES +
    Buffer.byteLength(providerId) +
    Buffer.byteLength(kind) +
    actions.value.estimatedSize;
  if (estimatedTotal > MAX_MANIFEST_SIZE_BYTES) {
    return fail(ERR_CUSTOM_PROVIDER_MANIFEST);
  }

  const output: Record<string, unknown> = {
    schemaVersion: CUSTOM_PROVIDER_SCHEMA_VERSION,
    providerId,
    kind,
    actions: actions.value.actions,
  };
  return { ok: true, value: detach(output) as unknown as CustomProviderManifest };
  } catch { return fail(ERR_CUSTOM_PROVIDER_MANIFEST); }
}
