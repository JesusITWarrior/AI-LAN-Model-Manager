/**
 * Capability profile schema and deterministic, explainable model matching.
 *
 * Two strict, bounded, immutable DTOs are defined here:
 *   - {@link CapabilityProfile}: what the caller requires (hard, preference, unknown).
 *   - {@link ObservedModelCapability}: what an observed model actually is.
 *
 * Matching is a pure, non-throwing function: every failure is a stable, redacted
 * machine-code string, never an echo of untrusted input and never exposing topology
 * (no host IDs, endpoints, provider values, model names, or resource numbers).
 *
 * Guarantees:
 *   - Deterministic: identical inputs yield identical outputs (reason codes in a
 *     fixed canonical order; deterministic preference scoring and tie-breaks).
 *   - Explainable: redacted hard-failure codes describe exactly which requirement(s)
 *     were not satisfied.
 *   - Fail-closed: malformed requests, stale observations, or observed unknowns never
 *     match when a required dimension cannot be verified.
 *   - Hard vs. preference: only the request marks a dimension "hard"; preferences
 *     rank candidates but never block a match.
 *
 * The observed capability is intentionally decoupled from {@link InstalledModelObservation}
 * / {@link ModelCapability} so a capability request never leaks, depends on, or is
 * reordered by fleet topology. The two DTOs share parsers (`parseByteAmount`,
 * `parseUtcTimestamp`) to stay consistent without leaking their shapes.
 */

import { parseByteAmount, type ByteAmount } from "./observations.js";
import { parseUtcTimestamp, type ParseResult, type UtcTimestamp } from "./protocol.js";
import { parseModelCapability, type ModelCapability } from "./model-observations.js";
import type { ModelModality } from "./model-observations.js";

// Re-exported so callers (and tests) can brand plain RFC-3339 strings to the contract.
export { type UtcTimestamp } from "./protocol.js";

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/** The kind of workload a profile asks for. Both require textual output. */
export type CapabilityPurpose = "chat" | "text";

/** Requested capability profile: a bounded, immutable constraint set. */
export interface CapabilityProfile {
  readonly version: number;
  readonly purpose: CapabilityPurpose;
  /** Required output modalities (text/chat + vision/image coverage). */
  readonly requiredModalities: readonly ModelModality[];
  /** Hard minimum context window (tokens); `null` = preference only (`largeContext`). */
  readonly contextWindow: number | null;
  /** Hard requirement when `true`; preference only when `null` or `false`. */
  readonly tools: boolean | null;
  readonly vision: boolean | null;
  readonly reasoning: boolean | null;
  /** Embedding support where the architecture supports it; `null` = explicitly unknown. */
  readonly embeddings: boolean | null;
  /** Hard provider constraint (opaque); `null` = not required. */
  readonly provider: string | null;
  /** Hard quantization/format constraint (opaque); `null` = not required. */
  readonly quantization: string | null;
  /** Per-workload resource budget (footprint ceiling) where appropriate; `null` = not required. */
  readonly minimumMemoryBytes: ByteAmount | null;
  readonly minimumVramBytes: ByteAmount | null;
  readonly minimumDiskBytes: ByteAmount | null;
  /** Soft ordering of satisfiable preference tokens (earlier = stronger). */
  readonly preferences: readonly CapabilityPreferenceToken[];
  /** Explicitly declared unknown dimensions (machine codes): skipped, never hard-fail. */
  readonly unknowns: readonly CapabilityDimensionCode[];
}

/** A preference token the matcher can evaluate against an observed model. */
export type CapabilityPreferenceToken =
  | "tools"
  | "vision"
  | "reasoning"
  | "embeddings"
  | "largeContext";

/** Dimensions the matcher knows how to require; the only codes allowed in `unknowns`. */
export type CapabilityDimensionCode =
  | "PURPOSE"
  | "MODALITIES"
  | "CONTEXT_WINDOW"
  | "TOOLS"
  | "VISION"
  | "REASONING"
  | "EMBEDDINGS"
  | "PROVIDER"
  | "QUANTIZATION"
  | "MINIMUM_MEMORY_BYTES"
  | "MINIMUM_VRAM_BYTES"
  | "MINIMUM_DISK_BYTES";

/** Whether an observed embedding capability is known to be supported, unsupported, or unknown. */
export type ObservedEmbeddingSupport = boolean | null;

/** Observed model capability: a bounded, immutable snapshot of what a model actually is. */
export interface ObservedModelCapability {
  /** What the model serves for output; `null` = explicitly unknown. */
  readonly purpose: CapabilityPurpose | null;
  /** Output modalities the model can emit; `[]` = not observed / not constrained. */
  readonly modalities: readonly ModelModality[];
  readonly contextWindow: number | null;
  readonly tools: boolean | null;
  readonly vision: boolean | null;
  readonly reasoning: boolean | null;
  readonly embeddings: ObservedEmbeddingSupport;
  /** Provider category the observed model serves; `null` = unknown. */
  readonly provider: string | null;
  /** Quantization/format actually loaded; `null` = unknown. */
  readonly quantization: string | null;
  /** Bytes the model occupies; `null` = unknown. */
  readonly sizeBytes: ByteAmount | null;
  /** Footprint the model needs to run; each `null` = unknown. */
  readonly requiresMemoryBytes: ByteAmount | null;
  readonly requiresVramBytes: ByteAmount | null;
  readonly requiresDiskBytes: ByteAmount | null;
  /** Folded, lower-level capability from the fleet observation seam (may omit `modalities`). */
  readonly capability: ModelCapability | null;
  readonly observedAt: UtcTimestamp;
}

/** Per-model match result. */
export interface CapabilityMatch {
  /** `true` iff every HARD requirement this profile imposes is satisfied. */
  readonly match: boolean;
  /** Redacted hard-failure codes (canonical order); empty when `match` is `true`. */
  readonly reasons: readonly string[];
  /** Satisfied requested preference tokens, in requested order. */
  readonly preferences: readonly CapabilityPreferenceToken[];
  /** Deterministic numeric fit score; higher is better. */
  readonly preferenceScore: number;
}

/** Pool-level match result (substitution eligibility). */
export interface CapabilityMatchResult {
  /** Whether any observed model in the pool satisfies every HARD requirement. */
  readonly substitutable: boolean;
  /** Redacted hard-failure codes unioned across the pool; empty when `substitutable` is `true`. */
  readonly reasons: readonly string[];
  /** Best-fit model, or `null` when the pool is empty or nothing matches. */
  readonly best: CapabilityMatch | null;
}

// ---------------------------------------------------------------------------
// Canonical codes and bounds
// ---------------------------------------------------------------------------

/** Canonical order for hard-failure codes. Matcher output is filtered by this array. */
const HARD_REASON_ORDER: readonly string[] = Object.freeze([
  "PROFILE_INVALID",
  "OBSERVATION_INVALID",
  "OBSERVATION_STALE",
  "PURPOSE_UNSUPPORTED",
  "MODALITY_MISSING",
  "CONTEXT_WINDOW_INSUFFICIENT",
  "TOOLS_MISSING",
  "VISION_MISSING",
  "REASONING_MISSING",
  "EMBEDDINGS_UNSUPPORTED",
  "EMBEDDINGS_UNKNOWN",
  "PROVIDER_MISMATCH",
  "QUANTIZATION_FORMAT_MISMATCH",
  "MINIMUM_MEMORY_INSUFFICIENT",
  "MINIMUM_VRAM_INSUFFICIENT",
  "MINIMUM_DISK_INSUFFICIENT",
]);
const HARD_REASON_SET: ReadonlySet<string> = new Set(HARD_REASON_ORDER);

const PURPOSES = new Set<unknown>(["chat", "text"]);
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const DIMENSION_CODE_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;
const MAX_CONTEXT_WINDOW = 10_000_000;
const LARGE_CONTEXT_THRESHOLD = 128 * 1024;

const DIMENSION_CODES: readonly CapabilityDimensionCode[] = Object.freeze([
  "PURPOSE", "MODALITIES", "CONTEXT_WINDOW", "TOOLS", "VISION", "REASONING",
  "EMBEDDINGS", "PROVIDER", "QUANTIZATION", "MINIMUM_MEMORY_BYTES",
  "MINIMUM_VRAM_BYTES", "MINIMUM_DISK_BYTES",
]);

/** Preference token => weight. Earlier-ordered tokens carry heavier weights so ordering dominates. */
const PREFERENCE_WEIGHT: Readonly<Record<CapabilityPreferenceToken, number>> = Object.freeze({
  tools: 16, vision: 8, reasoning: 4, embeddings: 2, largeContext: 1,
});
const PREFERENCE_TOKENS: readonly CapabilityPreferenceToken[] = Object.freeze(
  Object.keys(PREFERENCE_WEIGHT) as CapabilityPreferenceToken[]
);

// ---------------------------------------------------------------------------
// Low-level helpers (exact-key, accessor-safe, no-throw) — mirrors existing seams
// ---------------------------------------------------------------------------

function fail<T>(error: string): ParseResult<T> {
  return { ok: false, error };
}

/** Strict `fields` that requires the exact fixed key set (no extras) — used by the profile. */
function fields(input: unknown, keys: readonly string[], error: string): ParseResult<Record<string, PropertyDescriptor>> {
  if (typeof input !== "object" || input === null) return fail(error);
  try {
    if (Array.isArray(input)) return fail(error);
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) return fail(error);
    const ownKeys = Reflect.ownKeys(input);
    if (ownKeys.length !== keys.length || ownKeys.some((key) => typeof key !== "string" || !keys.includes(key))) return fail(error);
    const descriptors = Object.getOwnPropertyDescriptors(input);
    if (keys.some((key) => !descriptors[key] || !("value" in descriptors[key]))) return fail(error);
    return { ok: true, value: descriptors };
  } catch {
    return fail(error);
  }
}

/**
 * Strict `fields` for the observed DTO: it requires the exact fixed key set *except* it
 * permits a single optional `modalities` key. Observations intentionally omit modalities
 * (the fleet observation seam records it separately), so modalities is optional here.
 * Returns the parsed descriptors plus the raw modalities value (or `undefined`).
 */
function observedFields(input: unknown): ParseResult<{
  readonly d: Record<string, PropertyDescriptor>;
  readonly modalities: unknown;
}> {
  if (typeof input !== "object" || input === null) return fail("ERR_OBSERVED_INPUT");
  try {
    if (Array.isArray(input)) return fail("ERR_OBSERVED_INPUT");
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) return fail("ERR_OBSERVED_INPUT");
    const fixedKeys = [
      "purpose", "contextWindow", "tools", "vision", "reasoning", "embeddings",
      "provider", "quantization", "sizeBytes", "requiresMemoryBytes",
      "requiresVramBytes", "requiresDiskBytes", "observedAt",
    ] as const;
    const fixedSet = new Set<string>(fixedKeys), optionalSet = new Set(["modalities","capability"]);
    const ownKeys = Reflect.ownKeys(input);
    for (const key of ownKeys) if (typeof key !== "string" || (!fixedSet.has(key) && !optionalSet.has(key))) return fail("ERR_OBSERVED_INPUT");
    const presentKeys = ownKeys.filter((key) => typeof key === "string" && fixedSet.has(key));
    if (presentKeys.length !== fixedKeys.length) return fail("ERR_OBSERVED_INPUT");
    const descriptors = Object.getOwnPropertyDescriptors(input);
    for (const key of fixedKeys) {
      if (!descriptors[key] || !("value" in descriptors[key])) return fail("ERR_OBSERVED_INPUT");
    }
    const modalities = ownKeys.includes("modalities")
      ? (descriptors.modalities as PropertyDescriptor | undefined)?.value
      : undefined;
    return { ok: true, value: { d: descriptors, modalities } };
  } catch {
    return fail("ERR_OBSERVED_INPUT");
  }
}

function parsePurpose(input: unknown): ParseResult<CapabilityPurpose> {
  const purpose = input as unknown;
  return (typeof purpose === "string" && PURPOSES.has(purpose))
    ? { ok: true, value: purpose as CapabilityPurpose }
    : fail("ERR_PURPOSE");
}

function parseDenseModalities(input: unknown): ParseResult<readonly ModelModality[]> {
  try {
    if (!Array.isArray(input)) return fail("ERR_MODALITIES");
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const lengthDescriptor: PropertyDescriptor | undefined = Object.getOwnPropertyDescriptor(input, "length");
    const length = lengthDescriptor?.value as unknown;
    if (!Number.isSafeInteger(length) || (length as number) < 0 || (length as number) > 3) return fail("ERR_MODALITIES");
    const keys = Reflect.ownKeys(input);
    if (keys.some((key) => typeof key !== "string" || (key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key)))) return fail("ERR_MODALITIES");
    const output: ModelModality[] = [];
    const seen = new Set<string>();
    for (let index = 0; index < (length as number); index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !("value" in descriptor)) return fail("ERR_MODALITIES");
      const modality = descriptor.value as unknown;
      const modalityString = String(modality);
      if (!/^(?:text|image|audio)$/.test(modalityString)) return fail("ERR_MODALITIES");
      if (seen.has(modalityString)) return fail("ERR_MODALITIES_DUPLICATE");
      seen.add(modalityString);
      output.push(modalityString as ModelModality);
    }
    return { ok: true, value: Object.freeze(output) };
  } catch {
    return fail("ERR_MODALITIES");
  }
}

/** Parse optional modalities: `undefined` (key absent) => `[]`; otherwise a dense array. */
function parseModalitiesOptional(input: unknown): ParseResult<readonly ModelModality[]> {
  if (input === undefined) return { ok: true, value: Object.freeze([] as ModelModality[]) };
  return parseDenseModalities(input);
}

function parseBoundedToken(input: unknown, error: string): ParseResult<string | null> {
  const value = input as unknown;
  if (value === null) return { ok: true, value: null };
  return typeof value === "string" && value.length >= 1 && value.length <= 256 && TOKEN_PATTERN.test(value)
    ? { ok: true, value }
    : fail(error);
}

function parseOptionalNumber(input: unknown): ParseResult<number | null> {
  if (input === null || input === undefined) return { ok: true, value: null };
  const value = input as unknown;
  if (typeof value !== "number" || !Number.isFinite(value) || !Number.isInteger(value) || value < 1 || value > MAX_CONTEXT_WINDOW) return fail("ERR_CONTEXT_WINDOW");
  return { ok: true, value };
}

function parseOptionalBoolean(input: unknown): ParseResult<boolean | null> {
  if (input === null || input === undefined) return { ok: true, value: null };
  if (typeof input !== "boolean") return fail("ERR_OPTIONAL_BOOLEAN");
  return { ok: true, value: input };
}

// ---------------------------------------------------------------------------
// Parsing (strict bounded immutable DTOs)
// ---------------------------------------------------------------------------

export function parseCapabilityProfile(input: unknown): ParseResult<CapabilityProfile> {
  const keys = ["version", "purpose", "requiredModalities", "contextWindow", "tools", "vision",
    "reasoning", "embeddings", "provider", "quantization", "minimumMemoryBytes",
    "minimumVramBytes", "minimumDiskBytes", "preferences", "unknowns"] as const;
  const parsed = fields(input, keys, "ERR_PROFILE_INPUT");
  if (!parsed.ok) return parsed;
  const d = parsed.value;

  const version = (d.version!.value as unknown) as number;
  if (!Number.isSafeInteger(version) || version < 1 || version > 64) return fail("ERR_PROFILE_VERSION");

  const purpose = parsePurpose(d.purpose!.value);
  if (!purpose.ok) return purpose;

  const modalities = parseDenseModalities(d.requiredModalities!.value);
  if (!modalities.ok) return modalities;

  const contextWindow = parseOptionalNumber(d.contextWindow!.value as unknown);
  if (!contextWindow.ok) return contextWindow;

  const toolsResult = parseOptionalBoolean(d.tools!.value as unknown);
  if (!toolsResult.ok) return fail("ERR_OPTIONAL_BOOLEAN");
  const visionResult = parseOptionalBoolean(d.vision!.value as unknown);
  if (!visionResult.ok) return fail("ERR_OPTIONAL_BOOLEAN");
  const reasoningResult = parseOptionalBoolean(d.reasoning!.value as unknown);
  if (!reasoningResult.ok) return fail("ERR_OPTIONAL_BOOLEAN");
  const embeddingsResult = parseOptionalBoolean(d.embeddings!.value as unknown);
  if (!embeddingsResult.ok) return fail("ERR_OPTIONAL_BOOLEAN");

  const provider = parseBoundedToken(d.provider!.value as unknown, "ERR_PROVIDER");
  if (!provider.ok) return provider;
  const quantization = parseBoundedToken(d.quantization!.value as unknown, "ERR_QUANTIZATION");
  if (!quantization.ok) return quantization;

  const minimumMemoryBytes = parseOptionalByte(d.minimumMemoryBytes!.value as unknown, "ERR_MINIMUM_MEMORY");
  const minimumVramBytes = parseOptionalByte(d.minimumVramBytes!.value as unknown, "ERR_MINIMUM_VRAM");
  const minimumDiskBytes = parseOptionalByte(d.minimumDiskBytes!.value as unknown, "ERR_MINIMUM_DISK");
  if (!minimumMemoryBytes.ok || !minimumVramBytes.ok || !minimumDiskBytes.ok) return fail("ERR_MINIMUM_RESOURCE");

  const preferences = parsePreferences(d.preferences!.value);
  if (!preferences.ok) return preferences;
  const unknowns = parseUnknowns(d.unknowns!.value);
  if (!unknowns.ok) return unknowns;

  const output = Object.create(null) as Record<string, unknown>;
  Object.assign(output, {
    version, purpose: purpose.value, requiredModalities: modalities.value, contextWindow: contextWindow.value,
    tools: toolsResult.value, vision: visionResult.value, reasoning: reasoningResult.value,
    embeddings: embeddingsResult.value, provider: provider.value, quantization: quantization.value,
    minimumMemoryBytes: minimumMemoryBytes.value, minimumVramBytes: minimumVramBytes.value,
    minimumDiskBytes: minimumDiskBytes.value, preferences: preferences.value, unknowns: unknowns.value,
  });
  return { ok: true, value: Object.freeze(output) as unknown as CapabilityProfile };
}

function parseOptionalByte(input: unknown, error: string): ParseResult<ByteAmount | null> {
  if (input === null || input === undefined) return { ok: true, value: null };
  return parseByteAmount(input).ok ? parseByteAmount(input) : fail(error);
}

function parsePreferences(input: unknown): ParseResult<readonly CapabilityPreferenceToken[]> {
  try {
    if (!Array.isArray(input)) return fail("ERR_PREFERENCES");
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const lengthDescriptor: PropertyDescriptor | undefined = Object.getOwnPropertyDescriptor(input, "length");
    const length = lengthDescriptor?.value as unknown;
    if (!Number.isSafeInteger(length) || (length as number) < 0 || (length as number) > 64) return fail("ERR_PREFERENCES");
    const keys = Reflect.ownKeys(input);
    if (keys.some((key) => typeof key !== "string" || (key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key)))) return fail("ERR_PREFERENCES");
    const seen = new Set<CapabilityPreferenceToken>();
    const output: CapabilityPreferenceToken[] = [];
    for (let index = 0; index < (length as number); index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !("value" in descriptor)) return fail("ERR_PREFERENCES");
      const token = descriptor.value as unknown;
      if (!PREFERENCE_TOKENS.includes(token as CapabilityPreferenceToken)) return fail("ERR_PREFERENCE_TOKEN");
      const t = token as CapabilityPreferenceToken;
      if (seen.has(t)) return fail("ERR_PREFERENCE_DUPLICATE");
      seen.add(t);
      output.push(t);
    }
    return { ok: true, value: Object.freeze(output) };
  } catch {
    return fail("ERR_PREFERENCES");
  }
}

function parseUnknowns(input: unknown): ParseResult<readonly CapabilityDimensionCode[]> {
  try {
    if (!Array.isArray(input)) return fail("ERR_UNKNOWNS");
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const lengthDescriptor: PropertyDescriptor | undefined = Object.getOwnPropertyDescriptor(input, "length");
    const length = lengthDescriptor?.value as unknown;
    if (!Number.isSafeInteger(length) || (length as number) < 0 || (length as number) > 32) return fail("ERR_UNKNOWNS");
    const keys = Reflect.ownKeys(input);
    if (keys.some((key) => typeof key !== "string" || (key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key)))) return fail("ERR_UNKNOWNS");
    const seen = new Set<string>();
    const output: CapabilityDimensionCode[] = [];
    for (let index = 0; index < (length as number); index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !("value" in descriptor)) return fail("ERR_UNKNOWNS");
      const code = descriptor.value as unknown;
      if (typeof code !== "string" || !DIMENSION_CODE_PATTERN.test(code)) return fail("ERR_UNKNOWN_DIMENSION");
      if (!DIMENSION_CODES.includes(code as CapabilityDimensionCode)) return fail("ERR_UNKNOWN_DIMENSION");
      if (seen.has(code)) return fail("ERR_UNKNOWN_DUPLICATE");
      seen.add(code);
      output.push(code as CapabilityDimensionCode);
    }
    return { ok: true, value: Object.freeze(output) };
  } catch {
    return fail("ERR_UNKNOWNS");
  }
}

export function parseObservedModelCapability(input: unknown): ParseResult<ObservedModelCapability> {
  const parsed = observedFields(input);
  if (!parsed.ok) return parsed;
  const { d, modalities: modalitiesRaw } = parsed.value;

  const purposeResult = d.purpose!.value === null ? { ok: true as const, value: null } : parsePurpose(d.purpose!.value as unknown);
  if (!purposeResult.ok) return purposeResult;

  const modalities = parseModalitiesOptional(modalitiesRaw);
  if (!modalities.ok) return modalities;

  const contextWindow = parseOptionalNumber(d.contextWindow!.value);
  if (!contextWindow.ok) return contextWindow;

  const tools = parseOptionalBoolean(d.tools!.value);
  if (!tools.ok) return fail("ERR_OBSERVED_BOOLEAN");
  const vision = parseOptionalBoolean(d.vision!.value);
  if (!vision.ok) return fail("ERR_OBSERVED_BOOLEAN");
  const reasoning = parseOptionalBoolean(d.reasoning!.value);
  if (!reasoning.ok) return fail("ERR_OBSERVED_BOOLEAN");

  const embeddings = parseOptionalBoolean(d.embeddings!.value as unknown);
  if (!embeddings.ok) return fail("ERR_OPTIONAL_BOOLEAN");

  const provider = parseBoundedToken(d.provider!.value, "ERR_PROVIDER");
  if (!provider.ok) return provider;
  const quantization = parseBoundedToken(d.quantization!.value, "ERR_QUANTIZATION");
  if (!quantization.ok) return quantization;

  const sizeBytes = parseOptionalByte(d.sizeBytes === undefined ? null : (d.sizeBytes!.value as unknown), "ERR_SIZE_BYTES");
  if (!sizeBytes.ok) return fail("ERR_SIZE_BYTES");
  const requiresMemoryBytes = parseOptionalByte(d.requiresMemoryBytes!.value, "ERR_REQUIRES_MEMORY");
  const requiresVramBytes = parseOptionalByte(d.requiresVramBytes!.value, "ERR_REQUIRES_VRAM");
  const requiresDiskBytes = parseOptionalByte(d.requiresDiskBytes!.value, "ERR_REQUIRES_DISK");
  if (!requiresMemoryBytes.ok || !requiresVramBytes.ok || !requiresDiskBytes.ok) return fail("ERR_REQUIRES_RESOURCE");

  const observedAt = parseUtcTimestamp(d.observedAt!.value);
  if (!observedAt.ok) return observedAt;

  // Fold the lower-level fleet observation seam (capability) when it is present, but
  // never require it: the observed capability DTO stands independently of it.
  const capability = parseModelCapability(d.capability === undefined ? null : d.capability!.value as unknown);
  const capabilityResult = capability.ok ? capability.value : null;

  const output = Object.create(null) as Record<string, unknown>;
  Object.assign(output, {
    purpose: purposeResult.value, modalities: modalities.value, contextWindow: contextWindow.value,
    tools: tools.value, vision: vision.value, reasoning: reasoning.value, embeddings: embeddings.value,
    provider: provider.value, quantization: quantization.value,
    sizeBytes: sizeBytes.value, requiresMemoryBytes: requiresMemoryBytes.value,
    requiresVramBytes: requiresVramBytes.value, requiresDiskBytes: requiresDiskBytes.value,
    capability: capabilityResult, observedAt: observedAt.value,
  });
  return { ok: true, value: Object.freeze(output) as unknown as ObservedModelCapability };
}

function parseBoolean(input: unknown): ParseResult<boolean> {
  return typeof input === "boolean"
    ? { ok: true, value: input }
    : fail("ERR_OBSERVED_BOOLEAN");
}

// ---------------------------------------------------------------------------
// Matching (pure, deterministic, no-throw)
// ---------------------------------------------------------------------------

/** Build a canonical, immutable match unit (null-prototype, frozen, deep-frozen arrays). */
function toMatchUnit(
  match: boolean,
  reasons: readonly string[],
  preferences: readonly CapabilityPreferenceToken[],
  score: number,
): CapabilityMatch {
  const out = Object.create(null) as Record<string, unknown>;
  out.match = match;
  out.reasons = Object.freeze([...reasons]);
  out.preferences = Object.freeze([...preferences]);
  out.preferenceScore = score;
  Object.freeze(out);
  return out as unknown as CapabilityMatch;
}

/** Filter a failure set into canonical order. */
function ordered(reasons: ReadonlySet<string>): readonly string[] {
  return HARD_REASON_ORDER.filter((code) => reasons.has(code));
}

/** The set of dimensions this profile hard-requires (those not marked explicitly unknown). */
function requiredHardDimensions(
  profile: CapabilityProfile,
  unknowns: ReadonlySet<CapabilityDimensionCode>,
): ReadonlySet<CapabilityDimensionCode> {
  const required = new Set<CapabilityDimensionCode>();
  if (!unknowns.has("PURPOSE") && profile.purpose) required.add("PURPOSE");
  if (!unknowns.has("CONTEXT_WINDOW") && profile.contextWindow !== null) required.add("CONTEXT_WINDOW");
  if (!unknowns.has("TOOLS") && profile.tools === true) required.add("TOOLS");
  if (!unknowns.has("VISION") && profile.vision === true) required.add("VISION");
  if (!unknowns.has("REASONING") && profile.reasoning === true) required.add("REASONING");
  if (!unknowns.has("EMBEDDINGS") && profile.embeddings === true) required.add("EMBEDDINGS");
  if (!unknowns.has("PROVIDER") && profile.provider !== null) required.add("PROVIDER");
  if (!unknowns.has("QUANTIZATION") && profile.quantization !== null) required.add("QUANTIZATION");
  if (!unknowns.has("MINIMUM_MEMORY_BYTES") && profile.minimumMemoryBytes !== null) required.add("MINIMUM_MEMORY_BYTES");
  if (!unknowns.has("MINIMUM_VRAM_BYTES") && profile.minimumVramBytes !== null) required.add("MINIMUM_VRAM_BYTES");
  if (!unknowns.has("MINIMUM_DISK_BYTES") && profile.minimumDiskBytes !== null) required.add("MINIMUM_DISK_BYTES");
  if (!unknowns.has("MODALITIES") && (profile.requiredModalities.length > 0 || profile.purpose === "chat")) {
    required.add("MODALITIES");
  }
  return required;
}

/** Modalities the model must emit for the requested purpose (text/chat needs text). */
function chatTextRequired(profile: CapabilityProfile): readonly ModelModality[] {
  return profile.purpose === "chat"
    ? (profile.requiredModalities.length > 0 ? (["text", ...profile.requiredModalities] as ModelModality[]) : profile.requiredModalities)
    : profile.requiredModalities;
}

/** Check a single required dimension, pushing redacted fail codes into `reasons`. */
function satisfyDimension(
  profile: CapabilityProfile,
  observed: ObservedModelCapability,
  dimension: CapabilityDimensionCode,
  reasons: Set<string>,
): void {
  switch (dimension) {
    case "PURPOSE": {
      // A model produces text when it is a chat model, or it is a text model that
      // explicitly emits the text output modality. Otherwise, fail closed.
      const producesText = observed.purpose === "chat" || observed.modalities.includes("text");
      if (!producesText) reasons.add("PURPOSE_UNSUPPORTED");
      break;
    }
    case "MODALITIES": {
      const modalities = new Set(observed.modalities);
      for (const want of chatTextRequired(profile)) {
        if (!modalities.has(want)) reasons.add("MODALITY_MISSING");
      }
      break;
    }
    case "CONTEXT_WINDOW": {
      const contextWindow = profile.contextWindow as number;
      if (observed.contextWindow === null || observed.contextWindow < contextWindow) {
        reasons.add("CONTEXT_WINDOW_INSUFFICIENT");
      }
      break;
    }
    case "TOOLS":
      if (!observed.tools) reasons.add("TOOLS_MISSING");
      break;
    case "VISION":
      if (!observed.vision) reasons.add("VISION_MISSING");
      break;
    case "REASONING":
      if (!observed.reasoning) reasons.add("REASONING_MISSING");
      break;
    case "EMBEDDINGS":
      if (observed.embeddings === false) reasons.add("EMBEDDINGS_UNSUPPORTED");
      else if (observed.embeddings === null) reasons.add("EMBEDDINGS_UNKNOWN");
      break;
    case "PROVIDER": {
      const provider = profile.provider as string;
      if (observed.provider === null || observed.provider !== provider) reasons.add("PROVIDER_MISMATCH");
      break;
    }
    case "QUANTIZATION": {
      const quantization = profile.quantization as string;
      if (observed.quantization === null || observed.quantization !== quantization) {
        reasons.add("QUANTIZATION_FORMAT_MISMATCH");
      }
      break;
    }
    case "MINIMUM_MEMORY_BYTES": {
      const minimumMemoryBytes = profile.minimumMemoryBytes as number;
      if (observed.requiresMemoryBytes === null || observed.requiresMemoryBytes > minimumMemoryBytes) {
        reasons.add("MINIMUM_MEMORY_INSUFFICIENT");
      }
      break;
    }
    case "MINIMUM_VRAM_BYTES": {
      const minimumVramBytes = profile.minimumVramBytes as number;
      if (observed.requiresVramBytes === null || observed.requiresVramBytes > minimumVramBytes) {
        reasons.add("MINIMUM_VRAM_INSUFFICIENT");
      }
      break;
    }
    case "MINIMUM_DISK_BYTES": {
      const minimumDiskBytes = profile.minimumDiskBytes as number;
      if (observed.requiresDiskBytes === null || observed.requiresDiskBytes > minimumDiskBytes) {
        reasons.add("MINIMUM_DISK_INSUFFICIENT");
      }
      break;
    }
  }
}

/** Satisfied requested preference tokens (in requested order) and a deterministic score. */
function evaluatePreferences(
  profile: CapabilityProfile,
  observed: ObservedModelCapability,
): { satisfied: CapabilityPreferenceToken[]; score: number } {
  const satisfied: CapabilityPreferenceToken[] = [];
  let score = 0;
  const contextFloor = profile.contextWindow ?? 0;
  const largeThreshold = Math.max(LARGE_CONTEXT_THRESHOLD, contextFloor);
  for (const token of profile.preferences) {
    let ok = false;
    switch (token) {
      case "tools": ok = observed.tools === true; break;
      case "vision": ok = observed.vision === true; break;
      case "reasoning": ok = observed.reasoning === true; break;
      case "embeddings": ok = observed.embeddings === true; break;
      case "largeContext":
        ok = observed.contextWindow !== null && observed.contextWindow >= largeThreshold;
        break;
    }
    if (ok) {
      satisfied.push(token);
      score += PREFERENCE_WEIGHT[token];
    }
  }
  return { satisfied, score };
}

/** Whether two candidate models tie on all deterministic keys (preserve input order). */
function tieKepts(left: CapabilityMatch, right: CapabilityMatch): boolean {
  if (right.preferenceScore !== left.preferenceScore) return false;
  if (left.reasons.length !== right.reasons.length) return false;
  return left.reasons.every((code, index) => code === right.reasons[index]);
}

function matchOneInternal(
  profile: CapabilityProfile,
  observed: ObservedModelCapability,
  now: UtcTimestamp | null,
  staleThresholdMs: number | null,
): CapabilityMatch {
  const unknowns = new Set<CapabilityDimensionCode>(profile.unknowns);
  const required = requiredHardDimensions(profile, unknowns);

  // Freshness is evaluated independently of hard dimensions. Invalid or partial
  // freshness inputs fail closed instead of silently disabling the check.
  if ((now === null) !== (staleThresholdMs === null)) return toMatchUnit(false, ["OBSERVATION_INVALID"], [], 0);
  if (now !== null && staleThresholdMs !== null) {
    const nowMs = Date.parse(now), observedMs = Date.parse(observed.observedAt);
    if (!Number.isFinite(nowMs) || !Number.isFinite(observedMs) || !Number.isSafeInteger(staleThresholdMs) || staleThresholdMs < 0) return toMatchUnit(false, ["OBSERVATION_INVALID"], [], 0);
    const gap = nowMs - observedMs;
    if (gap < -30_000 || gap > staleThresholdMs) return toMatchUnit(false, ["OBSERVATION_STALE"], [], 0);
  }

  if (required.size === 0) {
    const { satisfied, score } = evaluatePreferences(profile, observed);
    return toMatchUnit(true, [], satisfied, score);
  }

  const reasons = new Set<string>();
  for (const dimension of required) {
    satisfyDimension(profile, observed, dimension, reasons);
  }
  if (reasons.size === 0) {
    const { satisfied, score } = evaluatePreferences(profile, observed);
    return toMatchUnit(true, [], satisfied, score);
  }
  return toMatchUnit(false, ordered(reasons), [], 0);
}

/** Match a single observed model against a requested profile. Non-throwing, deterministic. */
export function matchOne(
  profile: CapabilityProfile,
  observed: ObservedModelCapability,
  now: UtcTimestamp | null = null,
  staleThresholdMs: number | null = null,
): CapabilityMatch {
  try {
    const p=parseCapabilityProfile(profile),o=parseObservedModelCapability(observed);
    if(!p.ok)return toMatchUnit(false,["PROFILE_INVALID"],[],0);
    if(!o.ok)return toMatchUnit(false,["OBSERVATION_INVALID"],[],0);
    return matchOneInternal(p.value,o.value,now,staleThresholdMs);
  } catch { return toMatchUnit(false,["OBSERVATION_INVALID"],[],0); }
}

/** Best-fit model from two equally-scored match units (preserve input order). */
function pickBest(left: CapabilityMatch, right: CapabilityMatch): CapabilityMatch {
  return tieKepts(left, right) ? left : right;
}

/** Match an observed pool against a requested profile (substitution eligibility). Non-throwing. */
export function matchCapabilities(
  profile: CapabilityProfile,
  pool: readonly ObservedModelCapability[],
  now: UtcTimestamp | null = null,
  staleThresholdMs: number | null = null,
): CapabilityMatchResult {
  try {
    const parsedProfile=parseCapabilityProfile(profile);
    if(!parsedProfile.ok)return freezePool(false,["PROFILE_INVALID"],null);
    if(!Array.isArray(pool))return freezePool(false,["OBSERVATION_INVALID"],null);
    const units=pool.map(observed=>matchOne(parsedProfile.value,observed,now,staleThresholdMs));
    if(units.length===0)return freezePool(false,[],null);
    const matching=units.filter(unit=>unit.match);
    if(matching.length>0)return freezePool(true,[],matching.reduce((acc,unit)=>pickBest(acc,unit)));
    const union=new Set<string>();for(const unit of units)for(const code of unit.reasons)if(HARD_REASON_SET.has(code))union.add(code);
    return freezePool(false,ordered(union),null);
  } catch { return freezePool(false,["OBSERVATION_INVALID"],null); }
}
function freezePool(substitutable:boolean,reasons:readonly string[],best:CapabilityMatch|null):CapabilityMatchResult{const out=Object.create(null) as Record<string,unknown>;out.substitutable=substitutable;out.reasons=Object.freeze([...reasons]);out.best=best;return Object.freeze(out) as unknown as CapabilityMatchResult;}

export interface CapabilityCandidate{readonly candidateId:string;readonly capability:ObservedModelCapability}
export interface CapabilitySelection{readonly candidateId:string|null;readonly substitutable:boolean;readonly reasons:readonly string[];readonly match:CapabilityMatch|null}
export function selectCapabilityCandidate(profile:CapabilityProfile,candidates:readonly CapabilityCandidate[],now:UtcTimestamp,staleThresholdMs:number):CapabilitySelection{
 try{if(!Array.isArray(candidates))throw 0;let best:{id:string;unit:CapabilityMatch}|null=null;const failures=new Set<string>();for(const candidate of candidates){const d=fields(candidate,["candidateId","capability"],"ERR_CANDIDATE");if(!d.ok||typeof d.value.candidateId!.value!=="string"||!TOKEN_PATTERN.test(d.value.candidateId!.value))throw 0;const unit=matchOne(profile,d.value.capability!.value as ObservedModelCapability,now,staleThresholdMs);if(unit.match&&(!best||unit.preferenceScore>best.unit.preferenceScore||unit.preferenceScore===best.unit.preferenceScore&&d.value.candidateId!.value<best.id))best={id:d.value.candidateId!.value,unit};else for(const reason of unit.reasons)failures.add(reason);}
 const out=Object.create(null) as Record<string,unknown>;out.candidateId=best?.id??null;out.substitutable=best!==null;out.reasons=Object.freeze(best?[]:ordered(failures));out.match=best?.unit??null;return Object.freeze(out) as unknown as CapabilitySelection;
 }catch{const out=Object.create(null) as Record<string,unknown>;out.candidateId=null;out.substitutable=false;out.reasons=Object.freeze(["OBSERVATION_INVALID"]);out.match=null;return Object.freeze(out) as unknown as CapabilitySelection;}
}
