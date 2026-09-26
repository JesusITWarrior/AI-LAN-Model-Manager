import { parseByteAmount, type ByteAmount } from "./observations.js";
import { parseUtcTimestamp, type ParseResult, type UtcTimestamp } from "./protocol.js";

export type ProviderKind = "ollama" | "lm-studio" | "custom";
export type ProviderHealth = "unavailable" | "starting" | "ready" | "degraded" | "failed";
export type ModelArtifactState = "installed" | "installing" | "removing" | "failed";
export type ModelRuntimeState = "unloaded" | "loading" | "loaded-idle" | "serving" | "draining" | "unloading" | "failed" | "unknown";
export type ModelModality = "text" | "image" | "audio";

export interface ProviderObservation {
  readonly providerId: string;
  readonly kind: ProviderKind;
  readonly displayName: string;
  readonly endpoint: string;
  readonly health: ProviderHealth;
  readonly version: string | null;
  readonly observedAt: UtcTimestamp;
}
export interface ModelCapability {
  readonly tools: boolean;
  readonly vision: boolean;
  readonly reasoning: boolean;
  readonly modalities: readonly ModelModality[];
  readonly contextWindow: number | null;
}
export interface InstalledModelObservation {
  readonly modelId: string;
  readonly providerId: string;
  readonly displayName: string;
  readonly artifactState: ModelArtifactState;
  readonly runtimeState: ModelRuntimeState;
  readonly activeRequests: number;
  readonly sizeBytes: ByteAmount | null;
  readonly managedTemporary: boolean;
  readonly pinned: boolean;
  readonly capability: ModelCapability;
  readonly observedAt: UtcTimestamp;
}

const fail = <T>(error: string): ParseResult<T> => ({ ok: false, error });
const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const PRINTABLE = /^[^\u0000-\u001f\u007f]+$/;
const PROVIDER_KINDS = new Set<unknown>(["ollama", "lm-studio", "custom"]);
const PROVIDER_HEALTH = new Set<unknown>(["unavailable", "starting", "ready", "degraded", "failed"]);
const ARTIFACT_STATES = new Set<unknown>(["installed", "installing", "removing", "failed"]);
const RUNTIME_STATES = new Set<unknown>(["unloaded", "loading", "loaded-idle", "serving", "draining", "unloading", "failed", "unknown"]);
const MODALITIES = new Set<unknown>(["text", "image", "audio"]);

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
  } catch { return fail(error); }
}

function parseOpaqueId(input: unknown): ParseResult<string> {
  return typeof input === "string" && input.length >= 1 && input.length <= 128 && OPAQUE_ID.test(input)
    ? { ok: true, value: input }
    : fail("ERR_OPAQUE_ID");
}
function parsePrintable(input: unknown, max: number, nullable = false): ParseResult<string | null> {
  if (nullable && input === null) return { ok: true, value: null };
  return typeof input === "string" && input.length >= 1 && input.length <= max && PRINTABLE.test(input)
    ? { ok: true, value: input }
    : fail("ERR_PRINTABLE_STRING");
}
function parseEndpoint(input: unknown): ParseResult<string> {
  if (typeof input !== "string" || input.length < 1 || input.length > 2048) return fail("ERR_ENDPOINT");
  try {
    const url = new URL(input);
    if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password || url.hash) return fail("ERR_ENDPOINT");
    return { ok: true, value: input };
  } catch { return fail("ERR_ENDPOINT"); }
}

function parseModalities(input: unknown): ParseResult<readonly ModelModality[]> {
  try {
    if (!Array.isArray(input)) return fail("ERR_MODALITIES");
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const lengthDescriptor: PropertyDescriptor | undefined = Object.getOwnPropertyDescriptor(input, "length");
    const length = lengthDescriptor?.value as unknown;
    if (!Number.isSafeInteger(length) || (length as number) < 0 || (length as number) > 3) return fail("ERR_MODALITIES");
    const keys = Reflect.ownKeys(input);
    if (keys.some((key) => typeof key !== "string" || (key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key)))) return fail("ERR_MODALITIES");
    const output: ModelModality[] = [];
    const seen = new Set<ModelModality>();
    for (let index = 0; index < (length as number); index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !("value" in descriptor) || !MODALITIES.has(descriptor.value)) return fail("ERR_MODALITIES");
      const modality = descriptor.value as ModelModality;
      if (seen.has(modality)) return fail("ERR_MODALITIES_DUPLICATE");
      seen.add(modality); output.push(modality);
    }
    return { ok: true, value: Object.freeze(output) };
  } catch { return fail("ERR_MODALITIES"); }
}

export function parseModelCapability(input: unknown): ParseResult<ModelCapability> {
  const parsed = fields(input, ["tools", "vision", "reasoning", "modalities", "contextWindow"], "ERR_CAPABILITY");
  if (!parsed.ok) return parsed;
  const tools = parsed.value.tools?.value as unknown;
  const vision = parsed.value.vision?.value as unknown;
  const reasoning = parsed.value.reasoning?.value as unknown;
  if (typeof tools !== "boolean" || typeof vision !== "boolean" || typeof reasoning !== "boolean") return fail("ERR_CAPABILITY_BOOLEAN");
  const modalities = parseModalities(parsed.value.modalities?.value as unknown);
  if (!modalities.ok) return modalities;
  const contextWindow = parsed.value.contextWindow?.value as unknown;
  if (contextWindow !== null && (typeof contextWindow !== "number" || !Number.isSafeInteger(contextWindow) || contextWindow < 1 || contextWindow > 10_000_000)) return fail("ERR_CONTEXT_WINDOW");
  const output = Object.create(null) as Record<string, unknown>;
  Object.assign(output, { tools, vision, reasoning, modalities: modalities.value, contextWindow });
  return { ok: true, value: Object.freeze(output) as unknown as ModelCapability };
}

export function parseProviderObservation(input: unknown): ParseResult<ProviderObservation> {
  const parsed = fields(input, ["providerId", "kind", "displayName", "endpoint", "health", "version", "observedAt"], "ERR_PROVIDER");
  if (!parsed.ok) return parsed;
  const providerId = parseOpaqueId(parsed.value.providerId?.value as unknown);
  const displayName = parsePrintable(parsed.value.displayName?.value as unknown, 256);
  const endpoint = parseEndpoint(parsed.value.endpoint?.value as unknown);
  const version = parsePrintable(parsed.value.version?.value as unknown, 128, true);
  const observedAt = parseUtcTimestamp(parsed.value.observedAt?.value as unknown);
  const kind = parsed.value.kind?.value as unknown;
  const health = parsed.value.health?.value as unknown;
  if (!providerId.ok) return fail("ERR_PROVIDER_ID");
  if (!PROVIDER_KINDS.has(kind)) return fail("ERR_PROVIDER_KIND");
  if (!displayName.ok) return fail("ERR_PROVIDER_NAME");
  if (!endpoint.ok) return endpoint;
  if (!PROVIDER_HEALTH.has(health)) return fail("ERR_PROVIDER_HEALTH");
  if (!version.ok) return fail("ERR_PROVIDER_VERSION");
  if (!observedAt.ok) return fail("ERR_OBSERVED_AT");
  const output = Object.create(null) as Record<string, unknown>;
  Object.assign(output, { providerId: providerId.value, kind, displayName: displayName.value, endpoint: endpoint.value, health, version: version.value, observedAt: observedAt.value });
  return { ok: true, value: Object.freeze(output) as unknown as ProviderObservation };
}

export function parseInstalledModelObservation(input: unknown): ParseResult<InstalledModelObservation> {
  const parsed = fields(input, ["modelId", "providerId", "displayName", "artifactState", "runtimeState", "activeRequests", "sizeBytes", "managedTemporary", "pinned", "capability", "observedAt"], "ERR_INSTALLED_MODEL");
  if (!parsed.ok) return parsed;
  const modelId = parseOpaqueId(parsed.value.modelId?.value as unknown);
  const providerId = parseOpaqueId(parsed.value.providerId?.value as unknown);
  const displayName = parsePrintable(parsed.value.displayName?.value as unknown, 256);
  const artifactState = parsed.value.artifactState?.value as unknown;
  const runtimeState = parsed.value.runtimeState?.value as unknown;
  const activeRequests = parsed.value.activeRequests?.value as unknown;
  const managedTemporary = parsed.value.managedTemporary?.value as unknown;
  const pinned = parsed.value.pinned?.value as unknown;
  if (!modelId.ok) return fail("ERR_MODEL_ID");
  if (!providerId.ok) return fail("ERR_PROVIDER_ID");
  if (!displayName.ok) return fail("ERR_MODEL_NAME");
  if (!ARTIFACT_STATES.has(artifactState)) return fail("ERR_ARTIFACT_STATE");
  if (!RUNTIME_STATES.has(runtimeState)) return fail("ERR_RUNTIME_STATE");
  if (typeof activeRequests !== "number" || !Number.isSafeInteger(activeRequests) || activeRequests < 0 || activeRequests > 1_000_000) return fail("ERR_ACTIVE_REQUESTS");
  if (activeRequests > 0 && runtimeState !== "serving" && runtimeState !== "draining") return fail("ERR_RUNTIME_ACTIVITY");
  const rawSize = parsed.value.sizeBytes?.value as unknown;
  const size = rawSize === null ? { ok: true as const, value: null } : parseByteAmount(rawSize);
  if (!size.ok) return fail("ERR_SIZE_BYTES");
  if (typeof managedTemporary !== "boolean" || typeof pinned !== "boolean") return fail("ERR_MODEL_BOOLEAN");
  const capability = parseModelCapability(parsed.value.capability?.value as unknown);
  if (!capability.ok) return capability;
  const observedAt = parseUtcTimestamp(parsed.value.observedAt?.value as unknown);
  if (!observedAt.ok) return fail("ERR_OBSERVED_AT");
  const output = Object.create(null) as Record<string, unknown>;
  Object.assign(output, { modelId: modelId.value, providerId: providerId.value, displayName: displayName.value, artifactState, runtimeState, activeRequests, sizeBytes: size.value, managedTemporary, pinned, capability: capability.value, observedAt: observedAt.value });
  return { ok: true, value: Object.freeze(output) as unknown as InstalledModelObservation };
}
