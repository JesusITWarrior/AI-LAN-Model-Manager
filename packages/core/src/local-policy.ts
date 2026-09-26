import { parseByteAmount, type ByteAmount } from "./observations.js";
import { parseUtcTimestamp, type ParseResult, type UtcTimestamp } from "./protocol.js";
import type { ModelRuntimeState } from "./model-observations.js";

export type MutationAction = "load" | "set-options" | "drain" | "unload" | "install" | "remove-managed-artifact" | "evict-temporary";
export type LocalPolicyReason =
  | "stale-observation" | "insufficient-memory" | "insufficient-vram" | "insufficient-storage"
  | "load-concurrency-limit" | "internet-download-disabled" | "peer-transfer-disabled"
  | "active-requests" | "model-not-idle" | "artifact-unverified" | "eviction-disabled"
  | "model-not-temporary" | "model-pinned";

export interface LocalSafetyPolicy {
  readonly minimumFreeMemoryBytes: ByteAmount;
  readonly minimumFreeVramBytes: ByteAmount;
  readonly minimumFreeStorageBytes: ByteAmount;
  readonly maxConcurrentLoads: number;
  readonly allowInternetDownload: boolean;
  readonly allowPeerTransfer: boolean;
  readonly allowTemporaryEviction: boolean;
}
export interface LocalSafetySnapshot {
  readonly observedAt: UtcTimestamp;
  readonly observationFresh: boolean;
  readonly availableMemoryBytes: ByteAmount;
  readonly availableVramBytes: ByteAmount;
  readonly availableStorageBytes: ByteAmount;
  readonly activeLoads: number;
  readonly modelRuntimeState: ModelRuntimeState | null;
  readonly activeRequests: number;
  readonly modelPinned: boolean;
  readonly modelManagedTemporary: boolean;
  readonly artifactVerified: boolean;
}
export interface LocalMutationIntent {
  readonly action: MutationAction;
  readonly requiredMemoryBytes: ByteAmount;
  readonly requiredVramBytes: ByteAmount;
  readonly requiredStorageBytes: ByteAmount;
  readonly requiresInternetDownload: boolean;
  readonly requiresPeerTransfer: boolean;
}
export type LocalPolicyDecision =
  | { readonly allowed: true; readonly reasons: readonly [] }
  | { readonly allowed: false; readonly reasons: readonly LocalPolicyReason[] };

const fail = <T>(error: string): ParseResult<T> => ({ ok: false, error });
const ACTIONS = new Set<unknown>(["load", "set-options", "drain", "unload", "install", "remove-managed-artifact", "evict-temporary"]);
const STATES = new Set<unknown>(["unloaded", "loading", "loaded-idle", "serving", "draining", "unloading", "failed", "unknown"]);
const REASON_ORDER: readonly LocalPolicyReason[] = [
  "stale-observation", "insufficient-memory", "insufficient-vram", "insufficient-storage",
  "load-concurrency-limit", "internet-download-disabled", "peer-transfer-disabled",
  "active-requests", "model-not-idle", "artifact-unverified", "eviction-disabled",
  "model-not-temporary", "model-pinned",
];

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
function bytes(value: unknown, error: string): ParseResult<ByteAmount> {
  const parsed = parseByteAmount(value);
  return parsed.ok ? parsed : fail(error);
}
function frozen<T>(values: Record<string, unknown>): T {
  return Object.freeze(Object.assign(Object.create(null), values)) as T;
}

export function parseLocalSafetyPolicy(input: unknown): ParseResult<LocalSafetyPolicy> {
  const parsed = fields(input, ["minimumFreeMemoryBytes", "minimumFreeVramBytes", "minimumFreeStorageBytes", "maxConcurrentLoads", "allowInternetDownload", "allowPeerTransfer", "allowTemporaryEviction"], "ERR_LOCAL_POLICY");
  if (!parsed.ok) return parsed;
  const memory = bytes(parsed.value.minimumFreeMemoryBytes?.value as unknown, "ERR_POLICY_MEMORY");
  const vram = bytes(parsed.value.minimumFreeVramBytes?.value as unknown, "ERR_POLICY_VRAM");
  const storage = bytes(parsed.value.minimumFreeStorageBytes?.value as unknown, "ERR_POLICY_STORAGE");
  const maxLoads = parsed.value.maxConcurrentLoads?.value as unknown;
  const internet = parsed.value.allowInternetDownload?.value as unknown;
  const peer = parsed.value.allowPeerTransfer?.value as unknown;
  const eviction = parsed.value.allowTemporaryEviction?.value as unknown;
  if (!memory.ok || !vram.ok || !storage.ok) return fail("ERR_POLICY_RESERVE");
  if (typeof maxLoads !== "number" || !Number.isSafeInteger(maxLoads) || maxLoads < 1 || maxLoads > 64) return fail("ERR_POLICY_LOADS");
  if (typeof internet !== "boolean" || typeof peer !== "boolean" || typeof eviction !== "boolean") return fail("ERR_POLICY_BOOLEAN");
  return { ok: true, value: frozen<LocalSafetyPolicy>({ minimumFreeMemoryBytes: memory.value, minimumFreeVramBytes: vram.value, minimumFreeStorageBytes: storage.value, maxConcurrentLoads: maxLoads, allowInternetDownload: internet, allowPeerTransfer: peer, allowTemporaryEviction: eviction }) };
}

export function parseLocalSafetySnapshot(input: unknown): ParseResult<LocalSafetySnapshot> {
  const parsed = fields(input, ["observedAt", "observationFresh", "availableMemoryBytes", "availableVramBytes", "availableStorageBytes", "activeLoads", "modelRuntimeState", "activeRequests", "modelPinned", "modelManagedTemporary", "artifactVerified"], "ERR_LOCAL_SNAPSHOT");
  if (!parsed.ok) return parsed;
  const observedAt = parseUtcTimestamp(parsed.value.observedAt?.value as unknown);
  const memory = bytes(parsed.value.availableMemoryBytes?.value as unknown, "ERR_SNAPSHOT_MEMORY");
  const vram = bytes(parsed.value.availableVramBytes?.value as unknown, "ERR_SNAPSHOT_VRAM");
  const storage = bytes(parsed.value.availableStorageBytes?.value as unknown, "ERR_SNAPSHOT_STORAGE");
  const fresh = parsed.value.observationFresh?.value as unknown;
  const activeLoads = parsed.value.activeLoads?.value as unknown;
  const state = parsed.value.modelRuntimeState?.value as unknown;
  const activeRequests = parsed.value.activeRequests?.value as unknown;
  const pinned = parsed.value.modelPinned?.value as unknown;
  const temporary = parsed.value.modelManagedTemporary?.value as unknown;
  const verified = parsed.value.artifactVerified?.value as unknown;
  if (!observedAt.ok || !memory.ok || !vram.ok || !storage.ok) return fail("ERR_SNAPSHOT_FIELD");
  if (typeof fresh !== "boolean" || typeof pinned !== "boolean" || typeof temporary !== "boolean" || typeof verified !== "boolean") return fail("ERR_SNAPSHOT_BOOLEAN");
  if (typeof activeLoads !== "number" || !Number.isSafeInteger(activeLoads) || activeLoads < 0 || activeLoads > 64) return fail("ERR_SNAPSHOT_LOADS");
  if (state !== null && !STATES.has(state)) return fail("ERR_SNAPSHOT_STATE");
  if (typeof activeRequests !== "number" || !Number.isSafeInteger(activeRequests) || activeRequests < 0 || activeRequests > 1_000_000) return fail("ERR_SNAPSHOT_REQUESTS");
  return { ok: true, value: frozen<LocalSafetySnapshot>({ observedAt: observedAt.value, observationFresh: fresh, availableMemoryBytes: memory.value, availableVramBytes: vram.value, availableStorageBytes: storage.value, activeLoads, modelRuntimeState: state, activeRequests, modelPinned: pinned, modelManagedTemporary: temporary, artifactVerified: verified }) };
}

export function parseLocalMutationIntent(input: unknown): ParseResult<LocalMutationIntent> {
  const parsed = fields(input, ["action", "requiredMemoryBytes", "requiredVramBytes", "requiredStorageBytes", "requiresInternetDownload", "requiresPeerTransfer"], "ERR_LOCAL_INTENT");
  if (!parsed.ok) return parsed;
  const action = parsed.value.action?.value as unknown;
  const memory = bytes(parsed.value.requiredMemoryBytes?.value as unknown, "ERR_INTENT_MEMORY");
  const vram = bytes(parsed.value.requiredVramBytes?.value as unknown, "ERR_INTENT_VRAM");
  const storage = bytes(parsed.value.requiredStorageBytes?.value as unknown, "ERR_INTENT_STORAGE");
  const internet = parsed.value.requiresInternetDownload?.value as unknown;
  const peer = parsed.value.requiresPeerTransfer?.value as unknown;
  if (!ACTIONS.has(action) || !memory.ok || !vram.ok || !storage.ok) return fail("ERR_INTENT_FIELD");
  if (typeof internet !== "boolean" || typeof peer !== "boolean") return fail("ERR_INTENT_BOOLEAN");
  return { ok: true, value: frozen<LocalMutationIntent>({ action, requiredMemoryBytes: memory.value, requiredVramBytes: vram.value, requiredStorageBytes: storage.value, requiresInternetDownload: internet, requiresPeerTransfer: peer }) };
}

function lacksCapacity(available: ByteAmount, reserve: ByteAmount, required: ByteAmount): boolean {
  return available < reserve || required > available - reserve;
}

export function evaluateLocalMutation(policy: LocalSafetyPolicy, snapshot: LocalSafetySnapshot, intent: LocalMutationIntent): LocalPolicyDecision {
  const reasons = new Set<LocalPolicyReason>();
  if (!snapshot.observationFresh) reasons.add("stale-observation");
  if (lacksCapacity(snapshot.availableMemoryBytes, policy.minimumFreeMemoryBytes, intent.requiredMemoryBytes)) reasons.add("insufficient-memory");
  if (lacksCapacity(snapshot.availableVramBytes, policy.minimumFreeVramBytes, intent.requiredVramBytes)) reasons.add("insufficient-vram");
  if (lacksCapacity(snapshot.availableStorageBytes, policy.minimumFreeStorageBytes, intent.requiredStorageBytes)) reasons.add("insufficient-storage");
  if (intent.requiresInternetDownload && !policy.allowInternetDownload) reasons.add("internet-download-disabled");
  if (intent.requiresPeerTransfer && !policy.allowPeerTransfer) reasons.add("peer-transfer-disabled");

  const state = snapshot.modelRuntimeState;
  if (intent.action === "load") {
    if (snapshot.activeLoads >= policy.maxConcurrentLoads) reasons.add("load-concurrency-limit");
    if (!snapshot.artifactVerified) reasons.add("artifact-unverified");
  } else if (intent.action === "drain") {
    if (state !== "serving") reasons.add("model-not-idle");
  } else if (intent.action === "unload" || intent.action === "set-options") {
    if (snapshot.activeRequests > 0) reasons.add("active-requests");
    if (state !== "loaded-idle") reasons.add("model-not-idle");
  } else if (intent.action === "install") {
    if (snapshot.activeRequests > 0) reasons.add("active-requests");
    if (state !== null && state !== "unloaded") reasons.add("model-not-idle");
  } else if (intent.action === "remove-managed-artifact" || intent.action === "evict-temporary") {
    if (snapshot.activeRequests > 0) reasons.add("active-requests");
    if (state !== "unloaded") reasons.add("model-not-idle");
    if (!snapshot.modelManagedTemporary) reasons.add("model-not-temporary");
    if (snapshot.modelPinned) reasons.add("model-pinned");
    if (intent.action === "evict-temporary" && !policy.allowTemporaryEviction) reasons.add("eviction-disabled");
  }
  const ordered = Object.freeze(REASON_ORDER.filter((reason) => reasons.has(reason)));
  return ordered.length === 0
    ? Object.freeze({ allowed: true as const, reasons: Object.freeze([]) as readonly [] })
    : Object.freeze({ allowed: false as const, reasons: ordered });
}
