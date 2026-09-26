import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateLocalMutation,
  parseLocalMutationIntent,
  parseLocalSafetyPolicy,
  parseLocalSafetySnapshot,
} from "./local-policy.js";

const policyInput = (overrides: Record<string, unknown> = {}) => ({
  minimumFreeMemoryBytes: 10, minimumFreeVramBytes: 10, minimumFreeStorageBytes: 10,
  maxConcurrentLoads: 2, allowInternetDownload: true, allowPeerTransfer: true,
  allowTemporaryEviction: true, ...overrides,
});
const snapshotInput = (overrides: Record<string, unknown> = {}) => ({
  observedAt: "2026-09-26T11:00:00.000Z", observationFresh: true,
  availableMemoryBytes: 100, availableVramBytes: 100, availableStorageBytes: 100,
  activeLoads: 0, modelRuntimeState: "unloaded", activeRequests: 0,
  modelPinned: false, modelManagedTemporary: true, artifactVerified: true, ...overrides,
});
const intentInput = (action: string, overrides: Record<string, unknown> = {}) => ({
  action, requiredMemoryBytes: 20, requiredVramBytes: 20, requiredStorageBytes: 20,
  requiresInternetDownload: false, requiresPeerTransfer: false, ...overrides,
});
function parsed(action: string, snapshotOverrides: Record<string, unknown> = {}, policyOverrides: Record<string, unknown> = {}, intentOverrides: Record<string, unknown> = {}) {
  const policy = parseLocalSafetyPolicy(policyInput(policyOverrides));
  const snapshot = parseLocalSafetySnapshot(snapshotInput(snapshotOverrides));
  const intent = parseLocalMutationIntent(intentInput(action, intentOverrides));
  assert.equal(policy.ok && snapshot.ok && intent.ok, true);
  if (!policy.ok || !snapshot.ok || !intent.ok) throw new Error("fixture invalid");
  return evaluateLocalMutation(policy.value, snapshot.value, intent.value);
}

test("strictly parses and freezes policy, snapshot, and intent", () => {
  for (const result of [parseLocalSafetyPolicy(policyInput()), parseLocalSafetySnapshot(snapshotInput()), parseLocalMutationIntent(intentInput("load"))]) {
    assert.equal(result.ok, true); if (result.ok) { assert.equal(Object.getPrototypeOf(result.value), null); assert.equal(Object.isFrozen(result.value), true); }
  }
  assert.equal(parseLocalSafetyPolicy(policyInput({ maxConcurrentLoads: 0 })).ok, false);
  assert.equal(parseLocalSafetySnapshot(snapshotInput({ activeLoads: 65 })).ok, false);
  assert.equal(parseLocalMutationIntent(intentInput("delete")).ok, false);
});

test("rejects exact-key, accessor, custom prototype, and hostile inputs without throwing", () => {
  assert.equal(parseLocalSafetyPolicy({ ...policyInput(), extra: true }).ok, false);
  assert.equal(parseLocalSafetySnapshot(Object.assign(Object.create({ inherited: true }), snapshotInput())).ok, false);
  let invoked = false; const accessor = intentInput("load"); Object.defineProperty(accessor, "action", { get() { invoked = true; throw new Error("no"); } });
  assert.equal(parseLocalMutationIntent(accessor).ok, false); assert.equal(invoked, false);
  const hostile = new Proxy({}, { ownKeys() { throw new Error("hostile"); } });
  assert.doesNotThrow(() => parseLocalSafetyPolicy(hostile));
  const revoked = Proxy.revocable(snapshotInput(), {}); revoked.revoke();
  assert.doesNotThrow(() => parseLocalSafetySnapshot(revoked.proxy));
});

test("allows exact resource boundary and denies shortages without overflow", () => {
  assert.equal(parsed("load", {}, {}, { requiredMemoryBytes: 90, requiredVramBytes: 90, requiredStorageBytes: 90 }).allowed, true);
  const denied = parsed("load", { availableMemoryBytes: Number.MAX_SAFE_INTEGER }, { minimumFreeMemoryBytes: Number.MAX_SAFE_INTEGER }, { requiredMemoryBytes: 1 });
  assert.deepStrictEqual(denied.reasons, ["insufficient-memory"]);
  const multi = parsed("load", { availableMemoryBytes: 9, availableVramBytes: 9, availableStorageBytes: 9 });
  assert.deepStrictEqual(multi.reasons.slice(0, 3), ["insufficient-memory", "insufficient-vram", "insufficient-storage"]);
});

test("stale observation and transfer policy always fail closed", () => {
  const decision = parsed("load", { observationFresh: false }, { allowInternetDownload: false, allowPeerTransfer: false }, { requiresInternetDownload: true, requiresPeerTransfer: true });
  assert.deepStrictEqual(decision.reasons.filter((reason) => reason.includes("observation") || reason.includes("disabled")), ["stale-observation", "internet-download-disabled", "peer-transfer-disabled"]);
});

test("load enforces concurrency and verified artifacts", () => {
  assert.equal(parsed("load").allowed, true);
  assert.deepStrictEqual(parsed("load", { activeLoads: 2, artifactVerified: false }).reasons, ["load-concurrency-limit", "artifact-unverified"]);
});

test("drain, unload, and set-options enforce runtime and activity", () => {
  assert.equal(parsed("drain", { modelRuntimeState: "serving", activeRequests: 4 }).allowed, true);
  assert.deepStrictEqual(parsed("drain", { modelRuntimeState: "loaded-idle" }).reasons, ["model-not-idle"]);
  assert.equal(parsed("unload", { modelRuntimeState: "loaded-idle" }).allowed, true);
  assert.deepStrictEqual(parsed("unload", { modelRuntimeState: "serving", activeRequests: 1 }).reasons, ["active-requests", "model-not-idle"]);
  assert.equal(parsed("set-options", { modelRuntimeState: "loaded-idle" }).allowed, true);
});

test("install requires inactive null or unloaded model and obeys acquisition policy", () => {
  assert.equal(parsed("install", { modelRuntimeState: null }).allowed, true);
  assert.equal(parsed("install", { modelRuntimeState: "unloaded" }).allowed, true);
  assert.deepStrictEqual(parsed("install", { modelRuntimeState: "serving", activeRequests: 1 }).reasons, ["active-requests", "model-not-idle"]);
});

test("managed removal and eviction protect active, user, and pinned models", () => {
  assert.equal(parsed("remove-managed-artifact").allowed, true);
  const blocked = parsed("remove-managed-artifact", { activeRequests: 1, modelRuntimeState: "serving", modelManagedTemporary: false, modelPinned: true });
  assert.deepStrictEqual(blocked.reasons, ["active-requests", "model-not-idle", "model-not-temporary", "model-pinned"]);
  assert.equal(parsed("evict-temporary").allowed, true);
  assert.deepStrictEqual(parsed("evict-temporary", {}, { allowTemporaryEviction: false }).reasons, ["eviction-disabled"]);
});

test("reasons are deterministic, deduplicated, and decisions frozen", () => {
  const decision = parsed("evict-temporary", { observationFresh: false, availableMemoryBytes: 0, activeRequests: 1, modelRuntimeState: "serving", modelManagedTemporary: false, modelPinned: true }, { allowTemporaryEviction: false });
  assert.deepStrictEqual(decision.reasons, ["stale-observation", "insufficient-memory", "active-requests", "model-not-idle", "eviction-disabled", "model-not-temporary", "model-pinned"]);
  assert.equal(new Set(decision.reasons).size, decision.reasons.length);
  assert.equal(Object.isFrozen(decision), true); assert.equal(Object.isFrozen(decision.reasons), true);
});
