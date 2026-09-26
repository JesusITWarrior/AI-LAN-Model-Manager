import assert from "node:assert/strict";
import test from "node:test";
import { parseInstalledModelObservation, parseModelCapability, parseProviderObservation } from "./model-observations.js";

const capability = (overrides: Record<string, unknown> = {}) => ({ tools: true, vision: false, reasoning: true, modalities: ["text"], contextWindow: 8192, ...overrides });
const provider = (overrides: Record<string, unknown> = {}) => ({ providerId: "provider-1", kind: "ollama", displayName: "Local Ollama", endpoint: "http://127.0.0.1:11434", health: "ready", version: null, observedAt: "2026-09-26T10:00:00.000Z", ...overrides });
const model = (overrides: Record<string, unknown> = {}) => ({ modelId: "model-1", providerId: "provider-1", displayName: "Example Model", artifactState: "installed", runtimeState: "unloaded", activeRequests: 0, sizeBytes: null, managedTemporary: false, pinned: false, capability: capability(), observedAt: "2026-09-26T10:00:00.000Z", ...overrides });

test("accepts all provider kinds and health states", () => {
  for (const kind of ["ollama", "lm-studio", "custom"]) assert.equal(parseProviderObservation(provider({ kind })).ok, true);
  for (const health of ["unavailable", "starting", "ready", "degraded", "failed"]) assert.equal(parseProviderObservation(provider({ health })).ok, true);
});

test("validates provider ids, names, versions, times, and URLs", () => {
  assert.equal(parseProviderObservation(provider({ version: "1.2.3" })).ok, true);
  assert.equal(parseProviderObservation(provider({ endpoint: "https://host.example/v1?mode=local" })).ok, true);
  for (const value of [provider({ providerId: "bad/id" }), provider({ displayName: "bad\nname" }), provider({ version: "" }), provider({ observedAt: "bad" }), provider({ endpoint: "ftp://host" }), provider({ endpoint: "http://user:pass@host" }), provider({ endpoint: "http://host/#secret" })]) assert.equal(parseProviderObservation(value).ok, false);
});

test("parses capability enums, bounds, and unique dense modalities", () => {
  assert.equal(parseModelCapability(capability({ modalities: ["text", "image", "audio"], contextWindow: null })).ok, true);
  assert.equal(parseModelCapability(capability({ contextWindow: 1 })).ok, true);
  assert.equal(parseModelCapability(capability({ contextWindow: 10_000_000 })).ok, true);
  for (const value of [capability({ modalities: ["text", "text"] }), capability({ modalities: ["video"] }), capability({ contextWindow: 0 }), capability({ contextWindow: 10_000_001 }), capability({ tools: 1 })]) assert.equal(parseModelCapability(value).ok, false);
  const sparse = new Array(2); sparse[0] = "text";
  assert.equal(parseModelCapability(capability({ modalities: sparse })).ok, false);
  const decorated = ["text"] as string[] & { note?: string }; decorated.note = "no";
  assert.equal(parseModelCapability(capability({ modalities: decorated })).ok, false);
});

test("accepts model state enums and field bounds", () => {
  for (const artifactState of ["installed", "installing", "removing", "failed"]) assert.equal(parseInstalledModelObservation(model({ artifactState })).ok, true);
  for (const runtimeState of ["unloaded", "loading", "loaded-idle", "serving", "draining", "unloading", "failed", "unknown"]) assert.equal(parseInstalledModelObservation(model({ runtimeState })).ok, true);
  assert.equal(parseInstalledModelObservation(model({ activeRequests: 1_000_000, runtimeState: "serving", sizeBytes: Number.MAX_SAFE_INTEGER })).ok, true);
  assert.equal(parseInstalledModelObservation(model({ pinned: true, managedTemporary: true })).ok, true);
});

test("enforces active request/runtime invariants and nested validation", () => {
  for (const runtimeState of ["unloaded", "loading", "loaded-idle", "unloading", "failed", "unknown"]) assert.equal(parseInstalledModelObservation(model({ runtimeState, activeRequests: 1 })).ok, false);
  assert.equal(parseInstalledModelObservation(model({ runtimeState: "serving", activeRequests: 1 })).ok, true);
  assert.equal(parseInstalledModelObservation(model({ runtimeState: "draining", activeRequests: 1 })).ok, true);
  for (const value of [model({ modelId: "bad/id" }), model({ activeRequests: -1 }), model({ activeRequests: 1_000_001 }), model({ sizeBytes: -1 }), model({ pinned: "yes" }), model({ capability: capability({ tools: 1 }) })]) assert.equal(parseInstalledModelObservation(value).ok, false);
});

test("strictly rejects extra keys, symbols, custom prototypes, and accessors", () => {
  assert.equal(parseProviderObservation({ ...provider(), extra: true }).ok, false);
  assert.equal(parseInstalledModelObservation(Object.assign(Object.create({ inherited: true }), model())).ok, false);
  const symbolic = model(); Object.defineProperty(symbolic, Symbol("extra"), { value: true });
  assert.equal(parseInstalledModelObservation(symbolic).ok, false);
  let invoked = false; const accessor = provider(); Object.defineProperty(accessor, "kind", { get() { invoked = true; throw new Error("no"); } });
  assert.equal(parseProviderObservation(accessor).ok, false); assert.equal(invoked, false);
});

test("returns detached deeply frozen null-prototype outputs", () => {
  const input = model(); const parsed = parseInstalledModelObservation(input);
  assert.equal(parsed.ok, true); if (!parsed.ok) return;
  assert.equal(Object.getPrototypeOf(parsed.value), null);
  assert.equal(Object.isFrozen(parsed.value), true);
  assert.equal(Object.getPrototypeOf(parsed.value.capability), null);
  assert.equal(Object.isFrozen(parsed.value.capability), true);
  assert.equal(Object.isFrozen(parsed.value.capability.modalities), true);
  input.capability.modalities[0] = "image";
  assert.equal(parsed.value.capability.modalities[0], "text");
});

test("never throws for hostile and revoked roots or modality arrays", () => {
  const hostile = new Proxy({}, { ownKeys() { throw new Error("hostile"); } });
  assert.doesNotThrow(() => parseProviderObservation(hostile));
  const revoked = Proxy.revocable(model(), {}); revoked.revoke();
  assert.doesNotThrow(() => parseInstalledModelObservation(revoked.proxy));
  const modalities = new Proxy([], { ownKeys() { throw new Error("hostile"); } });
  assert.doesNotThrow(() => parseModelCapability(capability({ modalities })));
});
