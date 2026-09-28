import assert from "node:assert/strict";
import test from "node:test";
import {
  matchCapabilities,
  matchOne,
  parseCapabilityProfile,
  parseObservedModelCapability,
  selectCapabilityCandidate,
  type CapabilityProfile,
  type ObservedModelCapability,
  type UtcTimestamp,
} from "./capability-matching.js";

const TIMESTAMP = "2026-09-28T10:00:00.000Z" as UtcTimestamp;

test("observed explicit unknowns and lower-level capability seam parse",()=>{const result=parseObservedModelCapability(observed({purpose:null,tools:null,vision:null,reasoning:null,capability:{tools:true,vision:false,reasoning:true,modalities:["text"],contextWindow:4096}}));assert.equal(result.ok,true);if(result.ok){assert.equal(result.value.purpose,null);assert.equal(result.value.tools,null);assert.equal(result.value.capability?.tools,true);}});

test("hostile match inputs and invalid freshness fail closed without throwing",()=>{const p=parseProfile(profileInput()),o=parseObserved(observed());const hostile=Proxy.revocable({},{});hostile.revoke();assert.doesNotThrow(()=>matchOne(hostile.proxy as never,o));assert.deepEqual(matchOne(hostile.proxy as never,o).reasons,["PROFILE_INVALID"]);assert.deepEqual(matchOne(p,o,"bad" as never,1000).reasons,["OBSERVATION_INVALID"]);assert.deepEqual(matchOne(p,o,TIMESTAMP,-1).reasons,["OBSERVATION_INVALID"]);});

test("pool and candidate selection results are deeply immutable and deterministic",()=>{const p=parseProfile(profileInput()),o=parseObserved(observed()),pool=matchCapabilities(p,[o],TIMESTAMP,1000);assert.equal(Object.isFrozen(pool),true);assert.equal(Object.isFrozen(pool.reasons),true);const selection=selectCapabilityCandidate(p,[{candidateId:"b",capability:o},{candidateId:"a",capability:o}],TIMESTAMP,1000);assert.equal(selection.candidateId,"a");assert.equal(Object.isFrozen(selection),true);assert.equal(Object.isFrozen(selection.reasons),true);});

// Brand a plain RFC-3339 string to the UtcTimestamp contract (no leak; exact value only).
function utc(label: string): UtcTimestamp {
  return label as unknown as UtcTimestamp;
}

// Minimal baseline profile: requires an exact chat text modality only.
function profile(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { version: 1, purpose: "chat", requiredModalities: ["text"], ...overrides };
}

function profileInput(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const base: Record<string, unknown> = {
    version: 1, purpose: "chat", requiredModalities: ["text"], contextWindow: 128 * 1024,
    tools: true, vision: null, reasoning: null, embeddings: null,
    provider: null, quantization: null, minimumMemoryBytes: null,
    minimumVramBytes: null, minimumDiskBytes: null, preferences: [], unknowns: [],
  };
  return { ...base, ...overrides };
}

function observed(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const base: Record<string, unknown> = {
    purpose: "chat", modalities: ["text"], contextWindow: 128 * 1024,
    tools: true, vision: false, reasoning: false, embeddings: null,
    provider: "ollama", quantization: "q4_k_M", sizeBytes: null,
    requiresMemoryBytes: null, requiresVramBytes: null, requiresDiskBytes: null, observedAt: TIMESTAMP,
  };
  return { ...base, ...overrides };
}

function parseProfile(input: Record<string, unknown>) {
  const result = parseCapabilityProfile(input);
  assert.equal(result.ok, true, JSON.stringify(Object.keys(input)));
  if (!result.ok) throw new Error("profile fixture invalid");
  return result.value;
}
function parseObserved(input: Record<string, unknown>) {
  const result = parseObservedModelCapability(input);
  assert.equal(result.ok, true, JSON.stringify(Object.keys(input)));
  if (!result.ok) throw new Error("observed fixture invalid");
  return result.value;
}

// ---------------------------------------------------------------------------
// Strict parsing (bounded immutable DTOs)
// ---------------------------------------------------------------------------

test("accepts a minimal chat profile and a minimal observed capability", () => {
  const p = parseProfile(profileInput());
  assert.equal(p.version, 1);
  assert.equal(p.purpose, "chat");
  assert.equal(p.requiredModalities.length, 1);

  const o = parseObserved(observed());
  assert.equal(o.purpose, "chat");
  assert.equal(o.modalities.length, 1);
  assert.equal(o.tools, true);
  assert.equal(o.embeddings, null);
  assert.equal(matchOne(p, o).match, true);
});

test("accepts all three modalities, provider kinds, and explicit reason/quantization constraints", () => {
  const p = parseProfile(profileInput({
    purpose: "text", requiredModalities: ["text", "image", "audio"],
    provider: "ollama", quantization: "q8_0",
    tools: null, vision: true, reasoning: true, embeddings: true,
    minimumMemoryBytes: 0, minimumVramBytes: 0, minimumDiskBytes: 0,
  }));
  const o = parseObserved(observed({ purpose: "chat", modalities: ["text", "image", "audio"],
    tools: true, vision: true, reasoning: true, embeddings: true, provider: "ollama",
    quantization: "q8_0", requiresMemoryBytes: 0, requiresVramBytes: 0, requiresDiskBytes: 0 }));
  assert.equal(matchOne(p, o).match, true);
});

test("rejects version, modality, and field-bound violations", () => {
  assert.equal(parseCapabilityProfile(profileInput({ version: 0 })).ok, false);
  assert.equal(parseCapabilityProfile(profileInput({ version: 65 })).ok, false);
  assert.equal(parseCapabilityProfile(profileInput({ purpose: "vision" })).ok, false);
  assert.equal(parseCapabilityProfile(profileInput({ purpose: null })).ok, false);
  assert.equal(parseCapabilityProfile(profileInput({ purpose: "image" })).ok, false);
  assert.equal(parseCapabilityProfile(profileInput({ requiredModalities: ["text", "text"] })).ok, false);
  assert.equal(parseCapabilityProfile(profileInput({ requiredModalities: ["video"] })).ok, false);
  assert.equal(parseCapabilityProfile(profileInput({ requiredModalities: ["text"] })).ok, true);
  assert.equal(parseCapabilityProfile(profileInput({ contextWindow: 0 })).ok, false);
  assert.equal(parseCapabilityProfile(profileInput({ contextWindow: 10_000_001 })).ok, false);
  assert.equal(parseCapabilityProfile(profileInput({ tools: "yes" })).ok, false);
  assert.equal(parseCapabilityProfile(profileInput({ provider: "/bad" })).ok, false);
  assert.equal(parseCapabilityProfile(profileInput({ quantization: "q8 0" })).ok, false);
  assert.equal(parseObservedModelCapability(observed({ version: 1 })).ok, false);
});

test("profiles require the requiredModalities field, but observed does not", () => {
  assert.equal(parseCapabilityProfile({ version: 1, purpose: "chat" }).ok, false);
  // Observed DTO omits requiredModalities: still parseable (treated as no output constraint).
  assert.equal(parseObservedModelCapability({ purpose: "chat", contextWindow: 8192, tools: true,
    vision: true, reasoning: true, embeddings: null, provider: "ollama", quantization: "q4_k_M",
    sizeBytes: null, requiresMemoryBytes: null, requiresVramBytes: null, requiresDiskBytes: null,
    observedAt: TIMESTAMP }).ok, true);
});

// ---------------------------------------------------------------------------
// Strictness / hostile / accessor / prototype attacks — mirror the existing seams
// ---------------------------------------------------------------------------

test("strictly rejects extra keys, custom prototypes, accessor, and hostile proxies without throwing", () => {
  assert.equal(parseCapabilityProfile({ ...profileInput(), extra: true }).ok, false);
  assert.equal(parseCapabilityProfile(Object.assign(Object.create({ inherited: true }), profileInput())).ok, false);
  const accessor = profileInput(); Object.defineProperty(accessor, "tools", { get() { throw new Error("no"); } });
  assert.equal(parseCapabilityProfile(accessor).ok, false);
  const hostile = new Proxy({}, { ownKeys() { throw new Error("hostile"); } });
  assert.doesNotThrow(() => parseCapabilityProfile(hostile));
  const revoked = Proxy.revocable(profileInput(), {}); revoked.revoke();
  assert.doesNotThrow(() => parseCapabilityProfile(revoked.proxy));
  assert.doesNotThrow(() => parseObservedModelCapability(hostile));
  const modalitiesProxy = profileInput(); modalitiesProxy.requiredModalities = new Proxy(["text"], { get() { throw new Error("hostile"); } });
  assert.doesNotThrow(() => parseCapabilityProfile(modalitiesProxy));
});

test("returns deeply detached, null-prototype, frozen outputs; input mutation does not leak", () => {
  const input = profileInput();
  const result = parseCapabilityProfile(input);
  assert.equal(result.ok, true); if (!result.ok) return;
  const profile = result.value as CapabilityProfile;
  assert.equal(Object.getPrototypeOf(profile), null);
  assert.equal(Object.isFrozen(profile), true);
  assert.equal(Object.isFrozen(profile.requiredModalities), true);
  input.version = 2;
  assert.equal(profile.version, 1);
  (input.requiredModalities as string[]).push("image");
  assert.equal(profile.requiredModalities.length, 1);

  const obs = parseObservedModelCapability(observed());
  assert.equal(obs.ok, true); if (!obs.ok) return;
  const observedValue = obs.value as ObservedModelCapability;
  assert.equal(Object.getPrototypeOf(observedValue), null);
  assert.equal(Object.isFrozen(observedValue), true);
});

test("unknowns and preferences are strictly validated", () => {
  assert.equal(parseCapabilityProfile(profileInput({ unknowns: ["CONTEXT_WINDOW"], preferences: ["tools"] })).ok, true);
  assert.equal(parseCapabilityProfile(profileInput({ unknowns: ["bogus"] })).ok, false);
  assert.equal(parseCapabilityProfile(profileInput({ unknowns: ["tools", "tools"] })).ok, false);
  assert.equal(parseCapabilityProfile(profileInput({ preferences: ["tools", "tools"] })).ok, false);
  assert.equal(parseCapabilityProfile(profileInput({ preferences: ["nope"] })).ok, false);
  assert.equal(parseCapabilityProfile(profileInput({ preferences: [] })).ok, true);
  assert.equal(parseCapabilityProfile(profileInput({ unknowns: [] })).ok, true);
});

// ---------------------------------------------------------------------------
// Matching semantics: hard vs. preference, fail-closed, determinism
// ---------------------------------------------------------------------------

test("fails closed when a required modality is absent (chat implies text + required modalities)", () => {
  const p = parseProfile(profileInput());
  const o = parseObserved(observed({ modalities: ["image", "audio"] }));
  const result = matchOne(p, o);
  assert.equal(result.match, false);
  assert.equal(result.reasons.length, 1);
  assert.equal(result.reasons[0], "MODALITY_MISSING");
});

test("context window hard-fail when observed is null or below", () => {
  const p = parseProfile(profileInput({ contextWindow: 64 * 1024 }));
  const o = parseObserved(observed({ contextWindow: 8 * 1024 }));
  assert.equal(matchOne(p, o).reasons[0], "CONTEXT_WINDOW_INSUFFICIENT");
  const oNull = parseObserved(observed({ contextWindow: null }));
  assert.equal(matchOne(p, oNull).reasons[0], "CONTEXT_WINDOW_INSUFFICIENT");
});

test("provider/quantization constraints hard-fail on mismatch or unknown observation", () => {
  const p = parseProfile(profileInput({ provider: "ollama", quantization: "q8_0" }));
  assert.equal(matchOne(p, parseObserved(observed({ provider: "lm-studio" }))).reasons[0], "PROVIDER_MISMATCH");
  assert.equal(matchOne(p, parseObserved(observed({ provider: null }))).reasons[0], "PROVIDER_MISMATCH");
  assert.equal(matchOne(p, parseObserved(observed({ provider: "ollama", quantization: "q4_k_M" }))).reasons[0], "QUANTIZATION_FORMAT_MISMATCH");
  assert.equal(matchOne(p, parseObserved(observed({ provider: "ollama", quantization: null }))).reasons[0], "QUANTIZATION_FORMAT_MISMATCH");
});

test("embeddings: supported satisfies, unsupported fails, unknown fails closed", () => {
  const p = parseProfile(profileInput({ embeddings: true }));
  assert.equal(matchOne(p, parseObserved(observed({ embeddings: true }))).match, true);
  assert.equal(matchOne(p, parseObserved(observed({ embeddings: false }))).reasons[0], "EMBEDDINGS_UNSUPPORTED");
  assert.equal(matchOne(p, parseObserved(observed({ embeddings: null }))).reasons[0], "EMBEDDINGS_UNKNOWN");
});

test("minimum resources fail closed when observation is unknown or below ceiling", () => {
  const p = parseProfile(profileInput({
    minimumMemoryBytes: 100, minimumVramBytes: 100, minimumDiskBytes: 100,
  }));
  assert.equal(matchOne(p, parseObserved(observed({ requiresMemoryBytes: 90, requiresVramBytes: 90, requiresDiskBytes: 90 }))).match, true);
  assert.equal(matchOne(p, parseObserved(observed({ requiresMemoryBytes: 110 }))).reasons[0], "MINIMUM_MEMORY_INSUFFICIENT");
  assert.equal(matchOne(p, parseObserved(observed({ requiresMemoryBytes: null }))).reasons[0], "MINIMUM_MEMORY_INSUFFICIENT");
  const multi = matchOne(p, parseObserved(observed({ requiresMemoryBytes: 110, requiresVramBytes: 110, requiresDiskBytes: 110 })));
  assert.deepStrictEqual(multi.reasons, ["MINIMUM_MEMORY_INSUFFICIENT", "MINIMUM_VRAM_INSUFFICIENT", "MINIMUM_DISK_INSUFFICIENT"]);
});

test("hard and preference requirements coexist: a match carries preference tokens but no fail codes", () => {
  const p = parseProfile(profileInput({
    tools: true, vision: true, preferences: ["tools", "vision", "largeContext"],
  }));
  const o = parseObserved(observed({ tools: true, vision: true, contextWindow: 256 * 1024 }));
  const result = matchOne(p, o);
  assert.equal(result.match, true);
  assert.equal(result.reasons.length, 0);
  assert.deepStrictEqual(result.preferences, ["tools", "vision", "largeContext"]);
  assert.equal(result.preferenceScore, 16 + 8 + 1);
});

test("preferences are soft: an optional vision requirement may be unmet without a hard fail", () => {
  const p = parseProfile(profileInput({ vision: null, preferences: ["vision"] }));
  const o = parseObserved(observed({ vision: false }));
  const result = matchOne(p, o);
  assert.equal(result.match, true);
  assert.equal(result.reasons.length, 0);
  assert.deepStrictEqual(result.preferences, []);
});

test("unmet preferences are simply not reported and score drops to 0 when none satisfied", () => {
  const p = parseProfile(profileInput({ tools: null, reasoning: null, preferences: ["tools", "reasoning"] }));
  const o = parseObserved(observed({ tools: false, reasoning: false }));
  const result = matchOne(p, o);
  assert.equal(result.match, true);
  assert.equal(result.reasons.length, 0);
  assert.equal(result.preferenceScore, 0);
  assert.deepStrictEqual(result.preferences, []);
});

test("no hard requirements still matches and evaluates preferences (never fails closed)", () => {
  const p = parseProfile(profileInput({ contextWindow: null, tools: null, vision: null, reasoning: null }));
  const o = parseObserved(observed());
  const result = matchOne(p, o);
  assert.equal(result.match, true);
  assert.equal(result.reasons.length, 0);
});

// ---------------------------------------------------------------------------
// Deterministic ordering, ties, and pool-level substitution
// ---------------------------------------------------------------------------

test("pool returns the single best model and no hard-fail codes on substitution", () => {
  const p = parseProfile(profileInput({ tools: true, vision: true, preferences: ["tools", "vision"] }));
  const pool = [
    parseObserved(observed({ tools: true, vision: false })),
    parseObserved(observed({ tools: false, vision: true })),
    parseObserved(observed({ tools: true, vision: true })),
  ];
  const result = matchCapabilities(p, pool);
  assert.equal(result.substitutable, true);
  assert.deepStrictEqual(result.reasons, []);
  assert.equal(result.best?.match, true);
  assert.equal(result.best?.reasons.length, 0);
  // Third pool entry has both tools+vision => score 16+8 => best.
  assert.equal(result.best?.preferenceScore, 24);
});

test("pool returns canonical union of hard-fail codes when nothing matches", () => {
  const p = parseProfile(profileInput({ tools: true, reasoning: true, provider: "ollama" }));
  const pool = [
    parseObserved(observed({ tools: false })),
    parseObserved(observed({ reasoning: false })),
    parseObserved(observed({ provider: "lm-studio" })),
  ];
  const result = matchCapabilities(p, pool);
  assert.equal(result.substitutable, false);
  assert.equal(result.best, null);
  assert.deepStrictEqual(result.reasons, ["TOOLS_MISSING", "REASONING_MISSING", "PROVIDER_MISMATCH"]);
});

test("pool is empty => substitutable false and no best, and union does not include non-hard codes", () => {
  const p = parseProfile(profileInput());
  const result = matchCapabilities(p, []);
  assert.equal(result.substitutable, false);
  assert.equal(result.best, null);
  assert.deepStrictEqual(result.reasons, []);
});

test("ties on score preserve input order (stable) rather than pool order", () => {
  const p = parseProfile(profileInput({ preferences: ["tools"] }));
  const first = parseObserved(observed({ tools: true, vision: false }));
  const second = parseObserved(observed({ tools: true, vision: true }));
  const result = matchCapabilities(p, [first, second]);
  // Both score 16 (only `tools` preference is scored); input order tie picks the pool entry.
  assert.equal(result.best?.match, true);
  assert.equal(result.best?.preferenceScore, 16);
  assert.deepStrictEqual(result.best?.preferences, ["tools"]);
});

// ---------------------------------------------------------------------------
// Stale / unknown / stale-only: fail closed with OBSERVATION_STALE
// ---------------------------------------------------------------------------

test("stale observation fails closed with OBSERVATION_STALE regardless of other dimensions", () => {
  const p = parseProfile(profileInput());
  const o = parseObserved(observed({ purpose: "chat", modalities: ["text"], contextWindow: 128 * 1024,
    tools: true, provider: "ollama" }));
  const now = utc("2026-09-28T10:10:00.000Z");
  const result = matchOne(p, o, now, 60_000);
  assert.equal(result.match, false);
  assert.deepStrictEqual(result.reasons, ["OBSERVATION_STALE"]);
  // No other dimension codes leak.
  assert.equal(result.reasons.some((code) => code !== "OBSERVATION_STALE"), false);
});

test("non-stale observation within threshold does not add OBSERVATION_STALE", () => {
  const p = parseProfile(profileInput());
  const o = parseObserved(observed());
  const now = utc("2026-09-28T10:01:00.000Z");
  const result = matchOne(p, o, now, 60_000);
  assert.equal(result.match, true);
  assert.equal(result.reasons.length, 0);
});

test("stale reason is included in the pool union when some candidates are stale", () => {
  const p = parseProfile(profileInput());
  const pool = [
    parseObserved(observed({ observedAt: "2026-09-28T09:00:00.000Z" })),
    parseObserved(observed({ provider: "lm-studio" })),
  ];
  const now = utc("2026-09-28T10:10:00.000Z");
  const result = matchCapabilities(p, pool, now, 60_000);
  assert.equal(result.substitutable, false);
  assert.equal(result.reasons.includes("OBSERVATION_STALE"), true);
});

// ---------------------------------------------------------------------------
// No secret / topology leakage
// ---------------------------------------------------------------------------

test("match output carries no topology: no provider id, endpoint, model name, or byte counts leak", () => {
  const p = parseProfile(profileInput({ provider: "ollama", quantization: "q8_0" }));
  const o = parseObserved(observed({ provider: "ollama",
    requiresMemoryBytes: 4294967296, sizeBytes: 4294967296 }));
  const result = matchOne(p, o);
  const text = JSON.stringify(result);
  for (const forbidden of ["4294967296", "8192", "hostId", "provider-1", "http", "127.0.0.1", "endpoint"]) {
    assert.equal(text.includes(forbidden), false, `expected no leak of ${forbidden}`);
  }
});

test("matchOne on a mismatching, non-optional-only profile never leaks numeric resource footprints", () => {
  const p = parseProfile(profileInput({ minimumMemoryBytes: 100, minimumVramBytes: 100, minimumDiskBytes: 100 }));
  const o = parseObserved(observed({ requiresMemoryBytes: 999999999, requiresVramBytes: 888888888, requiresDiskBytes: 777777777 }));
  const result = matchOne(p, o);
  const text = JSON.stringify(result);
  for (const forbidden of ["999999999", "888888888", "777777777"]) {
    assert.equal(text.includes(forbidden), false);
  }
});

// ---------------------------------------------------------------------------
// Determinism: identical inputs produce identical outputs
// ---------------------------------------------------------------------------

test("determinism: repeated identical matching is byte-identical", () => {
  const p = parseProfile(profileInput({ tools: true, provider: "ollama", preferences: ["tools", "vision"] }));
  const o = parseObserved(observed({ tools: true, vision: true, provider: "ollama" }));
  const first = JSON.stringify(matchOne(p, o));
  const second = JSON.stringify(matchOne(p, o));
  assert.equal(first, second);
});

test("reason codes appear in canonical order, never the order they occur in the observation", () => {
  const p = parseProfile(profileInput({ reasoning: true, tools: true, vision: true }));
  const o = parseObserved(observed({ tools: false, reasoning: false, vision: false }));
  const result = matchOne(p, o);
  assert.deepStrictEqual(result.reasons, ["TOOLS_MISSING", "VISION_MISSING", "REASONING_MISSING"]);
});
