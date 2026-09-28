/**
 * Resource-safe placement scoring and explanation.
 *
 * Two tightly-coupled seams are provided from this module:
 *
 *   - {@link planPlacement}: fleet-level placement over {@link HostSnapshot}
 *     observations. It is strict (it fail-closes on malformed hosts/requests),
 *     no-throw against hostile inputs (getters/proxies never execute), and its
 *     reason codes are redacted machine identifiers that never echo topology.
 *
 *   - {@link planCapabilityPlacement}: the controller capability-resolver seam.
 *     It selects, among controller-owned {@link CapabilityCandidate} pool
 *     members, one capable, substitutable model — deterministically and
 *     fail-closed, with redacted public reason codes. Target data is never
 *     constructed from caller strings; it can only come from controller-owned
 *     candidates.
 *
 * Guarantees:
 *   - Hard rejection vs. preference score are separated: every host/model that
 *     fails a required check is reported in {@link PlacementPlan.rejected} with
 *     redacted machine codes and never contributes a (possibly winning) score.
 *   - Deterministic: identical inputs produce identical output (canonical reason
 *     ordering, bounded score bands, deterministic tie-break by internal host).
 *   - Redacted: reason codes are stable machine identifiers; they never echo
 *     topology (no endpoints, hostIds, digests, snapshots, provider/model
 *     values, runtime strings, or byte counts).
 *   - Fail-closed: malformed inputs never throw; they fail closed (rejected /
 *     no selection).
 *   - Immutability: {@link PlacementPlan} and every {@link PlacementCandidate}
 *     are null-prototype, deeply frozen, so the selected result is immutable and
 *     explainable.
 *
 * The public reason vocabulary is intentionally closed and ordered (see
 * {@link PLACEMENT_REASON_ORDER}).
 */

import type {
  HostModelObservation, HostSnapshot, PlacementCandidate,
  PlacementPlan, PlacementRejection, PlacementRequest
} from "./types.js";
import {
  HARD_REASON_ORDER,
  matchOne,
  parseCapabilityProfile,
  parseObservedModelCapability,
  selectCapabilityCandidate,
  type CapabilityCandidate,
  type CapabilityProfile,
  type CapabilitySelection,
  type ObservedModelCapability,
} from "./capability-matching.js";
import type { UtcTimestamp } from "./protocol.js";

// ---------------------------------------------------------------------------
// Bounded score bands. Bands are spaced far apart so that the bounded resource
// term, the bounded 13.1 preference score, and the band **never** cross a band
// boundary: a higher band always dominates regardless of resource usage. The
// MAX_RESOURCE_TERM bound keeps the within-band spread below the smallest band
// gap, so band ** always dominates. The 13.1 gap (400_000) is the smallest; the
// within-band spread bound (2 * MAX_RESOURCE_TERM = 399_998) stays strictly
// below it, so no within-band score can reach the next band.
// ---------------------------------------------------------------------------
const BAND_LOADED_IDLE = 2_000_000;
const BAND_SERVING = 1_500_000;
const BAND_INSTALLED = 800_000;
const BAND_ACQUIRE = 400_000;

/** Intra-band spread bound (term + preference). Chosen below the smallest band gap (400_000). */
const MAX_RESOURCE_TERM = 199_999;

/** Upper bound on candidate/host counts processed per plan. */
const MAX_CANDIDATES = 10_000;

/** Opaque model id / runtime token pattern used for request validation. */
const MODEL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;

/** Stable, redacted public error codes shared with capability-matching. */
const ERR_INPUT = "ERR_INPUT";
const ERR_OBSERVED = "ERR_OBSERVED";

// ---------------------------------------------------------------------------
// Public, closed, canonically ordered placement reason codes. The rejection and
// preference payloads share one merged order so every code is stably ordered.
//
// Note: runtime compatibility is reported as a *fixed* code (`RUNTIME_UNAVAILABLE`)
// rather than an interpolated runtime string — interpolated runtime values would
// echo topology and would be silently dropped by the closed `ordered()` filter.
// ---------------------------------------------------------------------------
export const PLACEMENT_REASON_ORDER: readonly string[] = Object.freeze([
  // Host-level hard rejection.
  "HOST_NOT_AUTHORIZED", "HOST_REVOKED", "HOST_OFFLINE", "OBSERVATION_STALE",
  "HOST_RESOURCE_OBSERVATION_UNKNOWN", "HOST_OBSERVATION_INVALID", "HOST_DRAINING",
  "RUNTIME_UNAVAILABLE",
  // Model-level hard rejection.
  "MODEL_NOT_AVAILABLE", "MODEL_DRAINING", "MODEL_PINNED", "LOAD_CONCURRENCY_LIMIT",
  "INSUFFICIENT_MEMORY_AFTER_RESERVE", "INSUFFICIENT_VRAM_AFTER_RESERVE",
  "INSUFFICIENT_STORAGE_AFTER_RESERVE",
  // Capability-eligibility hard rejection (also emitted as a STALE variant).
  "CAPABILITY_INELIGIBLE", "CAPABILITY_STALE",
  // Preference reasons (only on the winning candidate).
  "PLACEMENT_OK", "MODEL_ALREADY_LOADED", "MODEL_SERVING", "MODEL_INSTALLED_READY",
]);

/** Merged order: closed placement vocabulary followed by the 13.1 capability codes. */
const MERGED_REASON_ORDER: readonly string[] = Object.freeze([...PLACEMENT_REASON_ORDER, ...HARD_REASON_ORDER]);

/** Filter a failure set (any vocabulary) into canonical merged order (deduped). */
function ordered(reasons: ReadonlySet<string>): readonly string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const code of MERGED_REASON_ORDER) {
    if (reasons.has(code) && !seen.has(code)) {
      seen.add(code);
      out.push(code);
    }
  }
  return out;
}

function usable(available: number, reserve: number): number {
  return Math.max(0, available - reserve);
}

/** Bounded resource term: higher available headroom scores better within a band. */
function resourceTerm(memoryBytes: number, vramBytes: number): number {
  const raw = Math.floor(memoryBytes / 1_000_000_000) + Math.floor(vramBytes / 1_000_000_000) * 2;
  if (raw <= 0) return 0;
  return Math.min(raw, MAX_RESOURCE_TERM);
}

/** Combine a band with a bounded resource term and bounded 13.1 preference score. */
function candidateScore(band: number, memoryBytes: number, vramBytes: number, preferenceScore: number): number {
  const term = resourceTerm(memoryBytes, vramBytes);
  const preference = Math.max(0, Math.min(preferenceScore, MAX_RESOURCE_TERM));
  return band + Math.min(term + preference, MAX_RESOURCE_TERM);
}

interface EvaluateResult {
  candidate?: PlacementCandidate;
  rejection?: readonly string[];
}

function findModel(models: readonly HostModelObservation[], modelId: string): HostModelObservation | undefined {
  return models.find((model) => model.modelId === modelId);
}

/** Compute the set of modelIds that are pinned anywhere in the fleet. */
function pinnedModelIds(hosts: readonly HostSnapshot[]): Set<string> {
  const ids = new Set<string>();
  for (const host of hosts) {
    for (const model of host.models) {
      if (model.pinned) ids.add(model.modelId);
    }
  }
  return ids;
}

/** Optional 13.1 capability profile shape: accept either raw or parsed. */
function capabilityProfile(request: PlacementRequest): CapabilityProfile | null {
  const profile = request.profile ?? null;
  if (profile === null || profile === undefined) return null;
  const parsed = parseCapabilityProfile(profile);
  return parsed.ok ? parsed.value : null;
}

/**
 * Reflect own enumerable descriptors of an untrusted object, requiring the exact
 * `required` keys (data descriptors) plus any allowed `optional` keys, with no
 * extras and a plain/null prototype. Getters are never invoked — only their
 * descriptors are inspected — so a hostile getter/proxy cannot execute code.
 */
function reflectFields(input: unknown, required: readonly string[], optional: readonly string[]): { ok: true; value: Record<string, PropertyDescriptor> } | { ok: false; error: string } {
  if (typeof input !== "object" || input === null || Array.isArray(input)) return { ok: false, error: ERR_INPUT };
  try {
    const allowed=new Set([...required,...optional]),keys=Reflect.ownKeys(input);
    if(keys.some(key=>typeof key!=="string"||!allowed.has(key)))return{ok:false,error:"ERR_EXTRA_KEY"};
    const proto=Object.getPrototypeOf(input);if(proto!==Object.prototype&&proto!==null)return{ok:false,error:"ERR_PROTO"};
    const descriptors=Object.getOwnPropertyDescriptors(input);
    for(const key of required){const d=descriptors[key];if(!d||!("value" in d))return{ok:false,error:"ERR_MISSING_KEY"};}
    for(const key of optional){const d=descriptors[key];if(d&&!("value" in d))return{ok:false,error:ERR_INPUT};}
    return{ok:true,value:descriptors};
  }catch{return{ok:false,error:ERR_INPUT};}
}

/**
 * Read a dense array field via its descriptors (no method invocation), so a
 * hostile array proxy cannot execute `.map`/`.some`/`.includes` getters.
 */
function readElementArray(descriptors: Record<string, PropertyDescriptor>, key: string): unknown[] | null {
  const descriptor=descriptors[key];if(!descriptor||!("value" in descriptor))return null;const value=descriptor.value;
  try{if(!Array.isArray(value))return null;const all=Object.getOwnPropertyDescriptors(value),length=Object.getOwnPropertyDescriptor(value,"length")?.value;
    if(typeof length!=="number"||!Number.isSafeInteger(length)||length<0||length>MAX_CANDIDATES)return null;
    const keys=Reflect.ownKeys(value);if(keys.length!==length+1||keys.some(item=>typeof item!=="string"||(item!=="length"&&!/^(0|[1-9][0-9]*)$/.test(item))))return null;
    const out:unknown[]=[];for(let i=0;i<length;i++){const d=all[String(i)];if(!d||!("value" in d))return null;out.push(d.value);}return out;
  }catch{return null;}
}

/** Read a single data-descriptor field as a non-negative safe integer. */
function readNonNegInt(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) return null;
  return value;
}

/** Strictly parse a {@link ResourceAmount} (all three fields present as non-negative integers). */
function parseResourceAmount(input: unknown): { memoryBytes: number; vramBytes: number; diskBytes: number } | null {
  const d = reflectFields(input, ["memoryBytes", "vramBytes", "diskBytes"], []);
  if (!d.ok) return null;
  const memoryBytes = readNonNegInt(d.value.memoryBytes!.value);
  const vramBytes = readNonNegInt(d.value.vramBytes!.value);
  const diskBytes = readNonNegInt(d.value.diskBytes!.value);
  if (memoryBytes === null || vramBytes === null || diskBytes === null) return null;
  return { memoryBytes, vramBytes, diskBytes };
}

/** Strictly parse a {@link HostModelObservation} (all required fields, optional capability). */
function parseModelObservation(input: unknown): HostModelObservation | null {
  const d = reflectFields(input, ["modelId", "state", "activeRequests", "installed", "managedTemporary", "pinned"], ["capability"]);
  if (!d.ok) return null;

  const modelId = d.value.modelId?.value;
  const state = d.value.state?.value;
  const activeRequests = readNonNegInt(d.value.activeRequests?.value);
  const installed = d.value.installed?.value;
  const managedTemporary = d.value.managedTemporary?.value;
  const pinned = d.value.pinned?.value;

  if (typeof modelId !== "string" || !MODEL_ID_PATTERN.test(modelId)) return null;
  if (activeRequests === null) return null;
  if (typeof installed !== "boolean") return null;
  if (typeof managedTemporary !== "boolean") return null;
  if (typeof pinned !== "boolean") return null;
  if (typeof state !== "string" || !["absent","installing","installed","loading","loaded_idle","serving","draining","unloading","failed"].includes(state)) return null;
  if (activeRequests > 0 && state !== "serving" && state !== "draining") return null;

  let capability: ObservedModelCapability | null = null;
  const capabilityRaw = d.value.capability?.value;
  if (capabilityRaw !== undefined && capabilityRaw !== null) {
    const parsed = parseObservedModelCapability(capabilityRaw);
    if (!parsed.ok) return null;
    capability = parsed.value;
  }

  const out = Object.create(null) as Record<string, unknown>;
  out.modelId = modelId;
  out.state = state;
  out.activeRequests = activeRequests;
  out.installed = installed;
  out.managedTemporary = managedTemporary;
  out.pinned = pinned;
  if (capability !== null) out.capability = capability;
  return Object.freeze(out) as unknown as HostModelObservation;
}

/** Strictly build a {@link HostSnapshot} from untrusted input, or `null` when malformed. */
function parseHostSnapshot(input: unknown): HostSnapshot | null {
  const required = ["hostId", "authorized", "online", "observationFresh", "runtimes", "available", "reserve", "models"];
  const optional = ["revoked", "admission", "resourcesKnown", "activeLoads", "maxConcurrentLoads"];
  const d = reflectFields(input, required, optional);
  if (!d.ok) return null;

  const hostId = d.value.hostId?.value;
  const authorized = d.value.authorized?.value;
  const online = d.value.online?.value;
  const observationFresh = d.value.observationFresh?.value;
  const admission = d.value.admission?.value;

  if (typeof hostId !== "string" || !MODEL_ID_PATTERN.test(hostId)) return null;
  if (typeof authorized !== "boolean") return null;
  if (typeof online !== "boolean") return null;
  if (typeof observationFresh !== "boolean") return null;
  if (d.value.revoked && typeof d.value.revoked.value !== "boolean") return null;
  if (d.value.resourcesKnown && typeof d.value.resourcesKnown.value !== "boolean") return null;
  if (admission !== undefined && admission !== "active" && admission !== "drain") return null;
  const activeLoads=d.value.activeLoads?.value,maxLoads=d.value.maxConcurrentLoads?.value;
  if((activeLoads===undefined)!==(maxLoads===undefined))return null;
  if(activeLoads!==undefined&&readNonNegInt(activeLoads)===null)return null;
  if(maxLoads!==undefined&&(!Number.isSafeInteger(maxLoads)||maxLoads<1))return null;

  const runtimesRaw = readElementArray(d.value, "runtimes");
  if (runtimesRaw === null) return null;
  const runtimes: string[] = [],runtimeSet=new Set<string>();
  for (const r of runtimesRaw) {
    if (typeof r !== "string" || !MODEL_ID_PATTERN.test(r) || runtimeSet.has(r)) return null;
    runtimeSet.add(r);runtimes.push(r);
  }

  const available = parseResourceAmount(d.value.available?.value);
  const reserve = parseResourceAmount(d.value.reserve?.value);
  if (!available || !reserve) return null;

  const modelsRaw = readElementArray(d.value, "models");
  if (modelsRaw === null) return null;
  const models: HostModelObservation[] = [],modelSet=new Set<string>();
  for (const m of modelsRaw) {
    const parsed = parseModelObservation(m);
    if (!parsed || modelSet.has(parsed.modelId)) return null;
    modelSet.add(parsed.modelId);models.push(parsed);
  }

  const out = Object.create(null) as Record<string, unknown>;
  out.hostId = hostId;
  out.authorized = authorized;
  out.online = online;
  out.observationFresh = observationFresh;
  if (admission !== undefined) out.admission = admission;
  if (d.value.revoked?.value !== undefined) out.revoked = d.value.revoked.value;
  if (d.value.resourcesKnown?.value !== undefined) out.resourcesKnown=d.value.resourcesKnown.value;
  if(activeLoads!==undefined)out.activeLoads=activeLoads;
  if(maxLoads!==undefined)out.maxConcurrentLoads=maxLoads;
  out.runtimes = Object.freeze([...runtimes]);
  out.available = Object.freeze({ memoryBytes: available.memoryBytes, vramBytes: available.vramBytes, diskBytes: available.diskBytes });
  out.reserve = Object.freeze({ memoryBytes: reserve.memoryBytes, vramBytes: reserve.vramBytes, diskBytes: reserve.diskBytes });
  out.models = Object.freeze(models);
  return Object.freeze(out) as unknown as HostSnapshot;
}

/** Host-level hard checks (authorization, revocation, online, staleness, drain, runtime). */
function hostHardRejection(host: HostSnapshot, request: PlacementRequest, reasons: Set<string>): boolean {
  if (!host.authorized) reasons.add("HOST_NOT_AUTHORIZED");
  if (host.revoked) reasons.add("HOST_REVOKED");
  if (!host.online) reasons.add("HOST_OFFLINE");
  if (!host.observationFresh) reasons.add("OBSERVATION_STALE");
  if (host.admission === "drain") reasons.add("HOST_DRAINING");
  if (unknownResources(host)) reasons.add("HOST_RESOURCE_OBSERVATION_UNKNOWN");
  if (request.requirements.runtime) {
    if (!host.runtimes.includes(request.requirements.runtime)) {
      // Fixed code: never interpolate the runtime (would echo topology and be
      // silently dropped by the closed ordered() filter).
      reasons.add("RUNTIME_UNAVAILABLE");
    }
  }
  return reasons.size > 0;
}

/** Host has no usable resource observation at all. */
function unknownResources(host: HostSnapshot): boolean { return host.resourcesKnown === false; }

function makeCandidate(
  hostId: string,
  activeRequests: number,
  acquisition: "none" | "install",
  score: number,
  reasonCode: string = "PLACEMENT_OK",
): PlacementCandidate {
  const out = Object.create(null) as Record<string, unknown>;
  out.hostId = hostId;
  out.score = score;
  out.acquisition = acquisition;
  out.activeRequests = activeRequests;
  out.reasons = Object.freeze([reasonCode]);
  return Object.freeze(out) as unknown as PlacementCandidate;
}

/** Evaluate the acquisition path: the model is not present on this host. */
function evaluateAcquisition(
  request: PlacementRequest,
  host: HostSnapshot,
  pinned: Set<string>,
  now: UtcTimestamp | null,
  stale: number | null,
): EvaluateResult {
  const profile = capabilityProfile(request);
  const reasons = new Set<string>();

  // Pinning is an ownership constraint: a pinned model must not be relocated, so it may
  // only ever be acquired where it already resides. Any install here is a relocation.
  if (pinned.has(request.modelId)) reasons.add("MODEL_PINNED");

  if (profile) reasons.add("CAPABILITY_INELIGIBLE");
  if(host.maxConcurrentLoads!==undefined&&(host.activeLoads===undefined||host.activeLoads>=host.maxConcurrentLoads))reasons.add("LOAD_CONCURRENCY_LIMIT");

  const memory = usable(host.available.memoryBytes, host.reserve.memoryBytes);
  const vram = usable(host.available.vramBytes, host.reserve.vramBytes);
  const disk = usable(host.available.diskBytes, host.reserve.diskBytes);
  if (memory < request.requirements.memoryBytes) reasons.add("INSUFFICIENT_MEMORY_AFTER_RESERVE");
  if (vram < request.requirements.vramBytes) reasons.add("INSUFFICIENT_VRAM_AFTER_RESERVE");
  if (disk < request.requirements.diskBytes) reasons.add("INSUFFICIENT_STORAGE_AFTER_RESERVE");
  if (reasons.size > 0) return { rejection: ordered(reasons) };

  const score = candidateScore(BAND_ACQUIRE, memory, vram, 0);
  return { candidate: makeCandidate(host.hostId, 0, "install", score) };
}

/** Evaluate the present path: the model already resides on this host (keep semantics). */
function evaluatePresent(
  observed: HostModelObservation,
  request: PlacementRequest,
  host: HostSnapshot,
  now: UtcTimestamp | null,
  stale: number | null,
): EvaluateResult {
  const profile = capabilityProfile(request);
  const state = observed.state;

  // Lifecycle states that place the model in a non-ready state are hard-rejected:
  //   - `draining` explicitly closes admission.
  //   - every other non-ready state (`loading`, `unloading`, `failed`, `absent`,
  //     `installing`) is reported as not-available.
  if (state === "draining") {
    return { rejection: ordered(new Set(["MODEL_DRAINING"])) };
  }
  const readyStates: ReadonlySet<string> = new Set(["loaded_idle", "serving", "installed"]);
  if (!readyStates.has(state)) {
    return { rejection: ordered(new Set(["MODEL_NOT_AVAILABLE"])) };
  }

  const reasons = new Set<string>();
  checkCapability(profile, observed.capability, now, stale, reasons);

  // Pinning is an ownership constraint that only blocks *relocation*: placing a pinned
  // model on a different host where it is already present (keep/reinstall in place) is
  // allowed, but the same pinned model on another host is rejected as a relocation.
  if (observed.pinned && observed.installed === false) {
    reasons.add("MODEL_PINNED");
  }

  // Concurrency headroom for a loaded/serving model.
  const maxConcurrent = (typeof request.maxConcurrentRequests === "number" && request.maxConcurrentRequests > 0)
    ? request.maxConcurrentRequests
    : Number.POSITIVE_INFINITY;
  if (observed.activeRequests >= maxConcurrent) {
    reasons.add("LOAD_CONCURRENCY_LIMIT");
  }

  // Installed models already occupy disk; only an uninstalled model needs post-reserve
  // disk space for acquisition.
  const memory = usable(host.available.memoryBytes, host.reserve.memoryBytes);
  const vram = usable(host.available.vramBytes, host.reserve.vramBytes);
  if (memory < request.requirements.memoryBytes) reasons.add("INSUFFICIENT_MEMORY_AFTER_RESERVE");
  if (vram < request.requirements.vramBytes) reasons.add("INSUFFICIENT_VRAM_AFTER_RESERVE");
  if (!observed.installed && host.available.diskBytes > 0) {
    const disk = usable(host.available.diskBytes, host.reserve.diskBytes);
    if (disk < request.requirements.diskBytes) reasons.add("INSUFFICIENT_STORAGE_AFTER_RESERVE");
  }
  if (reasons.size > 0) return { rejection: ordered(reasons) };

  const band = state === "loaded_idle" ? BAND_LOADED_IDLE
    : state === "serving" ? BAND_SERVING
    : BAND_INSTALLED;
  const reasonCode = state === "loaded_idle" ? "MODEL_ALREADY_LOADED"
    : state === "serving" ? "MODEL_SERVING"
    : "MODEL_INSTALLED_READY";
  const score = candidateScore(band, memory, vram, capabilityPreferenceScore(profile, observed.capability, now, stale));
  return { candidate: makeCandidate(host.hostId, observed.activeRequests, "none", score, reasonCode) };
}

/** Preference score contributed by the 13.1 profile, clamped within a band. */
function capabilityPreferenceScore(profile:CapabilityProfile|null,observed:ObservedModelCapability|null|undefined,now:UtcTimestamp|null,stale:number|null):number{if(!profile||!observed)return 0;const result=matchOne(profile,observed,now,stale);return result.match?Math.min(result.preferenceScore,MAX_RESOURCE_TERM):0;}

/** Check whether a candidate model (observed capability or the synthetic acquisition default) is 13.1 capability-eligible for the request profile. */
function checkCapability(
  profile: CapabilityProfile | null,
  observed: ObservedModelCapability | null | undefined,
  now: UtcTimestamp | null,
  stale: number | null,
  reasons: Set<string>,
): void {
  if (!profile) return;
  if (!observed) { reasons.add("CAPABILITY_INELIGIBLE"); return; }
  const match = matchOne(profile, observed, now, stale);
  if (match.match) return;
  // Collapse every internal 13.1 dimension failure to a single, fully redacted
  // placement code so no provider/quantization/context semantics leak into the
  // public placement vocabulary. Capability-eligibility is a binary hard check. A
  // failure that is purely a freshness lapse is reported as CAPABILITY_STALE; any
  // other unverifiable or insufficient capability is reported as CAPABILITY_INELIGIBLE.
  if (match.reasons.length === 1 && match.reasons[0] === "OBSERVATION_STALE") {
    reasons.add("CAPABILITY_STALE");
  } else {
    reasons.add("CAPABILITY_INELIGIBLE");
  }
}


function parsePlacementRequest(input:unknown):PlacementRequest|null{
  const d=reflectFields(input,["modelId","requirements"],["maxConcurrentRequests","profile"]);if(!d.ok)return null;
  const modelId=d.value.modelId!.value;if(typeof modelId!=="string"||!MODEL_ID_PATTERN.test(modelId))return null;
  const rd=reflectFields(d.value.requirements!.value,["runtime","memoryBytes","vramBytes","diskBytes"],[]);if(!rd.ok)return null;
  const runtime=rd.value.runtime!.value,memoryBytes=readNonNegInt(rd.value.memoryBytes!.value),vramBytes=readNonNegInt(rd.value.vramBytes!.value),diskBytes=readNonNegInt(rd.value.diskBytes!.value);
  if(typeof runtime!=="string"||!MODEL_ID_PATTERN.test(runtime)||memoryBytes===null||vramBytes===null||diskBytes===null)return null;
  const max=d.value.maxConcurrentRequests?.value;if(max!==undefined&&max!==null&&(!Number.isSafeInteger(max)||max<1))return null;
  const rawProfile=d.value.profile?.value??null;let profile:CapabilityProfile|null=null;if(rawProfile!==null){const parsed=parseCapabilityProfile(rawProfile);if(!parsed.ok)return null;profile=parsed.value;}
  const requirements=Object.freeze({runtime,memoryBytes,vramBytes,diskBytes});
  return Object.freeze({modelId,requirements,...(max===undefined?{}:{maxConcurrentRequests:max}),...(profile===null?{}:{profile})});
}

/** Resource-safe placement seam over fleet {@link HostSnapshot} observations. */
export function planPlacement(request: PlacementRequest, hosts: readonly HostSnapshot[], now: UtcTimestamp | null = null, stale: number | null = null): PlacementPlan {
  try {
    const parsedRequest=parsePlacementRequest(request);if(!parsedRequest||!Array.isArray(hosts)||hosts.length>MAX_CANDIDATES)return freezePlan(null,[],[]);
    if(parsedRequest.profile&&((now===null)!==(stale===null)||now===null||stale===null))return freezePlan(null,[],[]);
    const parsedHosts:HostSnapshot[]=[],rejected:PlacementRejection[]=[];const hostIds=new Set<string>();
    for(const input of hosts){const host=parseHostSnapshot(input);if(!host){rejected.push(freezeRejection("invalid",["HOST_OBSERVATION_INVALID"]));continue;}if(hostIds.has(host.hostId))return freezePlan(null,[],[freezeRejection("invalid",["HOST_OBSERVATION_INVALID"])]);hostIds.add(host.hostId);parsedHosts.push(host);}
    const pinned=pinnedModelIds(parsedHosts),candidates:PlacementCandidate[]=[];
    for(const host of parsedHosts){const reasons=new Set<string>();if(hostHardRejection(host,parsedRequest,reasons)){rejected.push(freezeRejection(host.hostId,ordered(reasons)));continue;}const observed=findModel(host.models,parsedRequest.modelId);const result=observed?evaluatePresent(observed,parsedRequest,host,now,stale):evaluateAcquisition(parsedRequest,host,pinned,now,stale);if(result.candidate)candidates.push(result.candidate);if(result.rejection)rejected.push(freezeRejection(host.hostId,result.rejection));}
    candidates.sort((a,b)=>b.score-a.score||a.hostId.localeCompare(b.hostId));return freezePlan(candidates[0]??null,candidates,rejected);
  }catch{return freezePlan(null,[],[]);}
}

// ---------------------------------------------------------------------------
// Controller capability-resolver seam.
// ---------------------------------------------------------------------------

/** Public result of the controller placement seam (candidateId/substitutable/reasons). */
export interface CapabilityPlacementResult {
  readonly candidateId: string | null;
  readonly substitutable: boolean;
  readonly reasons: readonly string[];
}

/** Fail-closed selection result. */
function frozenSelection(
  candidateId: string | null,
  substitutable: boolean,
  reasons: readonly string[],
): CapabilityPlacementResult {
  const out = Object.create(null) as Record<string, unknown>;
  out.candidateId = candidateId;
  out.substitutable = substitutable;
  out.reasons = Object.freeze([...reasons]);
  return Object.freeze(out) as unknown as CapabilityPlacementResult;
}

/**
 * Controller capability-resolver seam: select, among controller-owned
 * {@link CapabilityCandidate} pool members, one capable, substitutable model —
 * deterministically and fail-closed. Public reason codes never echo topology.
 *
 * No target data is constructed from caller strings: target identity comes only
 * from controller-owned candidates (validated by the caller), and the selected
 * candidateId is looked up against that validated pool.
 */
export function planCapabilityPlacement(
  profile: CapabilityProfile,
  candidates: readonly CapabilityCandidate[],
  now: UtcTimestamp | null,
  staleAfterMs: number | null,
): CapabilityPlacementResult {
  if (profile === null || profile === undefined || parseCapabilityProfile(profile).ok === false) {
    return frozenSelection(null, false, ["PROFILE_INVALID"]);
  }
  if (!Array.isArray(candidates) || candidates.length > MAX_CANDIDATES) {
    return frozenSelection(null, false, [ERR_OBSERVED]);
  }
  if (now === null || staleAfterMs === null) {
    return frozenSelection(null, false, [ERR_OBSERVED]);
  }
  const selection = selectCapabilityCandidate(profile, candidates, now, staleAfterMs);
  return frozenSelection(selection.candidateId, selection.substitutable, selection.reasons);
}

function freezeRejection(hostId:string,reasons:readonly string[]):PlacementRejection{const out=Object.create(null) as Record<string,unknown>;out.hostId=hostId;out.reasons=Object.freeze([...reasons]);return Object.freeze(out) as unknown as PlacementRejection;}

function freezePlan(
  selected: PlacementCandidate | null,
  candidates: readonly PlacementCandidate[],
  rejected: readonly PlacementRejection[],
): PlacementPlan {
  const out = Object.create(null) as Record<string, unknown>;
  out.selected = selected;
  out.candidates = Object.freeze(candidates.map((candidate) => candidate as PlacementCandidate));
  out.rejected = Object.freeze(rejected.map((item)=>freezeRejection(item.hostId,item.reasons)));
  return Object.freeze(out) as unknown as PlacementPlan;
}

// Re-exported so callers (and tests) can brand plain RFC-3339 strings to the contract.
export type { CapabilityProfile, ObservedModelCapability } from "./capability-matching.js";
export type { CapabilityCandidate, CapabilitySelection } from "./capability-matching.js";
export { selectCapabilityCandidate, parseCapabilityProfile, parseObservedModelCapability, matchOne };
