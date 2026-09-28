import assert from "node:assert/strict";
import test from "node:test";
import { planPlacement } from "./placement.js";
import { parseCapabilityProfile,parseObservedModelCapability } from "./capability-matching.js";
import type { HostSnapshot, PlacementRequest } from "./types.js";

const gib = 1024 ** 3;
const request: PlacementRequest = {
  modelId: "example/model",
  requirements: { runtime: "example-runtime", memoryBytes: 8*gib, vramBytes: 6*gib, diskBytes: 12*gib }
};

function host(overrides: Partial<HostSnapshot>): HostSnapshot {
  return {
    hostId: "host-a", authorized: true, online: true, observationFresh: true,
    runtimes: ["example-runtime"],
    available: { memoryBytes: 32*gib, vramBytes: 16*gib, diskBytes: 100*gib },
    reserve: { memoryBytes: 4*gib, vramBytes: 2*gib, diskBytes: 20*gib },
    models: [], ...overrides
  };
}

test("rejects stale and under-resourced hosts before ranking", () => {
  const plan = planPlacement(request, [
    host({ hostId: "stale", observationFresh: false }),
    host({ hostId: "small", available: { memoryBytes: 10*gib, vramBytes: 7*gib, diskBytes: 25*gib } })
  ]);
  assert.equal(plan.selected, null);
  assert.equal(plan.rejected.length, 2);
  // Redacted, canonical codes (no human prose): host is stale.
  assert.deepStrictEqual(plan.rejected[0]?.reasons, ["OBSERVATION_STALE"]);
  // Host that lacks memory, VRAM, and storage after reserve; all three redacted codes fire.
  assert.deepStrictEqual(plan.rejected[1]?.reasons, ["INSUFFICIENT_MEMORY_AFTER_RESERVE", "INSUFFICIENT_VRAM_AFTER_RESERVE", "INSUFFICIENT_STORAGE_AFTER_RESERVE"]);
});

test("prefers a loaded model over a host requiring acquisition", () => {
  const plan = planPlacement(request, [
    host({ hostId: "install-target" }),
    host({ hostId: "ready-target", models: [{ modelId: request.modelId, state: "loaded_idle",
      activeRequests: 0, installed: true, managedTemporary: false, pinned: true }] })
  ]);
  assert.equal(plan.selected?.hostId, "ready-target");
  assert.equal(plan.selected?.acquisition, "none");
});

test("strict request and host boundaries never invoke accessors",()=>{let calls=0;const hostileRequest=Object.defineProperty({},"modelId",{get(){calls++;return"example/model";}});assert.deepEqual(planPlacement(hostileRequest as never,[host({})]).candidates,[]);const hostileHost=Object.defineProperty({},"hostId",{get(){calls++;return"host-x";}});const plan=planPlacement(request,[hostileHost as never]);assert.equal(calls,0);assert.equal(plan.rejected[0]?.hostId,"invalid");assert.deepEqual(plan.rejected[0]?.reasons,["HOST_OBSERVATION_INVALID"]);});

test("rejects revoked offline unknown-resource draining runtime and load-saturated hosts",()=>{const plan=planPlacement(request,[host({hostId:"revoked",revoked:true}),host({hostId:"offline",online:false}),host({hostId:"unknown",resourcesKnown:false}),host({hostId:"drain",admission:"drain"}),host({hostId:"runtime",runtimes:["other"]}),host({hostId:"loads",activeLoads:2,maxConcurrentLoads:2})]);assert.equal(plan.selected,null);assert.deepEqual(plan.rejected.map(item=>item.reasons[0]),["HOST_REVOKED","HOST_OFFLINE","HOST_RESOURCE_OBSERVATION_UNKNOWN","HOST_DRAINING","RUNTIME_UNAVAILABLE","LOAD_CONCURRENCY_LIMIT"]);});

test("exact post-reserve resources pass while one-byte shortages fail",()=>{const exact=host({hostId:"exact",available:{memoryBytes:12*gib,vramBytes:8*gib,diskBytes:32*gib}}),short=host({hostId:"short",available:{memoryBytes:12*gib-1,vramBytes:8*gib,diskBytes:32*gib}}),plan=planPlacement(request,[exact,short]);assert.equal(plan.selected?.hostId,"exact");assert.deepEqual(plan.rejected[0]?.reasons,["INSUFFICIENT_MEMORY_AFTER_RESERVE"]);});

test("loaded band wins safely and deterministic ties use host id",()=>{const loaded=(id:string)=>host({hostId:id,available:{memoryBytes:8*gib,vramBytes:6*gib,diskBytes:20*gib},reserve:{memoryBytes:0,vramBytes:0,diskBytes:0},models:[{modelId:request.modelId,state:"loaded_idle",activeRequests:0,installed:true,managedTemporary:false,pinned:false}]}),huge=host({hostId:"huge",available:{memoryBytes:Number.MAX_SAFE_INTEGER,vramBytes:Number.MAX_SAFE_INTEGER,diskBytes:Number.MAX_SAFE_INTEGER},reserve:{memoryBytes:0,vramBytes:0,diskBytes:0}}),plan=planPlacement(request,[loaded("z-host"),huge,loaded("a-host")]);assert.equal(plan.selected?.hostId,"a-host");assert.ok(plan.candidates[0]!.score<2_200_000);assert.ok(plan.candidates.find(item=>item.hostId==="huge")!.score<800_000);});

test("request and host concurrency caps reject saturated work",()=>{const loaded=host({models:[{modelId:request.modelId,state:"serving",activeRequests:2,installed:true,managedTemporary:false,pinned:false}]}),plan=planPlacement({...request,maxConcurrentRequests:2},[loaded]);assert.deepEqual(plan.rejected[0]?.reasons,["LOAD_CONCURRENCY_LIMIT"]);assert.equal(plan.selected,null);});

test("pinned models stay on their owning host and block acquisition elsewhere",()=>{const owner=host({hostId:"owner",models:[{modelId:request.modelId,state:"installed",activeRequests:0,installed:true,managedTemporary:false,pinned:true}]}),other=host({hostId:"other"}),plan=planPlacement(request,[other,owner]);assert.equal(plan.selected?.hostId,"owner");assert.deepEqual(plan.rejected.find(item=>item.hostId==="other")?.reasons,["MODEL_PINNED"]);});

test("capability placement requires fresh observed capability and rejects blind acquisition",()=>{const p=parseCapabilityProfile({version:1,purpose:"chat",requiredModalities:["text"],contextWindow:4096,tools:true,vision:null,reasoning:null,embeddings:null,provider:"ollama",quantization:null,minimumMemoryBytes:null,minimumVramBytes:null,minimumDiskBytes:null,preferences:["largeContext"],unknowns:[]});assert.ok(p.ok);const c=parseObservedModelCapability({purpose:"chat",modalities:["text"],contextWindow:8192,tools:true,vision:null,reasoning:null,embeddings:null,provider:"ollama",quantization:null,sizeBytes:null,requiresMemoryBytes:null,requiresVramBytes:null,requiresDiskBytes:null,observedAt:"2026-09-28T10:00:00.000Z"});assert.ok(c.ok);if(!p.ok||!c.ok)return;const capable=host({hostId:"capable",models:[{modelId:request.modelId,state:"installed",activeRequests:0,installed:true,managedTemporary:false,pinned:false,capability:c.value}]}),blind=host({hostId:"blind"}),plan=planPlacement({...request,profile:p.value},[blind,capable],"2026-09-28T10:00:30.000Z" as never,60000);assert.equal(plan.selected?.hostId,"capable");assert.deepEqual(plan.rejected[0]?.reasons,["CAPABILITY_INELIGIBLE"]);const stale=planPlacement({...request,profile:p.value},[capable],"2026-09-28T10:10:00.000Z" as never,60000);assert.deepEqual(stale.rejected[0]?.reasons,["CAPABILITY_STALE"]);});

test("plans are deeply frozen bounded and redact request details",()=>{const plan=planPlacement(request,[host({})]);assert.equal(Object.isFrozen(plan),true);assert.equal(Object.isFrozen(plan.candidates),true);assert.equal(Object.isFrozen(plan.selected),true);assert.equal(Object.isFrozen(plan.selected?.reasons),true);const text=JSON.stringify(plan);for(const secret of ["example/model","example-runtime","endpoint","digest","snapshot"])assert.equal(text.includes(secret),false);assert.deepEqual(planPlacement({...request,requirements:{...request.requirements,memoryBytes:Number.MAX_SAFE_INTEGER+1}},[host({})]).candidates,[]);});

test("does not require installation disk space for an installed model", () => {
  const plan = planPlacement(request, [host({
    hostId: "installed-target",
    available: { memoryBytes: 32*gib, vramBytes: 16*gib, diskBytes: 20*gib },
    models: [{ modelId: request.modelId, state: "installed", activeRequests: 0,
      installed: true, managedTemporary: false, pinned: false }]
  })]);
  assert.equal(plan.selected?.hostId, "installed-target");
});
