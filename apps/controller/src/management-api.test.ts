import assert from "node:assert/strict";
import test from "node:test";
import { MANAGEMENT_BODY_LIMIT, routeManagementRequest, type ManagementApiDependencies } from "./management-api.js";

const TOKEN="a".repeat(43);
const session=Object.freeze({ownerId:"owner-1",credentialVersion:1,sessionVersion:1,createdAt:"2026-01-01T00:00:00.000Z",lastSeenAt:"2026-01-01T00:00:00.000Z",absoluteExpiresAt:"2099-01-01T00:00:00.000Z",idleExpiresAt:"2099-01-01T00:00:00.000Z",revokedAt:null});
function dependencies(overrides:Partial<ManagementApiDependencies>={}):ManagementApiDependencies{
 const sessions={authenticate:(token:string)=>token===TOKEN?session:null,authenticateCsrf:(_token:string,csrf:string)=>csrf==="csrf"?session:null};
 const fleet={listHosts:()=>({ok:true,value:{items:[],nextCursor:null,counts:{hosts:0,active:0,degraded:0,offline:0,revoked:0,providers:0,models:0}}}),summary:()=>({ok:true,value:{hosts:0,active:0,degraded:0,offline:0,revoked:0,providers:0,models:0}}),getHost:(id:unknown)=>({ok:true,value:{hostId:id,displayName:"host",platform:"linux",health:"active",observedAt:"2026-01-01T00:00:00.000Z",idle:true,providerCount:0,modelCount:0}}),listProviders:()=>({ok:true,value:[]}),listModels:()=>({ok:true,value:[]})};
 const jobs={jobs:{list:()=>Object.freeze([]),listHistory:()=>Object.freeze([])},audit:{list:()=>Object.freeze([])}};
 const policy={install:()=>({ok:true,value:{version:1,hash:"secret-digest"}}),authorize:(intent:unknown)=>({ok:true,value:intent}),approve:()=>({ok:true,value:{approvalId:"a",requestId:"r",expiresAt:"2099-01-01T00:00:00.000Z"}})};
 const lifecycle={execute:(input:unknown)=>({ok:true,state:"succeeded",observation:input})};
 const dispatcher={cancel:()=>({ok:true,state:"cancelled",observation:null})};
 return {sessions:sessions as never,allowedOrigins:["https://manager.test"],fleet:fleet as never,jobs:jobs as never,policy:policy as never,lifecycle:lifecycle as never,dispatcher:dispatcher as never,...overrides};
}
const get=(url:string,headers:unknown={cookie:`__Host-lanmm_session=${TOKEN}`})=>({method:"GET",url,headers});
const post=(url:string,body:string,headers:unknown={cookie:`__Host-lanmm_session=${TOKEN}`,origin:"https://manager.test","x-csrf-token":"csrf","content-type":"application/json"})=>({method:"POST",url,headers,body});

test("management routes guard every API path and reject inference bearer",async()=>{
 const deps=dependencies();
 assert.equal((await routeManagementRequest(deps,get("/api/v1/fleet/summary",{}))).status,401);
 assert.equal((await routeManagementRequest(deps,get("/api/v1/unknown",{authorization:"Bearer inference"}))).status,401);
 assert.equal((await routeManagementRequest(deps,get("/api/v1/unknown"))).status,404);
});

test("routing, methods, query bounds, and immutable redacted envelopes are stable",async()=>{
 const deps=dependencies();
 const summary=await routeManagementRequest(deps,get("/api/v1/fleet/summary"));
 assert.equal(summary.status,200);assert.equal((summary.body as any).ok,true);assert.ok(Object.isFrozen(summary));assert.ok(Object.isFrozen(summary.body));
 assert.equal((await routeManagementRequest(deps,get("/api/v1/jobs?state=bogus"))).status,400);
 assert.equal((await routeManagementRequest(deps,get("/api/v1/fleet/summary",{cookie:`__Host-lanmm_session=${TOKEN}`,origin:"https://evil.test"}))).status,403);
 assert.equal((await routeManagementRequest(deps,{...get("/api/v1/fleet/summary"),method:"POST",body:"{}",headers:{cookie:`__Host-lanmm_session=${TOKEN}`,origin:"https://manager.test","x-csrf-token":"csrf","content-type":"application/json"}})).status,405);
 const installed=await routeManagementRequest(deps,post("/api/v1/policy/install","{}"));
 assert.equal(installed.status,200);assert.equal((installed.body as any).value.version,1);
});

test("mutations enforce CSRF, JSON media type, body bounds, and hostile inputs",async()=>{
 const deps=dependencies();
 assert.equal((await routeManagementRequest(deps,post("/api/v1/policy/install","{}",{cookie:`__Host-lanmm_session=${TOKEN}`,origin:"https://manager.test","content-type":"application/json"}))).status,403);
 assert.equal((await routeManagementRequest(deps,post("/api/v1/policy/install","{}",{cookie:`__Host-lanmm_session=${TOKEN}`,origin:"https://manager.test","x-csrf-token":"csrf","content-type":"text/plain"}))).status,415);
 assert.equal((await routeManagementRequest(deps,post("/api/v1/policy/install","x".repeat(MANAGEMENT_BODY_LIMIT+1)))).status,413);
 const hostile=Object.create(null);Object.defineProperty(hostile,"cookie",{get(){throw new Error("must not run");}});
 assert.equal((await routeManagementRequest(deps,get("/api/v1/fleet/summary",hostile))).status,400);
});

test("policy and lifecycle actors are bound to the authenticated owner",async()=>{
 let policyActor:unknown;let lifecycleActor:unknown;
 const deps=dependencies({policy:{install:()=>({ok:true,value:{}}),authorize:(v:unknown)=>{policyActor=v;return{ok:true,value:v}},approve:()=>({ok:true,value:{}})} as never,lifecycle:{execute:(v:any)=>{lifecycleActor=v.intent;return{ok:true,state:"succeeded",observation:{token:"hidden",safe:true}}}} as never});
 const intent={requestId:"1".repeat(64),actorKind:"controller",actorId:"attacker"};
 assert.equal((await routeManagementRequest(deps,post("/api/v1/policy/evaluate",JSON.stringify(intent)))).status,200);
 assert.equal((policyActor as any).actorKind,"owner");assert.equal((policyActor as any).actorId,"owner-1");
 const lifecycle=await routeManagementRequest(deps,post("/api/v1/lifecycle/operations",JSON.stringify({intent,request:{}})));
 assert.equal((lifecycleActor as any).actorId,"owner-1");assert.equal("token" in (((lifecycle.body as any).value.observation) as object),false);
});
