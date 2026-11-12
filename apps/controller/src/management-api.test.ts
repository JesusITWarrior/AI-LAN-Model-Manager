import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { commandAuthorizationDigest, commandPolicyOperation, type CommandRequest, type CommandResponse } from "@lan-model-manager/core";
import { MANAGEMENT_BODY_LIMIT, OWNER_EVIDENCE_PREPARE_BODY_LIMIT, routeManagementRequest, type ManagementApiDependencies } from "./management-api.js";
import { AgentCommandStore } from "./agent-command-channel.js";
import { CommandDispatcher } from "./command-dispatch.js";
import { CertificateRepository } from "./certificate-repository.js";
import { openControllerDatabase } from "./database.js";
import { createAllowedOrigins } from "./origin.js";
import { createJobStores } from "./jobs-store.js";
import { createOwnerBootstrapService } from "./owner-service.js";
import { guardManagementRequest } from "./guard.js";
import { OwnerNativeEvidenceIntakeService } from "./owner-native-evidence-intake.js";
import { encodeNativeTerminalEvidence } from "./native-terminal-evidence-codec.js";
import { buildOwnerNativeEvidenceSnapshot } from "./owner-native-evidence-snapshot.js";
import { SessionManager } from "./session-manager.js";

const TOKEN="a".repeat(43);
const session=Object.freeze({ownerId:"owner-1",credentialVersion:1,sessionVersion:1,createdAt:"2026-01-01T00:00:00.000Z",lastSeenAt:"2026-01-01T00:00:00.000Z",absoluteExpiresAt:"2099-01-01T00:00:00.000Z",idleExpiresAt:"2099-01-01T00:00:00.000Z",revokedAt:null});
function dependencies(overrides:Partial<ManagementApiDependencies>={}):ManagementApiDependencies{
 const sessions={authenticate:(token:string)=>token===TOKEN?session:null,authenticateCsrf:(_token:string,csrf:string)=>csrf==="csrf"?session:null};
 const fleet={listHosts:()=>({ok:true,value:{items:[],nextCursor:null,counts:{hosts:0,active:0,degraded:0,offline:0,revoked:0,providers:0,models:0}}}),summary:()=>({ok:true,value:{hosts:0,active:0,degraded:0,offline:0,revoked:0,providers:0,models:0}}),getHost:(id:unknown)=>({ok:true,value:{hostId:id,displayName:"host",platform:"linux",health:"active",observedAt:"2026-01-01T00:00:00.000Z",idle:true,providerCount:0,modelCount:0}}),listProviders:()=>({ok:true,value:[]}),listModels:()=>({ok:true,value:[]})};
 const jobs={jobs:{list:()=>Object.freeze([]),listAfter:()=>Object.freeze([]),listHistory:()=>Object.freeze([]),listHistoryAfter:()=>Object.freeze([])},audit:{list:()=>Object.freeze([]),listAfter:()=>Object.freeze([])}};
 const policy={install:()=>({ok:true,value:{version:1,hash:"secret-digest"}}),authorize:(intent:unknown)=>({ok:true,value:intent}),settings:()=>({ok:true,value:{version:1,noPromptEnabled:false,allowedOperations:[],approvalOperations:[],hardLimits:{minimumMemoryHeadroomBytes:0,minimumVramHeadroomBytes:0,minimumStorageHeadroomBytes:0,maxConcurrentOperations:1,maxOperationsPerMinute:1}}}),setConvenience:()=>({ok:true,value:{version:2,noPromptEnabled:true,allowedOperations:[],approvalOperations:[],hardLimits:{minimumMemoryHeadroomBytes:0,minimumVramHeadroomBytes:0,minimumStorageHeadroomBytes:0,maxConcurrentOperations:1,maxOperationsPerMinute:1}}}),pending:()=>({ok:true,value:[]}),approve:()=>({ok:true,value:{approvalId:"a",requestId:"r",expiresAt:"2099-01-01T00:00:00.000Z"}})};
 const inference={list:async()=>[],issue:async()=>({token:"x".repeat(43),metadata:{tokenId:"a".repeat(32),ownerId:"b".repeat(32),label:"test",scopes:["inference:invoke","model:list"],credentialVersion:1,createdAt:"2026-01-01T00:00:00.000Z",lastUsedAt:null,expiresAt:"2099-01-01T00:00:00.000Z",revokedAt:null}}),revoke:async()=>true,revokeAll:async()=>1};
 return {sessions:sessions as never,allowedOrigins:["https://manager.test"],fleet:fleet as never,jobs:jobs as never,policy:policy as never,inference:inference as never,...overrides};
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
 assert.equal(installed.status,200);assert.equal((installed.body as any).value.version,1);assert.equal((installed.body as any).value.hash,"secret-digest","ordinary management results retain unchanged generic deep behavior");
});

test("mutations enforce CSRF, JSON media type, body bounds, and hostile inputs",async()=>{
 const deps=dependencies();
 assert.equal((await routeManagementRequest(deps,post("/api/v1/policy/install","{}",{cookie:`__Host-lanmm_session=${TOKEN}`,origin:"https://manager.test","content-type":"application/json"}))).status,403);
 assert.equal((await routeManagementRequest(deps,post("/api/v1/policy/install","{}",{cookie:`__Host-lanmm_session=${TOKEN}`,origin:"https://manager.test","x-csrf-token":"csrf","content-type":"text/plain"}))).status,415);
 assert.equal((await routeManagementRequest(deps,post("/api/v1/policy/install","x".repeat(MANAGEMENT_BODY_LIMIT+1)))).status,413);
 const hostile=Object.create(null);Object.defineProperty(hostile,"cookie",{get(){throw new Error("must not run");}});
 assert.equal((await routeManagementRequest(deps,get("/api/v1/fleet/summary",hostile))).status,400);
});

test("jobs, history, and audit use deterministic bounded cursors",async()=>{
 const calls:unknown[][]=[];const row=(id:string)=>({jobId:id,state:"running",hostId:"host",submittedAt:"2026-01-01T00:00:00.000Z",updatedAt:"2026-01-01T00:00:00.000Z",attempt:1,idempotencyKey:id,payload:{}});
 const deps=dependencies({jobs:{jobs:{listAfter:(...args:unknown[])=>{calls.push(args);return [row("job-b"),row("job-c")]},listHistoryAfter:(...args:unknown[])=>{calls.push(args);return [{cursor:8,jobId:"job-b"},{cursor:9,jobId:"job-b"}]}},audit:{listAfter:(...args:unknown[])=>{calls.push(args);return [{sequence:4},{sequence:5}]}}} as never});
 const jobs=await routeManagementRequest(deps,get("/api/v1/jobs?state=running&limit=1&cursor=job-a"));assert.equal((jobs.body as any).value.nextCursor,"job-b");assert.equal((jobs.body as any).value.items.length,1);assert.deepEqual(Object.keys((jobs.body as any).value.items[0]).sort(),["attempt","hostId","jobId","state","submittedAt","updatedAt"]);
 const history=await routeManagementRequest(deps,get("/api/v1/jobs/job-b/history?limit=1&cursor=7"));assert.equal((history.body as any).value.nextCursor,8);assert.deepEqual(Object.keys((history.body as any).value.items[0]).sort(),["attempt","cursor","fromState","jobId","occurredAt","toState"]);
 const audit=await routeManagementRequest(deps,get("/api/v1/audit?limit=1&cursor=3"));assert.equal((audit.body as any).value.nextCursor,4);assert.deepEqual(Object.keys((audit.body as any).value.items[0]).sort(),["action","actorKind","hostId","jobId","occurredAt","outcome","sequence"]);
 assert.deepEqual(calls,[["running","job-a",2],["job-b",7,2],[3,2]]);assert.equal((await routeManagementRequest(deps,get("/api/v1/audit?cursor=bad"))).status,400);
});

test("policy approval flows through authenticated routes; lifecycle mutation fails closed",async()=>{
 let evaluated="",approved="",runs=0;const deps=dependencies({policy:{install:()=>({ok:true,value:{}}),authorize:(v:any)=>{evaluated=v.requestId;return{ok:true,value:{requestId:v.requestId,requiresApproval:true}}},settings:()=>({ok:true,value:{}}),setConvenience:()=>({ok:true,value:{}}),pending:()=>({ok:true,value:[{requestId:"7".repeat(64),operation:"model-load",targetKind:"model",targetId:"model-1",reasons:["approval-required"],createdAt:"2026-01-01T00:00:00.000Z"}]}),approve:(id:string)=>{approved=id;return{ok:true,value:{requestId:id,approvalId:"approval",expiresAt:"2099-01-01T00:00:00.000Z"}}}} as never});
 const pending=await routeManagementRequest(deps,get("/api/v1/policy/approvals"));assert.equal((pending.body as any).value[0].targetId,"model-1");
 const id="7".repeat(64),intent={requestId:id,actorKind:"controller",actorId:"attacker"};assert.equal((await routeManagementRequest(deps,post("/api/v1/policy/evaluate",JSON.stringify(intent)))).status,200);assert.equal((await routeManagementRequest(deps,post("/api/v1/policy/approve",JSON.stringify({requestId:id})))).status,200);assert.equal(evaluated,id);assert.equal(approved,id);
 const replay=JSON.stringify({intent,request:{requestId:id}});const ops=await routeManagementRequest(deps,post("/api/v1/lifecycle/operations",replay)),cancel=await routeManagementRequest(deps,post("/api/v1/lifecycle/cancel",JSON.stringify({jobId:"job-1"})));assert.equal(ops.status,405);assert.equal(cancel.status,405);
});

test("settings routes expose metadata, issue raw inference token once, and mutate with CSRF",async()=>{const deps=dependencies();const settings=await routeManagementRequest(deps,get("/api/v1/policy/settings"));assert.equal((settings.body as any).value.noPromptEnabled,false);const tokens=await routeManagementRequest(deps,get("/api/v1/inference/tokens"));assert.deepEqual((tokens.body as any).value,[]);const issued=await routeManagementRequest(deps,post("/api/v1/inference/tokens",JSON.stringify({label:"test",scopes:["inference:invoke","model:list"]})));assert.equal((issued.body as any).value.token,"x".repeat(43));assert.equal("ownerId" in (issued.body as any).value.metadata,false);const convenience=await routeManagementRequest(deps,post("/api/v1/policy/convenience",JSON.stringify({enabled:true,expectedVersion:1})));assert.equal((convenience.body as any).value.noPromptEnabled,true);assert.equal((await routeManagementRequest(deps,post("/api/v1/inference/tokens/revoke",JSON.stringify({tokenId:"a".repeat(32)})))).status,200);assert.equal((await routeManagementRequest(deps,post("/api/v1/inference/tokens/revoke-all","{}"))).status,200);});

const preview={candidateHandle:"b".repeat(48),expectedTupleDigest:"a".repeat(64),jobId:"job-1",hostId:"host-1",requestId:"request-1",terminalState:"succeeded",terminalRevision:"rev-1",evidenceKind:"succeeded",payloadBytes:100,responseBytes:20,expiresAt:"2099-01-01T00:00:00.000Z",action:"append-supplemental-native-evidence",disposition:"evidence-only",label:"Owner-provided unsigned evidence; source not independently proven"};
const evidencePayload=JSON.stringify({domain:"lan-model-manager.native-terminal-evidence",kind:"native-terminal-evidence",version:1,disposition:"evidence-only",tuple:{domain:"lan-model-manager.native-terminal-evidence-tuple",hostId:"host-1",jobId:"job-1",requestId:"request-1",commandSequence:1,idempotencyKey:"key-1",authorizationRequestDigest:"a".repeat(64),storedQueueDigest:"b".repeat(64),terminalState:"succeeded",terminalRevision:"rev-1",responseDigest:"c".repeat(64),responseByteLength:20,evidenceKind:"succeeded",holdClass:"none"},responseBase64:"e30=",evidenceSource:"owner supplied"});
const evidenceReq=(bytes:Uint8Array,url="/api/v1/native-evidence/prepare",headers:any={cookie:`__Host-lanmm_session=${TOKEN}`,origin:"https://manager.test","x-csrf-token":"csrf","content-type":"application/json"})=>({method:"POST",url,headers,rawBodyBytes:bytes});
test("owner evidence prepare requires exact raw route and independently caps its bytes",async()=>{
 let calls=0;const service={prepare:(input:any)=>{calls++;assert.equal(input.jobSelector,"job-1");assert.equal(input.path,"/api/v1/native-evidence/prepare");if(Buffer.byteLength(evidencePayload)===input.rawPayloadBytes.byteLength)assert.equal(Buffer.compare(Buffer.from(input.rawPayloadBytes),Buffer.from(evidencePayload)),0);return{ok:true,preview};}};
 const deps=dependencies({ownerEvidenceIntake:service as never});const bytes=Buffer.from(evidencePayload);
 const good=await routeManagementRequest(deps,evidenceReq(bytes));assert.equal(good.status,200);assert.equal((good.body as any).value.expectedTupleDigest,"a".repeat(64));assert.equal(calls,1);
 for(const alias of ["/api/v1/native-evidence/prepare?","/api/v1/native-evidence/prepare?x=1","/api/v1/native-evidence/%70repare","/api/v1/native-evidence/prepare/","http://127.0.0.1/api/v1/native-evidence/prepare"]) {
  const result=await routeManagementRequest(deps,evidenceReq(bytes,alias));assert.notEqual(result.status,200,alias);assert.equal(calls,1,alias);
 }
 const exact=Buffer.concat([bytes,Buffer.alloc(OWNER_EVIDENCE_PREPARE_BODY_LIMIT-bytes.length,0x20)]);assert.equal((await routeManagementRequest(deps,evidenceReq(exact,"/api/v1/native-evidence/prepare",{cookie:`__Host-lanmm_session=${TOKEN}`,origin:"https://manager.test","x-csrf-token":"csrf","content-type":"application/json", "content-length":String(exact.length)}))).status,200);assert.equal(calls,2);
 assert.equal((await routeManagementRequest(deps,evidenceReq(Buffer.concat([exact,Buffer.from(" ")])))).status,413);
 assert.equal((await routeManagementRequest(deps,evidenceReq(Buffer.alloc(MANAGEMENT_BODY_LIMIT+1),"/api/v1/native-evidence/prepare?x=1"))).status,413);
 assert.equal((await routeManagementRequest(deps,{method:"POST",url:"/api/v1/native-evidence/prepare?x=1",headers:{},body:"x".repeat(MANAGEMENT_BODY_LIMIT+1)})).status,413);
 assert.equal((await routeManagementRequest(deps,evidenceReq(bytes,"/api/v1/native-evidence/prepare",{cookie:`__Host-lanmm_session=${TOKEN}`,origin:"https://manager.test","x-csrf-token":"csrf","content-type":"application/json", "content-length":String(bytes.length+1)}))).status,400);
 assert.equal((await routeManagementRequest(deps,evidenceReq(bytes,"/api/v1/native-evidence/prepare",{cookie:`__Host-lanmm_session=${TOKEN}`}))).status,403);assert.equal(calls,2);
 for(const deniedHeaders of [{cookie:"__Host-lanmm_session=bad",origin:"https://manager.test","x-csrf-token":"csrf","content-type":"application/json"},{cookie:`__Host-lanmm_session=${TOKEN}`,origin:"https://evil.test","x-csrf-token":"csrf","content-type":"application/json"},{cookie:`__Host-lanmm_session=${TOKEN}`,origin:"https://manager.test","x-csrf-token":"bad","content-type":"application/json"}])assert.notEqual((await routeManagementRequest(deps,evidenceReq(bytes,"/api/v1/native-evidence/prepare",deniedHeaders))).status,200);
 assert.equal(calls,2);
 assert.equal((await routeManagementRequest(deps,{...evidenceReq(bytes),body:"{}"})).status,400);
 assert.equal((await routeManagementRequest(deps,{...evidenceReq(bytes),method:"GET"})).status!==200,true);
});
test("owner evidence response is allowlisted and raw shortcut cannot reach other routes",async()=>{
 const deps=dependencies({ownerEvidenceIntake:{prepare:()=>({ok:true,preview})} as never});const bytes=Buffer.from(evidencePayload),r=await routeManagementRequest(deps,evidenceReq(bytes));assert.equal(r.status,200);assert.deepEqual(Object.keys((r.body as any).value).sort(),Object.keys(preview).sort());assert.equal((r.body as any).value.expectedTupleDigest,"a".repeat(64));
 const poisoned=dependencies({ownerEvidenceIntake:{prepare:()=>({ok:true,preview:{...preview,certificatePem:"SECRET"}})} as never});assert.equal((await routeManagementRequest(poisoned,evidenceReq(bytes))).status,400);
 assert.equal((await routeManagementRequest(deps,{...get("/api/v1/fleet/summary"),rawBodyBytes:bytes})).status,400);
});
test("owner evidence strict parser rejects unsafe encodings before intake",async()=>{
 let calls=0;const deps=dependencies({ownerEvidenceIntake:{prepare:()=>{calls++;return{ok:true,preview};}} as never});const good=Buffer.from(evidencePayload);
 const duplicate=evidencePayload.replace('"jobId":"job-1"','"jobId":"job-1","job\\u0049d":"job-2"');
 const invalid=[Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),good]),Buffer.from(duplicate),Buffer.concat([good,Buffer.from("x")]),Buffer.from([0x7b,0x22,0xff,0x7d]),Buffer.concat([good,Buffer.from([0xc3])])];
 invalid.push(Buffer.from('{"tuple":{"jobId":"job-1"}}'));
 for(const bytes of invalid)assert.equal((await routeManagementRequest(deps,evidenceReq(bytes))).status,400);
 assert.equal((await routeManagementRequest(deps,evidenceReq(good,"/api/v1/native-evidence/prepare",{}))).status,401);assert.equal(calls,0);
 const hostileBytes=new Proxy(Buffer.from(good),{get(){throw new Error("must not inspect unauthenticated body");}});assert.equal((await routeManagementRequest(deps,evidenceReq(hostileBytes,"/api/v1/native-evidence/prepare",{}))).status,401);assert.equal(calls,0);
 let byteTraps=0;const accessorBytes=Buffer.from(good);Object.defineProperty(accessorBytes,"byteLength",{get(){byteTraps++;throw new Error("byte slot must stay intrinsic");}});
 assert.equal((await routeManagementRequest(deps,evidenceReq(accessorBytes))).status,400);assert.equal(byteTraps,0);assert.equal(calls,0);
 assert.equal((await routeManagementRequest(deps,evidenceReq(new Uint8Array(new SharedArrayBuffer(good.length))))).status,400);assert.equal(calls,0);
 const detached=new Uint8Array(good.length);structuredClone(detached.buffer,{transfer:[detached.buffer]});assert.equal((await routeManagementRequest(deps,evidenceReq(detached))).status,400);assert.equal(calls,0);
 assert.equal((await routeManagementRequest(deps,evidenceReq(good,"/api/v1/native-evidence/prepare",{cookie:`__Host-lanmm_session=${TOKEN}`,origin:"https://manager.test","x-csrf-token":"csrf","content-type":"application/json; charset=utf-8; charset=utf-8"}))).status,415);assert.equal(calls,0);
 assert.equal((await routeManagementRequest(deps,{...evidenceReq(good),headers:{cookie:`__Host-lanmm_session=${TOKEN}`,origin:"https://manager.test","x-csrf-token":"csrf","content-type":"application/json", "Content-Type":"application/json"}})).status,400);assert.equal(calls,0);
});
test("owner evidence preview DTO enforces its exact typed allowlist and missing intake stays unavailable",async()=>{
 const bytes=Buffer.from(evidencePayload),malformed=[
  {...preview,candidateHandle:""},{...preview,expectedTupleDigest:"not-a-digest"},{...preview,jobId:""},{...preview,terminalState:"running"},
  {...preview,terminalRevision:""},{...preview,evidenceKind:"timed-out"},{...preview,payloadBytes:0},{...preview,payloadBytes:OWNER_EVIDENCE_PREPARE_BODY_LIMIT+1},
  {...preview,responseBytes:Number.MAX_SAFE_INTEGER+1},{...preview,expiresAt:"not-a-time"},{...preview,label:"verified"},{...preview,extraCanary:"private"},
 ];
 for(const value of malformed){const deps=dependencies({ownerEvidenceIntake:{prepare:()=>({ok:true,preview:value})} as never});assert.equal((await routeManagementRequest(deps,evidenceReq(bytes))).status,400);}
 assert.equal((await routeManagementRequest(dependencies(),evidenceReq(bytes))).status,503,"service is opt-in and absent by default");
});
test("policy actors are bound to the authenticated owner; lifecycle replay fails closed",async()=>{
 let policyActor:unknown;
 const deps=dependencies({policy:{install:()=>({ok:true,value:{}}),authorize:(v:unknown)=>{policyActor=v;return{ok:true,value:v}},settings:()=>({ok:true,value:{}}),setConvenience:()=>({ok:true,value:{}}),pending:()=>({ok:true,value:[]}),approve:()=>({ok:true,value:{}})} as never});
 const intent={requestId:"1".repeat(64),actorKind:"controller",actorId:"attacker"};
 assert.equal((await routeManagementRequest(deps,post("/api/v1/policy/evaluate",JSON.stringify(intent)))).status,200);
 assert.equal((policyActor as any).actorKind,"owner");assert.equal((policyActor as any).actorId,"owner-1");
 // lifecycle/operations is not wired to a live engine: it fails closed (405)
 assert.equal((await routeManagementRequest(deps,post("/api/v1/lifecycle/operations",JSON.stringify({intent,request:{}})))).status,405);
});

test("real management API prepare stages a real intake candidate without protected DB writes",async()=>{
 const db=openControllerDatabase(":memory:");
 let now="2026-09-27T10:00:00.000Z",random=0;
 const cryptoEngine={random:(n:number)=>Buffer.alloc(n,3),async derive(password:Uint8Array,salt:Uint8Array,parameters:{keyLength:number}){const seed=createHash("sha256").update(password).update(salt).digest();return Buffer.alloc(parameters.keyLength,seed[0]);},equal:(a:Uint8Array,b:Uint8Array)=>Buffer.from(a).equals(Buffer.from(b))};
 const owners=createOwnerBootstrapService(db,{now:()=>now,ownerId:()=>"a".repeat(32),crypto:cryptoEngine});
 try {
  await owners.bootstrapOwner({username:"Admin",password:"owner-password-123"});
  const sessions=new SessionManager(db,owners,{clock:()=>now,random:n=>Buffer.alloc(n,++random),policy:{absoluteTtlMs:3_600_000,idleTtlMs:600_000,touchAfterMs:60_000}});
  const session=await sessions.create({username:"admin",password:"owner-password-123"});assert.ok(session);
  const stores=createJobStores(db,{now:()=>now}),certs=new CertificateRepository(db),pem="-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n";
  certs.insertCa({caId:"b".repeat(64),version:1,serial:"10",fingerprint:"b".repeat(64),certificatePem:pem,notBefore:"2026-01-01T00:00:00.000Z",notAfter:"2036-01-01T00:00:00.000Z",createdAt:"2026-09-27T10:00:00.000Z"});
  certs.insertHost({certificateId:"c".repeat(64),serial:"ABCD",fingerprint:"d".repeat(64),certificatePem:pem,caId:"b".repeat(64),caVersion:1,binding:{candidateId:"host-1",address:"192.0.2.10",port:7443,protocolMajor:1,protocolMinor:0},spiffeUri:"spiffe://lanmodelmanager/host/host-1",challengeId:"e".repeat(64),transcriptDigest:"f".repeat(64),notBefore:"2026-01-01T00:00:00.000Z",notAfter:"2036-01-01T00:00:00.000Z",status:"active",version:1,issuedAt:"2026-09-27T10:00:00.000Z",revokedAt:null});
  // Give the protected evidence table a nonempty immutable sentinel row. This is
  // fixture SQL only: it does not call an evidence-append or consent service.
  db.prepare(`INSERT INTO supplemental_native_evidence VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run("1".repeat(64),"{}",Buffer.from("fixture-payload"),"2".repeat(64),Buffer.from("r"),"3".repeat(64),1,"a".repeat(32),"4".repeat(64),1,"5".repeat(64),"append-supplemental-native-evidence","evidence-only","2026-09-27T10:00:00.000Z","{}","6".repeat(64),"{}","2026-09-27T10:00:00.000Z");
  const operation="probe",request:CommandRequest={requestId:"request-1",jobId:"job-1",hostId:"host-1",operation,idempotencyKey:"idem-1",sequence:1,deadline:"2026-09-27T10:05:00.000Z",capability:{operation:commandPolicyOperation(operation),targetKind:"host",targetId:"host-1",hostId:"host-1",modelId:null,requestDigest:"",expiresAt:"2026-09-27T10:05:00.000Z"},params:{providerId:"provider-1",model:"model:latest"}};
  (request.capability as {requestDigest:string}).requestDigest=commandAuthorizationDigest(request);
  const queue=new AgentCommandStore(db,()=>now,30_000,stores);assert.equal(new CommandDispatcher(stores,queue,()=>now).dispatch(request).ok,true);assert.ok(queue.poll(request.hostId).command);
  const terminal:CommandResponse={requestId:request.requestId,jobId:request.jobId,hostId:request.hostId,sequence:1,status:"failed",progress:null,observedAt:"2026-09-27T10:00:06.000Z",observation:"integration-response",errorCode:"ADAPTER_FAILED"};now=terminal.observedAt;assert.ok(queue.complete(request.hostId,terminal));
  let raw!:Uint8Array;stores.withAuditTransaction(tx=>{const built=buildOwnerNativeEvidenceSnapshot(db,tx,"job-1",Buffer.from(JSON.stringify(terminal)),"synthetic",now);assert.ok(built);const encoded=encodeNativeTerminalEvidence(built.snapshot);assert.ok(encoded.ok);raw=Uint8Array.from(Buffer.from(encoded.payloadBase64,"base64"));});
  const intake=new OwnerNativeEvidenceIntakeService(db,sessions,["https://manager.test"],()=>now),deps=dependencies({sessions:sessions as never,allowedOrigins:["https://manager.test"],jobs:stores as never,ownerEvidenceIntake:intake});
  const tableSnapshot=()=>{const names=(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all() as Array<{name:string}>).map(v=>v.name);return JSON.stringify(names.map(name=>[name,db.prepare(`SELECT * FROM "${name}"`).all()]));};
  const protectedBefore=tableSnapshot();
  for(const name of ["jobs","job_history","agent_commands","supplemental_native_evidence","audit_events","certificate_authorities","host_certificates","owners","sessions"])assert.ok((db.prepare(`SELECT COUNT(*) AS n FROM "${name}"`).get() as {n:number}).n>0,`${name} has nonempty protected fixture state`);
  const caller=Uint8Array.from(raw),callerBefore=caller.slice();
  const headers={cookie:`__Host-lanmm_session=${session.sessionToken}`,origin:"https://manager.test","x-csrf-token":session.csrfToken,"content-type":"application/json","content-length":String(caller.byteLength)};
  const invoke=(bytes:Uint8Array,hs:unknown=headers)=>routeManagementRequest(deps,{method:"POST",url:"/api/v1/native-evidence/prepare",headers:hs,rawBodyBytes:bytes});
  const prepared=await invoke(caller);assert.equal(prepared.status,200);assert.equal((prepared.body as any).ok,true);
  const preview=(prepared.body as any).value;assert.equal(preview.jobId,"job-1");assert.equal(preview.candidateHandle.length>0,true);assert.match(preview.expectedTupleDigest,/^[a-f0-9]{64}$/);assert.equal(preview.label,"Owner-provided unsigned evidence; source not independently proven");
  const rendered=JSON.stringify(preview);for(const canary of ["responseBase64","evidenceSource","certificateBindingAssertion","privateKey","consentedAt"])assert.equal(rendered.includes(canary),false);
  assert.deepEqual(caller,callerBefore,"API/intake copy cleanup leaves the caller-owned bytes unchanged");assert.equal(tableSnapshot(),protectedBefore,"successful prepare leaves every durable table unchanged");
  const guard=guardManagementRequest(sessions,["https://manager.test"],{method:"POST",cookieHeader:headers.cookie,originHeader:headers.origin,csrfHeader:headers["x-csrf-token"]});assert.ok(guard.ok);
  assert.equal(intake.candidateRegistry.inspect(guard,preview.candidateHandle).ok,true,"candidate is available after API return");
  const claim=intake.candidateRegistry.claim(guard,{handle:preview.candidateHandle,action:"append-supplemental-native-evidence",disposition:"evidence-only"});assert.ok(claim.ok);
  const responseBytes=Buffer.from((JSON.parse(Buffer.from(raw).toString("utf8")) as {responseBase64:string}).responseBase64,"base64");let leasePayload=false,leaseResponse=false;
  stores.withAuditTransaction(tx=>{const view=intake.candidateRegistry.withLeaseView(guard,tx,claim.token,candidate=>{leasePayload=Buffer.from(candidate.payloadBytes).equals(Buffer.from(callerBefore));leaseResponse=Buffer.from(candidate.responseBytes).equals(responseBytes);return "match";});assert.deepEqual(view,{ok:true,match:true});});
  assert.equal(leasePayload,true,"actual lease view retains exact original payload bytes");assert.equal(leaseResponse,true,"actual lease view retains exact decoded response bytes");
  assert.equal((await invoke(caller,{})).status,401,"unauthorized prepare is rejected by the real session guard");assert.equal(tableSnapshot(),protectedBefore);
  const malformed=Uint8Array.from(Buffer.from('{"tuple":'));assert.equal((await invoke(malformed)).status,400,"authenticated malformed wire payload is rejected");assert.equal(tableSnapshot(),protectedBefore);
  const staleObject=JSON.parse(Buffer.from(callerBefore).toString("utf8"));staleObject.tuple.terminalRevision="stale-revision";const stale=Uint8Array.from(Buffer.from(JSON.stringify(staleObject)));
  assert.equal((await invoke(stale)).status,400,"stale terminal tuple cannot prepare through API");assert.equal(tableSnapshot(),protectedBefore,"unauthorized, malformed, and stale prepares do not mutate jobs/history/commands/evidence/audit/certificates/owner/session rows");
  intake.close();
 } finally { db.close(); }
});
