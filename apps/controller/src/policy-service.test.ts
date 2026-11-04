import { DatabaseSync } from "node:sqlite";
import { commandAuthorizationDigest, type CommandRequest } from "@lan-model-manager/core";
import assert from "node:assert/strict";import test from "node:test";import { openControllerDatabase,migrateControllerDatabase,CONTROLLER_MIGRATIONS } from "./database.js";import { PolicyService } from "./policy-service.js";import type { SessionMetadata } from "./session-types.js";
const NOW="2026-09-28T07:00:00.000Z";const auth=()=>({ok:true as const,session:{ownerId:"owner-1",credentialVersion:1,sessionVersion:1,createdAt:NOW,lastSeenAt:NOW,absoluteExpiresAt:"2026-09-29T07:00:00.000Z",idleExpiresAt:"2026-09-28T08:00:00.000Z",revokedAt:null} satisfies SessionMetadata});const policy=(version=1)=>({version,allowedOperations:["observe","provider-status","model-status","model-load"],approvalOperations:["model-load"],allowArtifactAcquisition:false,allowArtifactRemoval:false,allowSubstitution:false,allowPublicExposure:false,minimumMemoryHeadroomBytes:0,minimumVramHeadroomBytes:0,minimumStorageHeadroomBytes:0,maxConcurrentOperations:2,maxOperationsPerMinute:10});const intent=(requestId="1".repeat(64))=>({requestId,actorKind:"controller",actorId:"controller",operation:"model-load",targetKind:"model",targetId:"model-1",hostId:"host-1",modelId:"model-1",observationFresh:true,hostRevoked:false,modelCompatible:true,publicExposure:false,availableMemoryBytes:1,availableVramBytes:1,availableStorageBytes:1,activeOperations:0,operationsLastMinute:0});
test("owner guard is required to install and inference bearer is rejected",()=>{const db=openControllerDatabase(":memory:");try{const service=new PolicyService(db,{clock:()=>NOW});assert.equal(service.install(policy(),"Bearer inference").ok,false);assert.equal(service.install(policy(),auth().session).ok,false);assert.equal(service.install(policy(),auth()).ok,true);}finally{db.close();}});
test("approval is exact single-use durable and audited",()=>{const db=openControllerDatabase(":memory:");try{let random=0;const service=new PolicyService(db,{clock:()=>NOW,random:n=>Buffer.alloc(n,++random)});assert.ok(service.install(policy(),auth()).ok);const request=intent(),decision=service.authorize(request);assert.ok(decision.ok);assert.equal(decision.value.requiresApproval,true);assert.equal(decision.value.allowed,false);const grant=service.approve(request.requestId,auth());assert.ok(grant.ok);const consumed=service.consume(grant.value.approvalId,request);assert.ok(consumed.ok);assert.deepEqual(Object.keys(consumed.value).sort(),["expiresAt","hostId","modelId","operation","requestDigest","targetId","targetKind"]);assert.equal(service.consume(grant.value.approvalId,request).ok,false);assert.equal(db.prepare("SELECT COUNT(*) count FROM audit_events").get()!.count,3);const service2=new PolicyService(db,{clock:()=>NOW});assert.equal(service2.consume(grant.value.approvalId,request).ok,false);}finally{db.close();}});
test("pending approvals expose exact public targets and disappear after grant",()=>{const db=openControllerDatabase(":memory:");try{const service=new PolicyService(db,{clock:()=>NOW,random:n=>Buffer.alloc(n,3)});assert.ok(service.install(policy(),auth()).ok);const request=intent();assert.ok(service.authorize(request).ok);const pending=service.pending(auth());assert.ok(pending.ok);assert.equal(pending.value.length,1);assert.equal(pending.value[0]!.requestId,request.requestId);assert.equal(pending.value[0]!.operation,"model-load");assert.equal(pending.value[0]!.targetKind,"model");assert.equal(pending.value[0]!.targetId,"model-1");assert.deepEqual(pending.value[0]!.reasons,["approval-required"]);assert.equal(pending.value[0]!.createdAt,NOW);assert.equal(service.pending("Bearer inference").ok,false);assert.ok(service.approve(request.requestId,auth()).ok);const after=service.pending(auth());assert.ok(after.ok);assert.equal(after.value.length,0);}finally{db.close();}});
test("expiry version drift and digest mismatch fail closed",()=>{const db=openControllerDatabase(":memory:");try{let now=NOW,random=6;const service=new PolicyService(db,{clock:()=>now,random:n=>Buffer.alloc(n,++random)});assert.ok(service.install(policy(),auth()).ok);const request=intent(),decision=service.authorize(request),grant=service.approve(request.requestId,auth(),1000);assert.ok(decision.ok&&grant.ok);assert.equal(service.consume(grant.value.approvalId,{...request,targetId:"model-2"}).ok,false);assert.ok(service.install(policy(2),auth()).ok);assert.equal(service.consume(grant.value.approvalId,request).ok,false);const request2=intent("2".repeat(64));service.authorize(request2);const grant2=service.approve(request2.requestId,auth(),1000);assert.ok(grant2.ok);now="2026-09-28T07:00:01.000Z";assert.equal(service.consume(grant2.value.approvalId,request2).ok,false);}finally{db.close();}});
test("no-prompt convenience mode skips prompts but preserves hard denials and is audited",()=>{const db=openControllerDatabase(":memory:");try{const service=new PolicyService(db,{clock:()=>NOW});assert.ok(service.install(policy(),auth()).ok);let settings=service.settings(auth());assert.ok(settings.ok);assert.equal(settings.value.noPromptEnabled,false);assert.ok(service.setConvenience({enabled:true},auth()).ok);settings=service.settings(auth());assert.ok(settings.ok);assert.equal(settings.value.noPromptEnabled,true);const allowed=service.authorize(intent("3".repeat(64)));assert.ok(allowed.ok);assert.equal(allowed.value.requiresApproval,false);assert.equal(allowed.value.allowed,true);const denied=service.authorize({...intent("4".repeat(64)),observationFresh:false});assert.ok(denied.ok);assert.equal(denied.value.allowed,false);assert.ok(denied.value.reasons.includes("stale-host"));assert.ok(service.setConvenience({enabled:false},auth()).ok);const prompted=service.authorize(intent("5".repeat(64)));assert.ok(prompted.ok);assert.equal(prompted.value.requiresApproval,true);assert.equal(db.prepare("SELECT COUNT(*) count FROM audit_events WHERE json_extract(event_json,'$.action') LIKE 'policy-no-prompt-%'").get()!.count,2);}finally{db.close();}});
test("concurrent approval consumption has one winner",async()=>{const db=openControllerDatabase(":memory:");try{const service=new PolicyService(db,{clock:()=>NOW,random:n=>Buffer.alloc(n,9)});service.install(policy(),auth());const request=intent();service.authorize(request);const grant=service.approve(request.requestId,auth());assert.ok(grant.ok);const results=await Promise.all([Promise.resolve().then(()=>service.consume(grant.value.approvalId,request)),Promise.resolve().then(()=>service.consume(grant.value.approvalId,request))]);assert.equal(results.filter(v=>v.ok).length,1);}finally{db.close();}});
test("migration11 creates policy approval tables",()=>{assert.equal(CONTROLLER_MIGRATIONS.length,17);assert.equal(CONTROLLER_MIGRATIONS[10]!.name,"private-plan-authorization-v1");});

test("consumed approval validates only its durably bound canonical command",()=>{
 const db=openControllerDatabase(":memory:");
 try{
  const service=new PolicyService(db,{clock:()=>NOW});assert.ok(service.install(policy(),auth()).ok);
  const input=intent(),decision=service.authorize(input);assert.ok(decision.ok);
  const command:CommandRequest={requestId:input.requestId,jobId:"approved-job",hostId:input.hostId,operation:"load",idempotencyKey:"approved-idem",sequence:1,deadline:"2026-09-28T07:04:00.000Z",capability:{operation:"model-load",targetKind:"model",targetId:"model-1",hostId:"host-1",modelId:"model-1",requestDigest:"0".repeat(64),expiresAt:"2026-09-28T07:04:00.000Z"},params:{providerId:"provider-1",model:"example/model:latest"}};
  const rehash=(value:CommandRequest)=>{const copy={...value,capability:{...value.capability}};copy.capability.requestDigest=commandAuthorizationDigest(copy);return copy;};
  const exact=rehash(command),grant=service.approve(input.requestId,auth());assert.ok(grant.ok);
  assert.equal(service.consume(grant.value.approvalId,input,{...exact,requestId:"other"}).ok,false);
  assert.ok(service.consume(grant.value.approvalId,input,exact).ok);
  assert.equal(service.validateCapability(exact.capability,input,decision.value),false);
  assert.equal(service.validateCapability(exact.capability,input,decision.value,exact),true);
  const replay=new PolicyService(db,{clock:()=>NOW});
  assert.equal(replay.validateCapability(exact.capability,input,decision.value,exact),true);
  for(const delta of [{jobId:"different-job"},{idempotencyKey:"different-idem"},{sequence:2},{deadline:"2026-09-28T07:03:00.000Z"},{params:{providerId:"provider-1",model:"example/model:latest",keepAlive:"30s"}}]){
   const changed=rehash({...exact,...delta});
   assert.equal(replay.validateCapability(changed.capability,input,decision.value,changed),false);
   assert.equal(replay.consume(grant.value.approvalId,input,changed).ok,false);
  }
  assert.equal(replay.validateCapability(exact.capability,{...input,actorId:"other-owner"},decision.value,exact),false);
  db.prepare("UPDATE approvals SET revoked_at=? WHERE approval_id=?").run(NOW,grant.value.approvalId);
  assert.equal(replay.validateCapability(exact.capability,input,decision.value,exact),false);
 }finally{db.close();}
});

test("legacy consumed approvals stay unbound and fail closed after schema upgrade",()=>{
 const db=new DatabaseSync(":memory:");
 try{
  migrateControllerDatabase(db,CONTROLLER_MIGRATIONS.slice(0,14));
  const service=new PolicyService(db,{clock:()=>NOW});assert.ok(service.install(policy(),auth()).ok);
  const input=intent(),decision=service.authorize(input);assert.ok(decision.ok);
  const grant=service.approve(input.requestId,auth());assert.ok(grant.ok);
  // Representative pre-upgrade consumed row: no trustworthy command binding.
  db.prepare("UPDATE approvals SET consumed_at=? WHERE approval_id=?").run(NOW,grant.value.approvalId);
  migrateControllerDatabase(db);
  const command:CommandRequest={requestId:input.requestId,jobId:"legacy-replay",hostId:input.hostId,operation:"load",idempotencyKey:"legacy-idem",sequence:1,deadline:"2026-09-28T07:04:00.000Z",capability:{operation:"model-load",targetKind:"model",targetId:"model-1",hostId:"host-1",modelId:"model-1",requestDigest:"0".repeat(64),expiresAt:"2026-09-28T07:04:00.000Z"},params:{providerId:"provider-1",model:"example/model:latest"}};
  (command.capability as {requestDigest:string}).requestDigest=commandAuthorizationDigest(command);
  assert.equal(service.validateCapability(command.capability,input,decision.value,command),false);
  assert.equal(service.consume(grant.value.approvalId,input,command).ok,false);
  assert.equal((db.prepare("SELECT consumed_command_digest FROM approvals WHERE approval_id=?").get(grant.value.approvalId) as any).consumed_command_digest,null);
 }finally{db.close();}
});
