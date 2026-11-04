import { DatabaseSync } from "node:sqlite";
import { commandAuthorizationDigest, type CommandRequest } from "@lan-model-manager/core";
import assert from "node:assert/strict";import test from "node:test";import { openControllerDatabase,migrateControllerDatabase,CONTROLLER_MIGRATIONS } from "./database.js";import { PolicyService } from "./policy-service.js";import type { SessionMetadata } from "./session-types.js";
const NOW="2026-09-28T07:00:00.000Z";const auth=()=>({ok:true as const,session:{ownerId:"owner-1",credentialVersion:1,sessionVersion:1,createdAt:NOW,lastSeenAt:NOW,absoluteExpiresAt:"2026-09-29T07:00:00.000Z",idleExpiresAt:"2026-09-28T08:00:00.000Z",revokedAt:null} satisfies SessionMetadata});const policy=(version=1)=>({version,allowedOperations:["observe","provider-status","model-status","model-load"],approvalOperations:["model-load"],allowArtifactAcquisition:false,allowArtifactRemoval:false,allowSubstitution:false,allowPublicExposure:false,minimumMemoryHeadroomBytes:0,minimumVramHeadroomBytes:0,minimumStorageHeadroomBytes:0,maxConcurrentOperations:2,maxOperationsPerMinute:10});const intent=(requestId="1".repeat(64))=>({requestId,actorKind:"controller",actorId:"controller",operation:"model-load",targetKind:"model",targetId:"model-1",hostId:"host-1",modelId:"model-1",observationFresh:true,hostRevoked:false,modelCompatible:true,publicExposure:false,availableMemoryBytes:1,availableVramBytes:1,availableStorageBytes:1,activeOperations:0,operationsLastMinute:0});
test("owner guard is required to install and inference bearer is rejected",()=>{const db=openControllerDatabase(":memory:");try{const service=new PolicyService(db,{clock:()=>NOW});assert.equal(service.install(policy(),"Bearer inference").ok,false);assert.equal(service.install(policy(),auth().session).ok,false);assert.equal(service.install(policy(),auth()).ok,true);}finally{db.close();}});
test("approval is exact single-use durable and audited",()=>{const db=openControllerDatabase(":memory:");try{let random=0;const service=new PolicyService(db,{clock:()=>NOW,random:n=>Buffer.alloc(n,++random)});assert.ok(service.install(policy(),auth()).ok);const request=intent(),decision=service.authorize(request);assert.ok(decision.ok);assert.equal(decision.value.requiresApproval,true);assert.equal(decision.value.allowed,false);const grant=service.approve(request.requestId,auth());assert.ok(grant.ok);const consumed=service.consume(grant.value.approvalId,request);assert.ok(consumed.ok);assert.deepEqual(Object.keys(consumed.value).sort(),["expiresAt","hostId","modelId","operation","requestDigest","targetId","targetKind"]);assert.equal(service.consume(grant.value.approvalId,request).ok,false);assert.equal(db.prepare("SELECT COUNT(*) count FROM audit_events").get()!.count,3);const service2=new PolicyService(db,{clock:()=>NOW});assert.equal(service2.consume(grant.value.approvalId,request).ok,false);}finally{db.close();}});
test("pending approvals expose exact public targets and disappear after grant",()=>{const db=openControllerDatabase(":memory:");try{const service=new PolicyService(db,{clock:()=>NOW,random:n=>Buffer.alloc(n,3)});assert.ok(service.install(policy(),auth()).ok);const request=intent();assert.ok(service.authorize(request).ok);const pending=service.pending(auth());assert.ok(pending.ok);assert.equal(pending.value.length,1);assert.equal(pending.value[0]!.requestId,request.requestId);assert.equal(pending.value[0]!.operation,"model-load");assert.equal(pending.value[0]!.targetKind,"model");assert.equal(pending.value[0]!.targetId,"model-1");assert.deepEqual(pending.value[0]!.reasons,["approval-required"]);assert.equal(pending.value[0]!.createdAt,NOW);assert.equal(service.pending("Bearer inference").ok,false);assert.ok(service.approve(request.requestId,auth()).ok);const after=service.pending(auth());assert.ok(after.ok);assert.equal(after.value.length,0);}finally{db.close();}});
test("expiry version drift and digest mismatch fail closed",()=>{const db=openControllerDatabase(":memory:");try{let now=NOW,random=6;const service=new PolicyService(db,{clock:()=>now,random:n=>Buffer.alloc(n,++random)});assert.ok(service.install(policy(),auth()).ok);const request=intent(),decision=service.authorize(request),grant=service.approve(request.requestId,auth(),1000);assert.ok(decision.ok&&grant.ok);assert.equal(service.consume(grant.value.approvalId,{...request,targetId:"model-2"}).ok,false);assert.ok(service.install(policy(2),auth()).ok);assert.equal(service.consume(grant.value.approvalId,request).ok,false);const request2=intent("2".repeat(64));service.authorize(request2);const grant2=service.approve(request2.requestId,auth(),1000);assert.ok(grant2.ok);now="2026-09-28T07:00:01.000Z";assert.equal(service.consume(grant2.value.approvalId,request2).ok,false);}finally{db.close();}});
test("no-prompt convenience mode skips prompts but preserves hard denials and is audited",()=>{const db=openControllerDatabase(":memory:");try{const service=new PolicyService(db,{clock:()=>NOW});assert.ok(service.install(policy(),auth()).ok);let settings=service.settings(auth());assert.ok(settings.ok);assert.equal(settings.value.noPromptEnabled,false);assert.ok(service.setConvenience({enabled:true,expectedVersion:1},auth()).ok);settings=service.settings(auth());assert.ok(settings.ok);assert.equal(settings.value.noPromptEnabled,true);const allowed=service.authorize(intent("3".repeat(64)));assert.ok(allowed.ok);assert.equal(allowed.value.requiresApproval,false);assert.equal(allowed.value.allowed,true);const denied=service.authorize({...intent("4".repeat(64)),observationFresh:false});assert.ok(denied.ok);assert.equal(denied.value.allowed,false);assert.ok(denied.value.reasons.includes("stale-host"));assert.ok(service.setConvenience({enabled:false,expectedVersion:2},auth()).ok);const prompted=service.authorize(intent("5".repeat(64)));assert.ok(prompted.ok);assert.equal(prompted.value.requiresApproval,true);assert.equal(db.prepare("SELECT COUNT(*) count FROM audit_events WHERE json_extract(event_json,'$.action') LIKE 'policy-no-prompt-%'").get()!.count,2);}finally{db.close();}});
test("concurrent approval consumption has one winner",async()=>{const db=openControllerDatabase(":memory:");try{const service=new PolicyService(db,{clock:()=>NOW,random:n=>Buffer.alloc(n,9)});service.install(policy(),auth());const request=intent();service.authorize(request);const grant=service.approve(request.requestId,auth());assert.ok(grant.ok);const results=await Promise.all([Promise.resolve().then(()=>service.consume(grant.value.approvalId,request)),Promise.resolve().then(()=>service.consume(grant.value.approvalId,request))]);assert.equal(results.filter(v=>v.ok).length,1);}finally{db.close();}});
test("migration11 creates policy approval tables",()=>{assert.equal(CONTROLLER_MIGRATIONS.length,18);assert.equal(CONTROLLER_MIGRATIONS[10]!.name,"private-plan-authorization-v1");});

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

test("exact proposal grants bind immutable intent, full execution, unique session and credential version before consumption",()=>{
 const db=openControllerDatabase(":memory:");try{
  const service=new PolicyService(db,{clock:()=>NOW});assert.ok(service.install(policy(),auth()).ok);
  const input={...intent(),actorKind:"owner" as const,actorId:"owner-1",operation:"model-load" as const,targetKind:"model" as const};
  assert.ok(service.authorize(input).ok);
  const command:CommandRequest={requestId:input.requestId,jobId:"exact-job",hostId:input.hostId,operation:"load",idempotencyKey:"exact-idem",sequence:1,deadline:"2026-09-28T07:04:00.000Z",capability:{operation:"model-load",targetKind:"model",targetId:"model-1",hostId:"host-1",modelId:"model-1",requestDigest:"0".repeat(64),expiresAt:"2026-09-28T07:04:00.000Z"},params:{providerId:"provider-1",model:"example:model"}};
  (command.capability as {requestDigest:string}).requestDigest=commandAuthorizationDigest(command);
  const binding={id:"a".repeat(64),credentialVersion:1,expiresAt:command.deadline};
  assert.ok(service.bindProposal(input,command,binding));assert.equal(service.approve(input.requestId,auth()).ok,false);
  assert.equal(service.approveExact({...input,availableMemoryBytes:2},command,auth(),binding).ok,false);
  const grant=service.approveExact(input,command,auth(),binding);assert.ok(grant.ok);
  assert.equal(service.consume(grant.value.approvalId,input,command).ok,false,"legacy consume cannot use exact grant");
  assert.equal(service.consumeExact(grant.value.approvalId,input,command,{...binding,id:"b".repeat(64)}).ok,false,"another same-owner session cannot consume");
  assert.equal(service.consumeExact(grant.value.approvalId,input,command,{...binding,credentialVersion:2}).ok,false);
  assert.equal(service.consumeExact(grant.value.approvalId,{...input,availableMemoryBytes:2},command,binding).ok,false);
  const changed={...command,jobId:"other-job",capability:{...command.capability}};changed.capability.requestDigest=commandAuthorizationDigest(changed);
  assert.equal(service.consumeExact(grant.value.approvalId,input,changed,binding).ok,false);
  assert.equal((db.prepare("SELECT consumed_at FROM approvals").get() as any).consumed_at,null);
  assert.ok(service.consumeExact(grant.value.approvalId,input,command,binding).ok);assert.equal(service.consumeExact(grant.value.approvalId,input,command,binding).ok,false);
 }finally{db.close();}
});
test("migration18 appends exact owner proposal authority without rewriting any of migrations1 through17",()=>{
 const db=new DatabaseSync(":memory:");try{
  migrateControllerDatabase(db,CONTROLLER_MIGRATIONS.slice(0,17));const before=db.prepare("SELECT * FROM schema_migrations ORDER BY version").all();
  migrateControllerDatabase(db);assert.deepEqual(db.prepare("SELECT * FROM schema_migrations WHERE version<=17 ORDER BY version").all(),before);
  assert.equal(db.prepare("PRAGMA user_version").get()!.user_version,18);assert.deepEqual(db.prepare("PRAGMA foreign_key_check").all(),[]);
 }finally{db.close();}
});

test("constrained settings CAS preserves flags, rejects strict inputs and rolls back on audit failure",()=>{
 const db=openControllerDatabase(":memory:");try{
 const service=new PolicyService(db,{clock:()=>NOW});const base={...policy(),allowArtifactAcquisition:true,allowArtifactRemoval:true,allowSubstitution:true,allowPublicExposure:true,allowedOperations:[...policy().allowedOperations,"artifact-install","artifact-remove","artifact-evict","model-substitute"],approvalOperations:["model-load","artifact-remove"]};assert.ok(service.install(base,auth()).ok);
 const settings=service.settings(auth());assert.ok(settings.ok);const update={expectedVersion:1,allowedOperations:[...settings.value.allowedOperations,"model-inference"],approvalOperations:[...settings.value.approvalOperations,"model-inference"],hardLimits:settings.value.hardLimits};
 for(const invalid of [{...update,hidden:true},{...update,expectedVersion:0},{...update,expectedVersion:NaN},{...update,expectedVersion:Number.MAX_SAFE_INTEGER+1},{...update,allowedOperations:["observe","observe"]},{...update,allowedOperations:["unknown"]},{...update,approvalOperations:["model-unload"]},{...update,hardLimits:{...update.hardLimits,extra:1}},...[-1,NaN,Infinity,Number.MAX_SAFE_INTEGER+1,0.5].map(n=>({...update,hardLimits:{...update.hardLimits,minimumMemoryHeadroomBytes:n}})),...[-1,0,NaN,Number.MAX_SAFE_INTEGER+1].map(n=>({...update,hardLimits:{...update.hardLimits,maxConcurrentOperations:n}}))])assert.deepEqual({...service.updateSettings(invalid,auth())},{ok:false,error:"ERR_POLICY_INPUT"});
 assert.equal(service.current().version,1);assert.equal(service.updateSettings(update,"Bearer inference").ok,false);
 const saved=service.updateSettings(update,auth());assert.ok(saved.ok);assert.equal(saved.value.version,2);const current=service.current();for(const key of ["allowArtifactAcquisition","allowArtifactRemoval","allowSubstitution","allowPublicExposure"] as const)assert.equal(current[key],true);
 assert.deepEqual({...service.updateSettings(update,auth())},{ok:false,error:"ERR_POLICY_CONFLICT"});assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_events WHERE json_extract(event_json,'$.action')='policy-settings-save'").get()!.n,1);
 db.exec("CREATE TRIGGER reject_settings_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'fixture audit failure'); END");assert.equal(service.updateSettings({...update,expectedVersion:2},auth()).ok,false);assert.equal(service.current().version,2);
 }finally{db.close();}
});
test("constrained saves invalidate previous authorization digest and preserve legacy disabled approvals",()=>{
 const db=openControllerDatabase(":memory:");try{const service=new PolicyService(db,{clock:()=>NOW});assert.ok(service.install({...policy(),approvalOperations:["model-load","artifact-remove"]},auth()).ok);const input=intent(),decision=service.authorize(input);assert.ok(decision.ok);const grant=service.approve(input.requestId,auth());assert.ok(grant.ok);const snapshot=service.settings(auth());assert.ok(snapshot.ok);assert.ok(service.updateSettings({expectedVersion:1,allowedOperations:snapshot.value.allowedOperations,approvalOperations:snapshot.value.approvalOperations,hardLimits:snapshot.value.hardLimits},auth()).ok);assert.equal(service.consume(grant.value.approvalId,input).ok,false);assert.ok(service.current().approvalOperations.includes("artifact-remove"));}finally{db.close();}
});
test("constrained DTO accepts all twelve core operations and the safe integer ceiling without new flags",()=>{
 const db=openControllerDatabase(":memory:");try{const service=new PolicyService(db,{clock:()=>NOW});const operations=["observe","provider-status","model-status","model-inference","model-load","model-unload","model-set-options","model-drain","artifact-install","artifact-remove","artifact-evict","model-substitute"],hardLimits={minimumMemoryHeadroomBytes:Number.MAX_SAFE_INTEGER,minimumVramHeadroomBytes:0,minimumStorageHeadroomBytes:0,maxConcurrentOperations:Number.MAX_SAFE_INTEGER,maxOperationsPerMinute:Number.MAX_SAFE_INTEGER};
 const update={expectedVersion:1,allowedOperations:operations,approvalOperations:operations,hardLimits};assert.equal(service.updateSettings({...update,approvalOperations:["model-load","model-load"]},auth()).ok,false);const saved=service.updateSettings(update,auth());assert.ok(saved.ok);assert.equal(saved.value.allowedOperations.length,12);assert.equal(saved.value.hardLimits.minimumMemoryHeadroomBytes,Number.MAX_SAFE_INTEGER);assert.equal(service.current().allowArtifactAcquisition,false);assert.equal(service.current().allowArtifactRemoval,false);assert.equal(service.current().allowSubstitution,false);assert.equal(service.current().allowPublicExposure,false);
 }finally{db.close();}
});

test("all policy writers fail cleanly at the safe version ceiling; audit failures rollback convenience",()=>{
 for(const writer of ["settings","convenience"] as const){const db=openControllerDatabase(":memory:");try{
  const service=new PolicyService(db,{clock:()=>NOW});assert.ok(service.install(policy(Number.MAX_SAFE_INTEGER-1),auth()).ok);
  const edit=(version:number)=>{const p=service.settings(auth());assert.ok(p.ok);return {expectedVersion:version,allowedOperations:p.value.allowedOperations,approvalOperations:p.value.approvalOperations,hardLimits:p.value.hardLimits};};
  const saved=writer==="settings"?service.updateSettings(edit(Number.MAX_SAFE_INTEGER-1),auth()):service.setConvenience({enabled:true,expectedVersion:Number.MAX_SAFE_INTEGER-1},auth());assert.ok(saved.ok);assert.equal(saved.value.version,Number.MAX_SAFE_INTEGER);
  const rows=()=>({documents:db.prepare("SELECT CAST(version AS TEXT) version,canonical_json FROM policy_documents ORDER BY version").all(),audit:db.prepare("SELECT * FROM audit_events").all()});const before=rows();
  assert.deepEqual({...service.updateSettings(edit(Number.MAX_SAFE_INTEGER),auth())},{ok:false,error:"ERR_POLICY_INPUT"});
  for(const enabled of [true,false])assert.deepEqual({...service.setConvenience({enabled,expectedVersion:Number.MAX_SAFE_INTEGER},auth())},{ok:false,error:"ERR_POLICY_INPUT"});
  assert.deepEqual({...service.install(policy(Number.MAX_SAFE_INTEGER+1),auth())},{ok:false,error:"ERR_POLICY_INPUT"});assert.deepEqual(rows(),before);assert.ok(service.settings(auth()).ok);assert.equal(service.current().version,Number.MAX_SAFE_INTEGER);
 }finally{db.close();}}
 const db=openControllerDatabase(":memory:");try{const service=new PolicyService(db,{clock:()=>NOW});assert.ok(service.install(policy(),auth()).ok);db.exec("CREATE TRIGGER reject_convenience_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'fixture failure'); END");assert.deepEqual({...service.setConvenience({enabled:true,expectedVersion:1},auth())},{ok:false,error:"ERR_POLICY_DATABASE"});assert.equal(service.current().version,1);assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_events").get()!.n,0);}finally{db.close();}
});

test("fresh convenience preserves every allowed operation, hidden flag and limit; strict descriptors fail closed",()=>{
 const db=openControllerDatabase(":memory:");try{const service=new PolicyService(db,{clock:()=>NOW});const base={...policy(),allowArtifactAcquisition:true,allowArtifactRemoval:true,allowSubstitution:true,allowPublicExposure:true,allowedOperations:[...policy().allowedOperations,"artifact-remove","model-set-options"],approvalOperations:["model-load","artifact-remove"]};assert.ok(service.install(base,auth()).ok);
 for(const input of [{enabled:true},{enabled:true,expectedVersion:1,extra:true},{enabled:true,expectedVersion:0},{enabled:true,expectedVersion:Infinity},Object.defineProperty({expectedVersion:1},"enabled",{get(){throw new Error("must not invoke");}})])assert.deepEqual({...service.setConvenience(input,auth())},{ok:false,error:"ERR_POLICY_INPUT"});
 assert.ok(service.setConvenience({enabled:true,expectedVersion:1},auth()).ok);const {version,approvalOperations,...rest}=service.current(),{version:oldVersion,approvalOperations:oldApproval,...oldRest}=base;assert.deepEqual({...rest},{...oldRest,allowedOperations:[...oldRest.allowedOperations].sort()});assert.equal(version,2);assert.deepEqual(approvalOperations,[]);
 assert.ok(service.setConvenience({enabled:false,expectedVersion:2},auth()).ok);assert.deepEqual(service.current().approvalOperations,["artifact-remove","model-load","model-set-options"]);
 }finally{db.close();}
});
