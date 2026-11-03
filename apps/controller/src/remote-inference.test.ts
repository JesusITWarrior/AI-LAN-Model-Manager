import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { commandAuthorizationDigest, parseStreamCommand, type CommandRequest, type OperationPolicy } from "@lan-model-manager/core";
import { openControllerDatabase, CONTROLLER_MIGRATIONS, migrateControllerDatabase } from "./database.js";
import { DatabaseSync } from "node:sqlite";
import { createControllerRepositories } from "./repositories.js";
import { createJobStores } from "./jobs-store.js";
import { createOwnerBootstrapService } from "./owner-service.js";
import { InferenceTokenManager } from "./inference-manager.js";
import { PolicyService } from "./policy-service.js";
import { CertificateRepository } from "./certificate-repository.js";
import { createAdmissionController } from "./admission-accounting.js";
import { RemoteInferenceService } from "./remote-inference.js";
import { AgentCommandStore } from "./agent-command-channel.js";
import type { AgentStreamRelay } from "./agent-stream-relay.js";

const NOW="2026-10-01T12:00:00.000Z",OWNER="a".repeat(32),MODEL="example/model:latest",SECRET="synthetic-private-prompt-never-persist";
const guard={ok:true,session:{ownerId:OWNER,sessionVersion:1,revokedAt:null}};
const allowed:OperationPolicy={version:1,allowedOperations:["model-inference"],approvalOperations:[],allowArtifactAcquisition:false,allowArtifactRemoval:false,allowSubstitution:false,allowPublicExposure:false,minimumMemoryHeadroomBytes:1,minimumVramHeadroomBytes:0,minimumStorageHeadroomBytes:1,maxConcurrentOperations:10,maxOperationsPerMinute:100};
async function fixture(){
 const db=openControllerDatabase(":memory:");let now=NOW,n=10;
 const clock=()=>now,repos=createControllerRepositories(db,{now:clock}),jobs=createJobStores(db,{now:clock});
 const owner=createOwnerBootstrapService(db,{now:clock,ownerId:()=>OWNER,crypto:{random:size=>Buffer.alloc(size,3),async derive(password,salt,p){return Buffer.alloc(p.keyLength,createHash("sha256").update(password).update(salt).digest()[0]);},equal:(a,b)=>Buffer.from(a).equals(Buffer.from(b))}});
 await owner.bootstrapOwner({username:"Owner",password:"synthetic-owner-password"});
 const tokens=new InferenceTokenManager(db,async v=>v==="management",{clock,random:size=>Buffer.alloc(size,++n)}),issued=await tokens.issue("management",{label:"synthetic",ttlMs:60000});assert.ok(issued);
 const context=Object.freeze({token:issued.metadata}),policy=new PolicyService(db,{clock,stores:jobs}),admissions=createAdmissionController({clock});
 const certs=new CertificateRepository(db),pem="-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n",fp="b".repeat(64);
 certs.insertCa({caId:"c".repeat(64),version:1,serial:"10",fingerprint:"c".repeat(64),certificatePem:pem,notBefore:"2026-01-01T00:00:00.000Z",notAfter:"2036-01-01T00:00:00.000Z",createdAt:NOW});
 certs.insertHost({certificateId:fp,serial:"ABCD",fingerprint:fp,certificatePem:pem,caId:"c".repeat(64),caVersion:1,binding:{candidateId:"host-1",address:"192.0.2.10",port:7443,protocolMajor:1,protocolMinor:0},spiffeUri:"spiffe://lanmodelmanager/host/host-1",challengeId:"d".repeat(64),transcriptDigest:"e".repeat(64),notBefore:"2026-01-01T00:00:00.000Z",notAfter:"2027-01-01T00:00:00.000Z",status:"active",version:1,issuedAt:NOW,revokedAt:null});
 repos.hosts.upsert({hostId:"host-1",displayName:"Synthetic",platform:"linux",observedAt:NOW,online:true,freshness:"fresh",snapshot:{resource:{hostId:"host-1",platform:"linux",observedAt:NOW,cpuLogicalCores:4,cpuUtilizationPercent:0,memory:{totalBytes:100,usedBytes:10,availableBytes:90},storage:{totalBytes:100,usedBytes:10,availableBytes:90},accelerators:[]}}});
 repos.providers.upsert({providerId:"provider-1",hostId:"host-1",kind:"ollama",endpoint:"http://127.0.0.1:11434",health:"ready",version:"",versionKnown:false,observedAt:NOW,snapshot:{}});
 repos.models.upsert({modelId:"model-1",providerId:"provider-1",hostId:"host-1",canonicalName:MODEL,state:"running",type:"llm",digest:"",digestKnown:false,observedAt:NOW,snapshot:{modelId:"model-1",providerId:"provider-1",displayName:MODEL,artifactState:"installed",runtimeState:"loaded-idle",activeRequests:0,managedTemporary:false,observedAt:NOW}});
 db.prepare("INSERT INTO fleet_liveness(host_id,certificate_fingerprint,protocol_minor,last_sequence,last_observed_at,last_request_id,idle,updated_at) VALUES(?,?,?,?,?,?,?,?)").run("host-1",fp,0,1,NOW,"heartbeat-1",1,NOW);
 const service=new RemoteInferenceService(repos,tokens,policy,admissions,jobs,clock),input={model:MODEL,messages:[{role:"user" as const,content:SECRET}]};
 const ready=()=>{admissions.register("model-1");assert.ok(policy.install(allowed,guard).ok);};
 const select=()=>service.select(context,MODEL),open=(signal=new AbortController().signal)=>service.open(context,select(),input,signal);
 return{db,repos,jobs,tokens,issued,context,policy,admissions,certs,fp,clock,service,input,ready,select,open,setNow:(s:string)=>now=s,close(){service.close();db.close();}};
}

test("exact identity default deny and unknown admission stay closed without manufacturing idle",async()=>{
 const x=await fixture();try{
  assert.throws(x.select,/ERR_REMOTE_INFERENCE/);assert.throws(()=>x.admissions.snapshot("model-1"));
  x.admissions.register("model-1");assert.throws(x.select);assert.ok(x.policy.install({...allowed,approvalOperations:["model-inference"]},guard).ok);assert.throws(x.select);
  assert.ok(x.policy.install({...allowed,version:2},guard).ok);assert.equal(x.select().modelId,"model-1");assert.throws(()=>x.service.select(x.context,"other/model"));
  assert.throws(()=>x.service.select({token:{...x.context.token,ownerId:"f".repeat(32)}},MODEL));
  const selected=x.select();assert.throws(()=>x.service.open(x.context,{...selected},x.input,new AbortController().signal));
  assert.equal(x.db.prepare("SELECT COUNT(*) n FROM inference_executions").get()!.n,0);
 }finally{x.close();}
});

test("dispatch rejects policy drift revoke expiry drain and changed observations after selection",async()=>{
 for(const mutation of ["policy","revoke","expiry","owner-version","drain","model","certificate","resource","liveness","foreign-resource","provider","future-resource"]){
  const x=await fixture();try{x.ready();const selected=x.select();
   if(mutation==="policy")assert.ok(x.policy.install({...allowed,version:2},guard).ok);
   if(mutation==="revoke")await x.tokens.revoke("management",x.issued.metadata.tokenId);
   if(mutation==="expiry")x.setNow("2026-10-01T12:01:00.000Z");
   if(mutation==="owner-version")x.db.exec("UPDATE owners SET credential_version=credential_version+1");
   if(mutation==="drain")await x.admissions.stopAdmission("model-1");
   if(mutation==="model")x.db.exec("UPDATE models SET state='installed'");
   if(mutation==="certificate")x.certs.revoke(x.fp,NOW);
   if(mutation==="resource")x.db.exec("UPDATE hosts SET snapshot_json=json_set(snapshot_json,'$.resource.observedAt','2026-10-01T11:58:00.000Z')");
   if(mutation==="liveness")x.db.exec("UPDATE fleet_liveness SET last_observed_at='2026-10-01T11:58:00.000Z'");
   if(mutation==="foreign-resource")x.db.exec("UPDATE hosts SET snapshot_json=json_set(snapshot_json,'$.resource.hostId','foreign-host')");
   if(mutation==="provider")x.db.exec("UPDATE providers SET health='failed'");
   if(mutation==="future-resource")x.db.exec("UPDATE hosts SET snapshot_json=json_set(snapshot_json,'$.resource.observedAt','2026-10-01T12:00:01.000Z')");
   assert.throws(()=>x.service.open(x.context,selected,x.input,new AbortController().signal),/ERR_REMOTE_INFERENCE/,mutation);assert.equal(x.service.activeCount,0);assert.equal(x.db.prepare("SELECT COUNT(*) n FROM inference_executions").get()!.n,0);
  }finally{x.close();}
 }
});

test("policy capability is canonical execution-bound and ledger excludes prompt bearer and ordinary queue",async()=>{
 const x=await fixture();try{x.ready();const handle=x.open();
  const relay=(x.service as unknown as {relay:AgentStreamRelay}).relay,command=relay.poll("host-1").streamCommand;assert.ok(command);parseStreamCommand(Buffer.from(JSON.stringify(command)));assert.equal(command.params.chat.model,MODEL);assert.equal(command.capability.targetId,"model-1");
  const row=x.db.prepare("SELECT * FROM inference_executions").get()!;assert.equal(row.command_digest,command.capability.requestDigest);assert.equal(row.token_id,x.context.token.tokenId);assert.equal(row.owner_id,OWNER);assert.equal(row.policy_version,1);assert.equal(row.outcome,"running");
  const audit=x.jobs.audit.list().find(row=>row.action==="policy-model-inference");assert.equal(audit?.actorId,OWNER);assert.equal(audit?.actorKind,"owner");
  const tables=x.db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as {name:string}[];
  const dump=JSON.stringify(tables.map(t=>x.db.prepare(`SELECT * FROM "${t.name}"`).all()));
  for(const secret of [SECRET,Buffer.from(SECRET).toString("base64"),x.issued.token])assert.equal(dump.includes(secret),false);
  assert.equal(x.db.prepare("SELECT COUNT(*) n FROM agent_commands").get()!.n,0);assert.throws(x.open);handle.cancel();handle.close();await handle.outcome;await x.service.shutdown();assert.equal(x.admissions.snapshot("model-1").active,0);assert.equal(x.admissions.snapshot("model-1").draining,true);assert.equal(x.db.prepare("SELECT outcome FROM inference_executions").get()!.outcome,"cancelled");
 }finally{x.close();}
});

test("strict terminal success settles once without closing a safely completed admission",async()=>{
 const x=await fixture();try{x.ready();const handle=x.open(),relay=(x.service as unknown as {relay:AgentStreamRelay}).relay,c=relay.poll("host-1").streamCommand!;
  const event={schemaVersion:1,hostId:c.hostId,jobId:c.jobId,requestId:c.requestId,commandDigest:c.capability.requestDigest,index:0,kind:"succeeded",chunk:{id:c.requestId,object:"chat.completion.chunk",model:MODEL,choices:[{index:0,delta:{role:"assistant",content:"synthetic"},finish_reason:"stop"}],usage:{prompt_tokens:1,completion_tokens:1,total_tokens:2}},errorCode:null};
  const publish=relay.publish("host-1",Buffer.from(JSON.stringify(event)),new AbortController().signal);assert.equal((await handle.next(new AbortController().signal))?.kind,"succeeded");await publish;assert.equal(await handle.outcome,"succeeded");handle.close();await x.service.shutdown();assert.equal(x.db.prepare("SELECT outcome FROM inference_executions").get()!.outcome,"succeeded");assert.equal(x.admissions.snapshot("model-1").active,0);assert.equal(x.admissions.snapshot("model-1").draining,false);
 }finally{x.close();}
});

test("bounded shutdown and sync fallback abort waits settle interrupted and never touch DB after close",async()=>{
 const x=await fixture();x.ready();const handle=x.open(),waiting=handle.next(new AbortController().signal);x.service.close();x.service.close();assert.equal(x.db.prepare("SELECT outcome FROM inference_executions").get()!.outcome,"interrupted");assert.equal(x.service.activeCount,0);assert.equal(x.admissions.snapshot("model-1").active,0);assert.equal(x.admissions.snapshot("model-1").draining,true);x.db.close();await waiting;await handle.outcome;handle.close();await x.service.shutdown();assert.throws(x.open);
});

test("restart terminalizes ledger without replay or synthesizing admission and scrubs legacy chat",async()=>{
 const x=await fixture();try{x.ready();const handle=x.open();
  // Simulate process loss by retaining only durable metadata in a fresh owner.
  const freshAdmissions=createAdmissionController({clock:x.clock}),next=new RemoteInferenceService(x.repos,x.tokens,x.policy,freshAdmissions,x.jobs,x.clock);
  assert.equal(x.db.prepare("SELECT outcome FROM inference_executions").get()!.outcome,"interrupted");assert.throws(()=>freshAdmissions.snapshot("model-1"));assert.throws(()=>next.select(x.context,MODEL));assert.equal((next as unknown as {relay:AgentStreamRelay}).relay.poll("host-1").streamCommand,null);next.close();handle.close();
  const request:CommandRequest={requestId:"legacy-request",jobId:"legacy-job",hostId:"host-1",operation:"inference.chat",idempotencyKey:"legacy-key",sequence:1,deadline:"2026-10-01T12:02:00.000Z",capability:{operation:"model-inference",targetKind:"model",targetId:"model-1",hostId:"host-1",modelId:"model-1",requestDigest:"0".repeat(64),expiresAt:"2026-10-01T12:02:00.000Z"},params:{providerId:"provider-1",modelId:"model-1",model:MODEL,requestId:"legacy-request",maxRequestBytes:524288,maxResponseBytes:262144,messages:[{role:"user",contentBase64:Buffer.from(SECRET).toString("base64")}],temperatureMilli:null,maxTokens:null}};
  (request.capability as {requestDigest:string}).requestDigest=commandAuthorizationDigest(request);const store=new AgentCommandStore(x.db,x.clock);
  x.jobs.jobs.create({operation:{jobId:request.jobId as never,requestId:request.requestId as never,action:"load",hostId:request.hostId as never,submittedAt:NOW as never,manifestRevision:null,idempotencyKey:request.idempotencyKey,idempotent:true},state:"submitted",updatedAt:NOW as never,progressPercent:null,attempt:1,terminalCode:null,terminalMessage:null});store.send(request);
  const restarted=new RemoteInferenceService(x.repos,x.tokens,x.policy,freshAdmissions,x.jobs,x.clock);assert.equal(store.poll("host-1").command,null);const row=x.db.prepare("SELECT * FROM agent_commands").get()!;assert.equal(row.request_json,"{}");assert.equal(row.result_json,null);assert.equal(row.state,"expired");assert.equal(x.jobs.jobs.get(request.jobId)?.state,"cancelled");assert.equal(x.jobs.jobs.get(request.jobId)?.payload.terminalCode,"INTERRUPTED");restarted.close();
 }finally{x.close();}
});

test("migration16 preserves all fifteen historical checksums",()=>{
 const db=new DatabaseSync(":memory:");try{
  migrateControllerDatabase(db,CONTROLLER_MIGRATIONS.slice(0,15));const oldPolicy=new PolicyService(db,{clock:()=>NOW});
  assert.ok(oldPolicy.install({...allowed,allowedOperations:["model-load"],approvalOperations:["model-load"]},guard).ok);
  const intent={requestId:"1".repeat(64),actorKind:"owner",actorId:OWNER,operation:"model-load",targetKind:"model",targetId:"model-1",hostId:"host-1",modelId:"model-1",observationFresh:true,hostRevoked:false,modelCompatible:true,publicExposure:false,availableMemoryBytes:90,availableVramBytes:0,availableStorageBytes:90,activeOperations:0,operationsLastMinute:0};
  assert.ok(oldPolicy.authorize(intent).ok);const approval=oldPolicy.approve(intent.requestId,guard);assert.ok(approval.ok);assert.ok(oldPolicy.consume(approval.value.approvalId,intent).ok);
  const before=db.prepare("SELECT * FROM schema_migrations ORDER BY version").all(),tables=["authorization_requests","approvals","decisions","audit_events"],rows=tables.map(t=>db.prepare(`SELECT * FROM ${t} ORDER BY rowid`).all());
  migrateControllerDatabase(db);assert.deepEqual(db.prepare("SELECT * FROM schema_migrations WHERE version<=15 ORDER BY version").all(),before);assert.equal(db.prepare("PRAGMA user_version").get()!.user_version,16);
  assert.deepEqual(tables.map(t=>db.prepare(`SELECT * FROM ${t} ORDER BY rowid`).all()),rows);assert.deepEqual(db.prepare("PRAGMA foreign_key_check").all(),[]);
  assert.ok(oldPolicy.install({...allowed,version:2},guard).ok);const inference=oldPolicy.authorize({...intent,requestId:"2".repeat(64),operation:"model-inference"});assert.ok(inference.ok);assert.equal(inference.value.allowed,true);
 }finally{db.close();}
});

test("dispatch revalidation catches changes during command construction",async()=>{
 for(const mutation of ["policy","token","drain"]){const x=await fixture();try{x.ready();const selected=x.select();const input={...x.input,get messages(){if(mutation==="policy")x.policy.install({...allowed,version:2},guard);if(mutation==="token")x.db.prepare("UPDATE inference_tokens SET revoked_at=?").run(NOW);if(mutation==="drain")void x.admissions.stopAdmission("model-1");return x.input.messages;}};assert.throws(()=>x.service.open(x.context,selected,input,new AbortController().signal),/ERR_REMOTE_INFERENCE/);assert.equal(x.db.prepare("SELECT COUNT(*) n FROM inference_executions").get()!.n,0);assert.equal(x.admissions.snapshot("model-1").active,0);}finally{x.close();}}
});

test("relay-open failure terminalizes ledger and releases its lease exactly once",async()=>{
 const x=await fixture();try{x.ready();const relay=(x.service as unknown as {relay:AgentStreamRelay}).relay;relay.open=()=>{throw new Error("synthetic relay limit");};assert.throws(x.open,/ERR_REMOTE_INFERENCE/);assert.equal(x.db.prepare("SELECT outcome FROM inference_executions").get()!.outcome,"failed");assert.equal(x.admissions.snapshot("model-1").active,0);assert.equal(x.admissions.snapshot("model-1").draining,false);assert.equal(x.service.activeCount,0);}finally{x.close();}
});

test("failed ledger finalization still cleans up and closes admission",async()=>{
 const x=await fixture();try{x.ready();const handle=x.open();x.db.exec("DROP TABLE inference_executions");handle.cancel();handle.cancel();await handle.outcome;await x.service.shutdown();assert.equal(x.service.activeCount,0);assert.equal(x.admissions.snapshot("model-1").active,0);assert.equal(x.admissions.snapshot("model-1").draining,true);assert.throws(x.select);}finally{x.close();}
});

test("stop/start refreshes relay owner without reopening uncertain targets",async()=>{
 const x=await fixture();try{x.ready();const selected=x.select(),handle=x.open();await x.service.shutdown();assert.equal(await handle.outcome,"cancelled");x.service.start();assert.throws(x.select);assert.throws(()=>x.service.open(x.context,selected,x.input,new AbortController().signal));assert.equal((x.service as unknown as {relay:AgentStreamRelay}).relay.poll("host-1").streamCommand,null);assert.equal(x.db.prepare("SELECT outcome FROM inference_executions").get()!.outcome,"interrupted");}finally{x.close();}
});

test("temporary or foreign installed snapshots and real resource/count limits deny",async()=>{
 for(const mutation of ["temporary","foreign-model","foreign-provider","artifact-removing","memory","count"]){const x=await fixture();try{x.ready();if(mutation==="temporary")x.db.exec("UPDATE models SET snapshot_json=json_set(snapshot_json,'$.managedTemporary',json('true'))");if(mutation==="foreign-model")x.db.exec("UPDATE models SET snapshot_json=json_set(snapshot_json,'$.modelId','foreign')");if(mutation==="foreign-provider")x.db.exec("UPDATE models SET snapshot_json=json_set(snapshot_json,'$.providerId','foreign')");if(mutation==="artifact-removing")x.db.exec("UPDATE models SET snapshot_json=json_set(snapshot_json,'$.artifactState','removing')");if(mutation==="memory")assert.ok(x.policy.install({...allowed,version:2,minimumMemoryHeadroomBytes:91},guard).ok);if(mutation==="count"){assert.ok(x.policy.install({...allowed,version:2,maxConcurrentOperations:1},guard).ok);x.jobs.jobs.create({operation:{jobId:"other-job" as never,requestId:"other-request" as never,action:"load",hostId:"host-1" as never,submittedAt:NOW as never,manifestRevision:null,idempotencyKey:"other-key",idempotent:true},state:"submitted",updatedAt:NOW as never,progressPercent:null,attempt:1,terminalCode:null,terminalMessage:null});}assert.throws(x.select,/ERR_REMOTE_INFERENCE/,mutation);}finally{x.close();}}
});

test("same-stack proven success survives consumer cancellation and synchronous owner close",async()=>{
 for(const mode of ["cancel","close"]){const x=await fixture();try{x.ready();const handle=x.open(),relay=(x.service as unknown as {relay:AgentStreamRelay}).relay,c=relay.poll("host-1").streamCommand!;
  const event={schemaVersion:1,hostId:c.hostId,jobId:c.jobId,requestId:c.requestId,commandDigest:c.capability.requestDigest,index:0,kind:"succeeded",chunk:{id:c.requestId,object:"chat.completion.chunk",model:MODEL,choices:[{index:0,delta:{role:"assistant",content:"synthetic"},finish_reason:"stop"}],usage:{prompt_tokens:1,completion_tokens:1,total_tokens:2}},errorCode:null};
  const publish=relay.publish("host-1",Buffer.from(JSON.stringify(event)),new AbortController().signal),next=handle.next(new AbortController().signal);
  if(mode==="cancel")handle.cancel();else x.service.close();
  assert.equal((await next)?.kind,"succeeded");await publish;assert.equal(await handle.outcome,"succeeded");assert.equal(x.db.prepare("SELECT outcome FROM inference_executions").get()!.outcome,"succeeded");assert.equal(x.admissions.snapshot("model-1").draining,false);assert.equal(x.admissions.snapshot("model-1").uncertain,undefined);
 }finally{x.close();}}
});

test("leased inference cancellation blocks unload until a fresh trusted remote drain settles",async()=>{
 const x=await fixture();try{x.ready();const handle=x.open(),relay=(x.service as unknown as {relay:AgentStreamRelay}).relay;assert.ok(relay.poll("host-1").streamCommand);handle.cancel();assert.equal(x.admissions.snapshot("model-1").active,0);assert.equal(x.admissions.snapshot("model-1").uncertain,true);
  const {LifecycleService}=await import("./lifecycle-service.js"),{RemoteLifecycleController}=await import("./remote-lifecycle.js"),{CommandDispatcher}=await import("./command-dispatch.js");
  assert.ok(x.policy.install({...allowed,version:2,allowedOperations:["model-unload","model-drain"]},guard).ok);
  const commands=new AgentCommandStore(x.db,x.clock,30000,x.jobs,true),dispatcher=new CommandDispatcher(x.jobs,commands,x.clock),lifecycle=new LifecycleService(x.policy,dispatcher,x.repos,x.admissions),remote=new RemoteLifecycleController(lifecycle,commands,x.repos,x.jobs,x.admissions,x.clock);
  const execution=(operation:"drain"|"unload",n:number)=>{const requestId=String(n).padStart(64,"0"),policyOperation=operation==="drain"?"model-drain" as const:"model-unload" as const,request:CommandRequest={requestId,jobId:`lifecycle-${n}`,hostId:"host-1",operation,idempotencyKey:`lifecycle-idem-${n}`,sequence:1,deadline:"2026-10-01T12:02:00.000Z",capability:{operation:policyOperation,targetKind:"model",targetId:"model-1",hostId:"host-1",modelId:"model-1",requestDigest:"0".repeat(64),expiresAt:"2026-10-01T12:02:00.000Z"},params:{providerId:"provider-1",model:MODEL}};(request.capability as {requestDigest:string}).requestDigest=commandAuthorizationDigest(request);return{request,intent:{requestId,actorKind:"owner" as const,actorId:OWNER,operation:policyOperation,targetKind:"model" as const,targetId:"model-1",hostId:"host-1",modelId:"model-1",observationFresh:true,hostRevoked:false,modelCompatible:true,publicExposure:false,availableMemoryBytes:90,availableVramBytes:0,availableStorageBytes:90,activeOperations:0,operationsLastMinute:0}};};
  assert.deepEqual(lifecycle.execute(execution("unload",100)),{ok:false,error:"ERR_LIFECYCLE_STATE"});assert.equal(commands.poll("host-1").command,null);
  const drain=execution("drain",101),pending=remote.execute(drain,new AbortController().signal);assert.equal(commands.poll("host-1").command?.jobId,drain.request.jobId);x.setNow("2026-10-01T12:00:05.000Z");assert.ok(commands.complete("host-1",{requestId:drain.request.requestId,jobId:drain.request.jobId,hostId:"host-1",sequence:1,status:"succeeded",progress:100,observedAt:x.clock(),observation:{action:"drain",providerId:"provider-1",canonicalModelName:MODEL,outcome:"succeeded",runtimeState:"loaded",activeRequests:0,observedAt:x.clock()},errorCode:null}));assert.equal((await pending).ok,true);assert.equal(x.admissions.snapshot("model-1").uncertain,undefined);assert.equal(lifecycle.execute(execution("unload",102)).ok,true);await remote.shutdown();
 }finally{x.close();}
});
