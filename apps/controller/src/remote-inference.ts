import { randomBytes } from "node:crypto";
import { evaluateOperationPolicy, parseHostResourceObservation, parseStreamCommand, policyHash, streamAuthorizationDigest, type AuthorizationIntent, type StreamCommandRequest } from "@lan-model-manager/core";
import type { ControllerRepositories } from "./repositories.js";
import type { InferenceTokenManager } from "./inference-manager.js";
import type { JobStores } from "./jobs-store.js";
import type { PolicyService } from "./policy-service.js";
import type { AdmissionController, AdmissionLease } from "./admission-accounting.js";
import type { ChatAuthenticatedContext, ChatUpstreamRequest } from "./inference-chat.js";
import { AgentStreamRelay, type StreamRelayHandle, type StreamRelayOutcome, type AgentStreamAdapter } from "./agent-stream-relay.js";

export interface InferenceSelection {readonly modelId:string;readonly providerId:string;readonly hostId:string;readonly model:string;readonly policyVersion:number;readonly policyHash:string;readonly certificate:string;readonly observation:string}
const fail=():never=>{throw new Error("ERR_REMOTE_INFERENCE");};
const object=(v:unknown):Record<string,unknown>|null=>typeof v==="object"&&v!==null&&!Array.isArray(v)?v as Record<string,unknown>:null;
type Execution={handle:StreamRelayHandle;lease:AdmissionLease;modelId:string;finish:(outcome:StreamRelayOutcome)=>void;done:Promise<void>;valid:()=>boolean;stopWatch:()=>void};
/** Runtime-owned, component-only stream authority. Not an HTTP adapter. No ordinary
 * command store, replay, endpoint input, auto-load or substitution is permitted.
 * Selection carries no execution authority: dispatch revalidates all facts.
 */
export class RemoteInferenceService {
 private accepting=true;
 private readonly httpOwners=new Set<()=>Promise<void>>();
 ownHttp(close:()=>Promise<void>):void{if(!this.accepting)throw new Error("ERR_REMOTE_INFERENCE");this.httpOwners.add(close);}
 private readonly live=new Map<string,Execution>();
 private selections=new WeakSet<InferenceSelection>();
 private relay:AgentStreamRelay;
 constructor(private readonly repositories:ControllerRepositories,private readonly tokens:InferenceTokenManager,private readonly policy:PolicyService,private readonly admissions:AdmissionController,private readonly jobs:JobStores,private readonly clock:()=>string=()=>new Date().toISOString()){
  this.relay=new AgentStreamRelay(()=>Date.parse(clock()));
  // No prompt-bearing work is restored; admission registration is deliberately absent.
  // Legacy ordinary chat commands are never replayed. Scrub payload/result bytes
  // as well as closing queued/leased authority before any listener can poll.
  const legacy=repositories.db.prepare("SELECT job_id FROM agent_commands WHERE json_extract(request_json,'$.operation')='inference.chat'").all() as {job_id:string}[];
  for(const row of legacy)this.jobs.withAuditTransaction(tx=>{
   const job=tx.jobs.get(row.job_id);
   if(job&&!["succeeded","failed","timed-out","cancelled"].includes(job.state)){
    const at=new Date(Math.max(Date.parse(clock()),Date.parse(job.updatedAt)+1)).toISOString();
    tx.jobs.transition(row.job_id,"cancelled",at,{progressPercent:null,terminalCode:"INTERRUPTED",terminalMessage:"interrupted"});
    tx.audit.append({actorKind:"controller",actorId:"controller",action:"inference-interrupted",outcome:"cancelled",requestId:job.payload.operation.requestId,jobId:job.jobId,hostId:job.hostId,details:null,occurredAt:at});
   }
   repositories.db.prepare("UPDATE agent_commands SET request_json='{}',request_digest=?,result_json=NULL,state='expired',lease_until=NULL,updated_at=? WHERE job_id=?").run("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",clock(),row.job_id);
  });
  repositories.db.prepare("UPDATE inference_executions SET outcome='interrupted',finished_at=? WHERE outcome='running'").run(clock());
 }
 start():void{if(this.accepting)return;this.relay=new AgentStreamRelay(()=>Date.parse(this.clock()));this.selections=new WeakSet();this.accepting=true;}
 /** Generation-fenced narrow view: stale HTTP owners cannot lease replacement work. */
 get streams():AgentStreamAdapter{
  const relay=this.relay;
  const current=()=>{if(relay!==this.relay||!this.accepting)throw new Error("ERR_REMOTE_INFERENCE");this.revalidateLive();};
  return {
   busy:host=>{if(relay!==this.relay||!this.accepting)return false;current();return relay.busy(host);},
   poll:(host,lease)=>{if(relay!==this.relay||!this.accepting)return {streamCommand:null,cancelledJobIds:[]};current();return relay.poll(host,lease);},
   publish:(host,raw,signal,authorized)=>{current();return relay.publish(host,raw,signal,()=>{try{current();return this.accepting&&relay===this.relay&&(authorized?.()??true);}catch{return false;}});},
   complete:(host,input)=>{current();return relay.complete(host,input);},
  };
 }
 private revalidateLive():void{for(const e of [...this.live.values()])if(e.handle.settledOutcome===null&&!e.valid()){e.handle.cancel();e.finish("interrupted");}}
 get activeCount():number{return this.live.size;}
 private facts(context:ChatAuthenticatedContext,modelId:string,requestId:string,existing=false){
  if(!this.accepting||!this.tokens.revalidateMetadata(context.token))return fail();
  const now=Date.parse(this.clock()),fresh=(at:string)=>{const age=now-Date.parse(at);return Number.isFinite(age)&&age>=0&&age<60_000;};
  const model=this.repositories.models.get(modelId),host=model&&this.repositories.hosts.get(model.hostId),provider=model&&this.repositories.providers.get(model.providerId),snapshot=object(model?.snapshot);
  if(!model||!host||!provider||provider.hostId!==host.hostId||model.hostId!==host.hostId||provider.kind!=="ollama"||provider.health!=="ready"||!host.online||host.freshness!=="fresh"||model.state!=="running"||!snapshot||!(existing?["serving","loaded-idle","draining"]:["serving","loaded-idle"]).includes(String(snapshot.runtimeState))||!Number.isSafeInteger(snapshot.activeRequests)||Number(snapshot.activeRequests)<0||(snapshot.runtimeState==="loaded-idle"&&snapshot.activeRequests!==0)||snapshot.managedTemporary!==false||snapshot.artifactState!=="installed"||snapshot.modelId!==model.modelId||snapshot.providerId!==model.providerId||snapshot.displayName!==model.canonicalName||snapshot.observedAt!==model.observedAt)return fail();
  const resource=parseHostResourceObservation(object(host.snapshot)?.resource);
  const binding=this.repositories.db.prepare("SELECT l.certificate_fingerprint,l.last_observed_at,l.health,l.revoked_at,c.status,c.revoked_at cert_revoked,c.not_before,c.not_after FROM fleet_liveness l JOIN host_certificates c ON c.fingerprint=l.certificate_fingerprint AND c.candidate_id=l.host_id WHERE l.host_id=?").get(host.hostId) as {certificate_fingerprint:string;last_observed_at:string;health:string;revoked_at:string|null;status:string;cert_revoked:string|null;not_before:string;not_after:string}|undefined;
  if(!resource.ok||resource.value.hostId!==host.hostId||resource.value.platform!==host.platform||![host.observedAt,provider.observedAt,model.observedAt,resource.value.observedAt].every(fresh)||!binding||binding.health!=="active"||binding.revoked_at!==null||binding.status!=="active"||binding.cert_revoked!==null||!fresh(binding.last_observed_at)||!(Date.parse(binding.not_before)<=now&&Date.parse(binding.not_after)>now))return fail();
  const admission=this.admissions.snapshot(model.modelId); // unknown is CLOSED
  if((admission.draining&&!existing)||admission.uncertain)return fail();
  const counts=this.repositories.db.prepare("SELECT (SELECT COUNT(*) FROM jobs WHERE state NOT IN ('succeeded','failed','timed-out','cancelled'))+(SELECT COUNT(*) FROM inference_executions WHERE outcome='running' AND request_id<>?) active,(SELECT COUNT(*) FROM jobs WHERE submitted_at>?)+(SELECT COUNT(*) FROM inference_executions WHERE started_at>? AND request_id<>?) recent").get(requestId,new Date(now-60_000).toISOString(),new Date(now-60_000).toISOString(),requestId) as {active:number;recent:number};
  const intent:AuthorizationIntent={requestId,actorKind:"owner",actorId:context.token.ownerId,operation:"model-inference",targetKind:"model",targetId:model.modelId,hostId:host.hostId,modelId:model.modelId,observationFresh:true,hostRevoked:false,modelCompatible:true,publicExposure:false,availableMemoryBytes:resource.value.memory.availableBytes,availableVramBytes:resource.value.accelerators.reduce((max,gpu)=>Math.max(max,gpu.memory.availableBytes),0),availableStorageBytes:resource.value.storage.availableBytes,activeOperations:counts.active,operationsLastMinute:counts.recent};
  return {model,provider,host,binding,intent};
 }
 select(context:ChatAuthenticatedContext,requestedModel:string):InferenceSelection {
  const candidates=this.repositories.hosts.list().flatMap(host=>this.repositories.models.listByHost(host.hostId)).filter(model=>model.canonicalName===requestedModel);
  for(const candidate of candidates){try{
   const f=this.facts(context,candidate.modelId,"selection"),p=this.policy.current(),d=evaluateOperationPolicy(p,f.intent);
   if(!d.allowed||d.requiresApproval)continue;
   const selection=Object.freeze({modelId:f.model.modelId,providerId:f.provider.providerId,hostId:f.host.hostId,model:f.model.canonicalName,policyVersion:p.version,policyHash:policyHash(p),certificate:f.binding.certificate_fingerprint,observation:f.model.observedAt});this.selections.add(selection);return selection;
  }catch{/* fail closed, exact candidates only */}}
  return fail();
 }
 /** Fail-fast capacity, no queue in this slice. All checks and relay.open are
  * synchronous; future queue composition must call this AFTER every wait. */
 open(context:ChatAuthenticatedContext,selected:InferenceSelection,input:Pick<ChatUpstreamRequest,"model"|"messages"|"temperature"|"maxTokens">,signal:AbortSignal):StreamRelayHandle {
  try{return this.openOwned(context,selected,input,signal);}catch{return fail();}
 }
 private openOwned(context:ChatAuthenticatedContext,selected:InferenceSelection,input:Pick<ChatUpstreamRequest,"model"|"messages"|"temperature"|"maxTokens">,signal:AbortSignal):StreamRelayHandle {
  if(!this.accepting||signal.aborted||!this.selections.has(selected)||this.live.size>=16||[...this.live.values()].some(e=>e.modelId===selected.modelId)||input.model!==selected.model)return fail();
  const id=randomBytes(16).toString("hex"),requestId=randomBytes(32).toString("hex"),jobId=`inference-job-${id}`;
  const f=this.facts(context,selected.modelId,requestId),p=this.policy.current();
  if(p.version!==selected.policyVersion||policyHash(p)!==selected.policyHash||f.host.hostId!==selected.hostId||f.provider.providerId!==selected.providerId||f.model.canonicalName!==selected.model||f.binding.certificate_fingerprint!==selected.certificate||f.model.observedAt!==selected.observation)return fail();
  const decision=this.policy.authorize(f.intent);
  if(!decision.ok||!decision.value.allowed||decision.value.requiresApproval)return fail();
  const deadline=new Date(Date.parse(this.clock())+120_000).toISOString();
  // Execution capability is created only after authoritative policy acceptance.
  const command:StreamCommandRequest={requestId,jobId,hostId:selected.hostId,operation:"inference.chat.stream",idempotencyKey:`inference-idem-${id}`,sequence:1,deadline,capability:{operation:"model-inference",targetKind:"model",targetId:selected.modelId,hostId:selected.hostId,modelId:selected.modelId,requestDigest:"0".repeat(64),expiresAt:deadline},params:{schemaVersion:1,upstreamFrameBytes:65536,maxEventBytes:131072,maxTotalEventBytes:1048576,maxEvents:4096,chat:{providerId:selected.providerId,modelId:selected.modelId,model:selected.model,requestId,maxRequestBytes:524288,maxResponseBytes:262144,messages:input.messages.map(m=>({role:m.role,contentBase64:Buffer.from(m.content,"utf8").toString("base64")})),temperatureMilli:input.temperature===undefined?null:Math.round(input.temperature*1000),maxTokens:input.maxTokens??null}}};
  (command.capability as {requestDigest:string}).requestDigest=streamAuthorizationDigest(command);
  const raw=Buffer.from(JSON.stringify(command));parseStreamCommand(raw);
  // Recheck even synchronous command construction: injected dependencies and
  // caller-owned values are not an authorization boundary.
  const dispatchFacts=this.facts(context,selected.modelId,requestId),dispatchPolicy=this.policy.current();
  if(signal.aborted||dispatchPolicy.version!==p.version||policyHash(dispatchPolicy)!==policyHash(p)||dispatchFacts.host.hostId!==selected.hostId||dispatchFacts.provider.providerId!==selected.providerId||dispatchFacts.model.canonicalName!==selected.model||dispatchFacts.model.observedAt!==selected.observation||dispatchFacts.binding.certificate_fingerprint!==selected.certificate||!evaluateOperationPolicy(dispatchPolicy,dispatchFacts.intent).allowed)return fail();
  const lease=this.admissions.acquire(selected.modelId);
  let handle:StreamRelayHandle;
  try{
   this.repositories.db.prepare("INSERT INTO inference_executions(request_id,job_id,token_id,owner_id,host_id,provider_id,model_id,command_digest,policy_version,policy_hash,deadline,started_at,finished_at,outcome) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL,'running')").run(requestId,jobId,context.token.tokenId,context.token.ownerId,selected.hostId,selected.providerId,selected.modelId,command.capability.requestDigest,p.version,policyHash(p),deadline,this.clock());
   handle=this.relay.open(raw);
  }catch{lease.release();this.repositories.db.prepare("UPDATE inference_executions SET outcome='failed',finished_at=? WHERE request_id=? AND outcome='running'").run(this.clock(),requestId);return fail();}
  let finished=false;
  const cancel=()=>{const outcome=handle.settledOutcome;handle.cancel();finish(outcome??"cancelled");};
  const finish=(outcome:StreamRelayOutcome)=>{
   if(finished)return;finished=true;
   signal.removeEventListener("abort",cancel);
   this.live.get(jobId)?.stopWatch();
   // Local cancellation is NOT proof the remote provider stopped. Keep target
   // draining until independently trusted lifecycle/reconciliation restores it.
   if(outcome!=="succeeded")try{this.admissions.markUncertain(selected.modelId);void this.admissions.stopAdmission(selected.modelId);}catch{/* unknown remains closed */}
   try{this.repositories.db.prepare("UPDATE inference_executions SET outcome=?,finished_at=? WHERE request_id=? AND outcome='running'").run(outcome,this.clock(),requestId);}
   catch{this.accepting=false;try{this.admissions.markUncertain(selected.modelId);void this.admissions.stopAdmission(selected.modelId);}catch{/* closed */}}
   finally{lease.release();handle.close();this.live.delete(jobId);}
  };
  const valid=()=>{try{const current=this.facts(context,selected.modelId,requestId,true),policy=this.policy.current(),decision=evaluateOperationPolicy(policy,current.intent);return current.binding.certificate_fingerprint===selected.certificate&&current.model.canonicalName===selected.model&&current.provider.providerId===selected.providerId&&policy.version===selected.policyVersion&&policyHash(policy)===selected.policyHash&&decision.allowed&&!decision.requiresApproval;}catch{return false;}};
  const watch=setInterval(()=>this.revalidateLive(),250);watch.unref();
  const done=handle.outcome.then(outcome=>{clearInterval(watch);finish(outcome);});
  this.live.set(jobId,{handle,lease,modelId:selected.modelId,finish,done,valid,stopWatch:()=>clearInterval(watch)});
  signal.addEventListener("abort",cancel,{once:true});lease.onCancel(cancel);
  if(signal.aborted)cancel();
  return {get settledOutcome(){return handle.settledOutcome;},next:s=>{this.revalidateLive();return handle.settledOutcome===null?handle.next(s):Promise.resolve(null);},outcome:handle.outcome,cancel,close:cancel};
 }
 /** Reject, abort, settle ledger and await every owned continuation before DB close. */
 async shutdown():Promise<void>{const pending=[...this.live.values()].map(e=>e.done),http=[...this.httpOwners].map(close=>close());this.httpOwners.clear();this.close();await Promise.allSettled([...pending,...http]);}
 /** Synchronous close fallback also makes later promise continuations DB-free. */
 close():void{this.accepting=false;for(const close of this.httpOwners)void close();this.httpOwners.clear();for(const e of [...this.live.values()]){const outcome=e.handle.settledOutcome;e.handle.cancel();e.finish(outcome??"interrupted");}this.relay.stop();}
}
