import { randomBytes } from "node:crypto";
import { commandAuthorizationDigest, commandPolicyOperation, evaluateOperationPolicy, parseCommandRequest, type CommandRequest, type AuthorizationIntent, type PolicyDecision, type OperationPolicy } from "@lan-model-manager/core";
import type { ControllerRuntimeHandle } from "./controller-runtime.js";
import type { GuardResult } from "./guard.js";
import type { ManagementLifecycleService } from "./management-lifecycle.js";
import type { ExactSessionBinding } from "./policy-service.js";

export type ProposalOperation = "load" | "drain" | "unload";
export type ProposalState = "prepared" | "approval-required" | "approved" | "submitting" | "terminal" | "cancelled" | "stale" | "expired";
export interface LifecycleProposalDto {
  readonly proposalId:string; readonly operation:ProposalOperation;
  readonly target:Readonly<{modelId:string;hostId:string;providerId:string;canonicalName:string}>;
  readonly consequence:string; readonly expiresAt:string; readonly requiresApproval:boolean;
  readonly reasons:readonly string[]; readonly state:ProposalState; readonly jobId:string|null; readonly jobState:string|null;
}
type Result = {ok:true;value:LifecycleProposalDto}|{ok:false;error:"ERR_LIFECYCLE_INPUT"|"ERR_LIFECYCLE_STATE"|"ERR_LIFECYCLE_DENIED"};
interface Proposal {
  readonly id:string; readonly request:CommandRequest; readonly intent:AuthorizationIntent; readonly semantic:string;
  readonly decision:PolicyDecision; readonly policy:OperationPolicy; readonly binding:ExactSessionBinding; readonly target:LifecycleProposalDto["target"];
  state:ProposalState; approvalId:string|null; submitted:boolean; pending:Promise<void>|null;
}
const consequences:Record<ProposalOperation,string>={load:"Load this exact model into the provider. This may allocate host memory and accelerator resources.",drain:"Stop new local admissions and request an explicit remote idle observation. This does not unload the model.",unload:"Unload this exact model only after authoritative idle and draining checks. This does not remove its artifact."};
const fail=(error: "ERR_LIFECYCLE_INPUT"|"ERR_LIFECYCLE_STATE"|"ERR_LIFECYCLE_DENIED"):Result=>({ok:false,error});
// Reviewed identity excludes only ambient resource samples and the rolling rate
// count. Active work, actor/target, trust/freshness/compatibility and exposure
// remain exact bindings. Resource/rate safety is independently evaluated fresh.
function reviewedIdentity(intent:AuthorizationIntent):string {
  const {availableMemoryBytes,availableVramBytes,availableStorageBytes,operationsLastMinute,...identity}=intent;
  return JSON.stringify(identity);
}
const admissible=(decision:PolicyDecision):boolean=>decision.allowed||decision.requiresApproval&&decision.reasons.every(r=>r==="approval-required");
function strict(input:unknown,keys:readonly string[]):Record<string,unknown>|null {
  try {if(typeof input!=="object"||input===null||Array.isArray(input))return null;const p=Object.getPrototypeOf(input),own=Reflect.ownKeys(input),d=Object.getOwnPropertyDescriptors(input);if(p!==Object.prototype&&p!==null||own.length!==keys.length||own.some(k=>typeof k!=="string"||!keys.includes(k)||!d[k]||!("value" in d[k]!)))return null;return Object.fromEntries(keys.map(k=>[k,d[k]!.value]));}catch{return null;}
}
/** An ephemeral review owns immutable server commands, not browser assertions.
 * Only the existing runtime lifecycle owner runs/waits for remote work. No pump,
 * timer, recovered authority, public grant, or browser capability is introduced. */
export class OwnerLifecycleProposals {
  private readonly proposals=new Map<string,Proposal>();
  private closed=false;
  private readonly owner;
  constructor(private readonly runtime:ControllerRuntimeHandle,private readonly lifecycle:ManagementLifecycleService,private readonly clock:()=>string=()=>new Date().toISOString()) {
    this.owner=runtime.services.lifecycle;
    const unsubscribe=this.owner.onShutdown(()=>{this.closed=true;try{for(const p of this.proposals.values())if(!p.submitted)this.revoke(p,"cancelled");}finally{this.proposals.clear();unsubscribe();}});
  }
  private context(guard:GuardResult):ExactSessionBinding|null {return guard.ok&&!this.closed&&!this.runtime.isClosed?this.runtime.services.sessions.binding(guard.session):null;}
  private revoke(p:Proposal,state:ProposalState):void {this.runtime.services.policy.revokeProposal(p.request.requestId);p.approvalId=null;p.state=state;}
  private expire(p:Proposal):void {if(!p.submitted&&["prepared","approval-required","approved"].includes(p.state)&&Date.parse(this.clock())>=Date.parse(p.request.deadline))this.revoke(p,"expired");}
  private dto(p:Proposal):Result {
    this.expire(p);
    const job=p.submitted?this.runtime.jobStores.jobs.get(p.request.jobId):null;
    return {ok:true,value:Object.freeze({proposalId:p.id,operation:p.request.operation as ProposalOperation,target:p.target,consequence:consequences[p.request.operation as ProposalOperation]+(p.request.operation==="load"&&(p.request.params as Record<string,unknown>).keepAlive==="5m"?" Request 5 minutes of provider keep-alive after load. This is a retention request, not a guarantee of unloading at expiry.":""),expiresAt:p.request.deadline,requiresApproval:p.decision.requiresApproval,reasons:Object.freeze([...p.decision.reasons]),state:p.state,jobId:p.submitted&&job?p.request.jobId:null,jobState:job?.state??null})};
  }
  private lookup(input:unknown,guard:GuardResult,cancelSubmitted=false):Proposal|Result {
    const body=strict(input,["proposalId"]);if(!body||typeof body.proposalId!=="string"||! /^[a-f0-9]{64}$/.test(body.proposalId))return fail("ERR_LIFECYCLE_INPUT");
    const binding=this.context(guard);if(!binding)return fail("ERR_LIFECYCLE_DENIED");
    const p=this.proposals.get(body.proposalId);
    if(!p) {
      // Restart/reconnect recovers only a redacted durable job view, never a
      // command, approval, or authority to dispatch. The same session is needed.
      const row=this.runtime.repositories.db.prepare("SELECT * FROM lifecycle_proposal_jobs WHERE proposal_id=? AND session_binding=? AND credential_version=?").get(body.proposalId,binding.id,binding.credentialVersion) as {job_id:string;review_json:string}|undefined;
      if(!row)return fail("ERR_LIFECYCLE_STATE");
      let job=this.runtime.jobStores.jobs.get(row.job_id);
      if(!job)return {ok:true,value:Object.freeze({...JSON.parse(row.review_json) as LifecycleProposalDto,state:"terminal",jobId:null,jobState:null})};
      if(cancelSubmitted&&! ["succeeded","failed","timed-out","cancelled"].includes(job.state)){this.owner.cancel(row.job_id);job=this.runtime.jobStores.jobs.get(row.job_id)!;}
      const review=JSON.parse(row.review_json) as LifecycleProposalDto;
      return {ok:true,value:Object.freeze({...review,state:["succeeded","failed","timed-out","cancelled"].includes(job.state)?"terminal":"submitting",jobId:job.jobId,jobState:job.state})};
    }
    if(p.binding.id!==binding.id||p.binding.credentialVersion!==binding.credentialVersion)return fail("ERR_LIFECYCLE_STATE");
    this.expire(p);return p;
  }
  prepare(input:unknown,guard:GuardResult):Result {
    const body=strict(input,["operation","modelId"]);if(!body||!["load","drain","unload"].includes(body.operation as string)||typeof body.operation!=="string"||typeof body.modelId!=="string"||! /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(body.modelId))return fail("ERR_LIFECYCLE_INPUT");
    const binding=this.context(guard);if(!binding)return fail("ERR_LIFECYCLE_DENIED");
    if(!this.owner.acceptsSubmissions)return fail("ERR_LIFECYCLE_STATE");
    for(const [id,p] of this.proposals){this.expire(p);if(!p.pending&&Date.parse(this.clock())>=Date.parse(p.request.deadline))this.proposals.delete(id);}
    if(this.proposals.size>=256)return fail("ERR_LIFECYCLE_STATE");
    const model=this.runtime.repositories.models.get(body.modelId);if(!model)return fail("ERR_LIFECYCLE_STATE");
    const id=()=>randomBytes(32).toString("hex"),expiresAt=new Date(Math.min(Date.parse(this.clock())+300_000,Date.parse(binding.expiresAt))).toISOString();
    const provider=this.runtime.repositories.providers.get(model.providerId);if(!provider)return fail("ERR_LIFECYCLE_STATE");
    const request:CommandRequest={requestId:id(),jobId:id(),hostId:model.hostId,operation:body.operation as ProposalOperation,idempotencyKey:id(),sequence:1,deadline:expiresAt,params:Object.freeze({providerId:model.providerId,model:model.canonicalName,...(body.operation==="load"?{keepAlive:provider.kind==="lmstudio"?0:"5m"}:{})}),capability:{operation:commandPolicyOperation(body.operation as ProposalOperation),targetKind:"model",targetId:model.modelId,hostId:model.hostId,modelId:model.modelId,requestDigest:"0".repeat(64),expiresAt}};
    (request as {capability:CommandRequest["capability"]}).capability=Object.freeze({...request.capability,requestDigest:commandAuthorizationDigest(request)});
    const parsed=parseCommandRequest(Object.freeze(request));if(!parsed.ok)return fail("ERR_LIFECYCLE_STATE");
    const facts=this.lifecycle.facts(parsed.value,guard);if(!facts)return fail("ERR_LIFECYCLE_STATE");
    const decision=this.runtime.services.policy.authorize(facts.intent);if(!decision.ok)return fail("ERR_LIFECYCLE_DENIED");
    // Denied proposals remain reviewable, but can never be approved or submitted.
    const p:Proposal={id:id(),request:parsed.value,intent:Object.freeze(facts.intent),semantic:facts.semantic,decision:decision.value,policy:this.runtime.services.policy.current(),binding:Object.freeze({...binding,expiresAt}),target:Object.freeze(facts.target),state:decision.value.requiresApproval?"approval-required":"prepared",approvalId:null,submitted:false,pending:null};
    if(!this.runtime.services.policy.bindProposal(p.intent,p.request,p.binding))return fail("ERR_LIFECYCLE_STATE");
    this.proposals.set(p.id,p);return this.dto(p);
  }
  private revalidate(p:Proposal,guard:GuardResult):boolean {
    const facts=this.lifecycle.facts(p.request,guard),binding=this.context(guard);
    if(!binding||binding.id!==p.binding.id||binding.credentialVersion!==p.binding.credentialVersion||!facts||facts.semantic!==p.semantic||JSON.stringify(facts.target)!==JSON.stringify(p.target)||reviewedIdentity(facts.intent)!==reviewedIdentity(p.intent)){this.revoke(p,"stale");return false;}
    // Never rebind a request ID/digest to changed observations. The stored intent
    // is immutable reviewed evidence; its exact approval/command/session bindings
    // are still checked by PolicyService and the synchronous lifecycle executor.
    // Fresh facts must also pass the pinned policy; authorize below independently
    // verifies that this exact policy is still current. Both gates run at approve
    // AND submit; submit reaches execution without an await or event turn.
    const fresh=evaluateOperationPolicy(p.policy,facts.intent);
    const decision=this.runtime.services.policy.authorize(p.intent);
    if(!decision.ok||decision.value.requestDigest!==p.decision.requestDigest||decision.value.policyHash!==p.decision.policyHash||decision.value.policyVersion!==p.decision.policyVersion||fresh.policyHash!==p.decision.policyHash||fresh.policyVersion!==p.decision.policyVersion||!admissible(fresh)||!admissible(decision.value)){this.revoke(p,"stale");return false;}
    return true;
  }
  approve(input:unknown,guard:GuardResult):Result {
    const p=this.lookup(input,guard);if("ok" in p)return p;
    if(p.state==="approved")return this.dto(p);
    if(p.state!=="approval-required"||!this.owner.acceptsSubmissions||!this.revalidate(p,guard))return this.dto(p);
    const grant=this.runtime.services.policy.approveExact(p.intent,p.request,guard,p.binding);if(!grant.ok)return fail("ERR_LIFECYCLE_DENIED");
    p.approvalId=grant.value.approvalId;p.state="approved";return this.dto(p);
  }
  submit(input:unknown,guard:GuardResult):Result {
    const p=this.lookup(input,guard);if("ok" in p)return p;
    // Claim synchronously before invoking any asynchronous executor. Every retry
    // reports this same owned execution and durable job; never consume twice.
    if(p.submitted)return this.dto(p);
    if(!["prepared","approved"].includes(p.state)||!this.owner.acceptsSubmissions)return this.dto(p);
    if(!this.revalidate(p,guard))return this.dto(p);
    if(p.request.operation==="load") {
      const model=this.runtime.repositories.models.get(p.target.modelId),snapshot=model?.snapshot as Record<string,unknown>|undefined;
      if(snapshot?.activeRequests!==0||!["installed","unloaded","failed"].includes(String(snapshot?.runtimeState??model?.state)))return fail("ERR_LIFECYCLE_STATE");
    }
    if(p.decision.requiresApproval&&(!p.approvalId||!this.runtime.services.policy.consumeExact(p.approvalId,p.intent,p.request,p.binding).ok))return fail("ERR_LIFECYCLE_DENIED");
    if(p.request.operation==="load")this.runtime.services.admissions.register(p.target.modelId);
    // Persist only the redacted review before dispatch. A crash in this boundary
    // recovers a closed view, never authority, and reports a job only if it exists.
    const review=this.dto(p);
    if(!review.ok)return review;
    this.runtime.repositories.db.prepare("INSERT INTO lifecycle_proposal_jobs(proposal_id,job_id,session_binding,credential_version,review_json) VALUES(?,?,?,?,?)").run(p.id,p.request.jobId,p.binding.id,p.binding.credentialVersion,JSON.stringify(review.value));
    p.submitted=true;p.state="submitting";
    p.pending=this.owner.execute({request:p.request,intent:p.intent},new AbortController().signal).then(()=>{p.state="terminal";},()=>{p.state="terminal";}).finally(()=>{p.pending=null;});
    return this.dto(p);
  }
  status(input:unknown,guard:GuardResult):Result {const p=this.lookup(input,guard);return "ok" in p?p:this.dto(p);}
  cancel(input:unknown,guard:GuardResult):Result {
    const p=this.lookup(input,guard,true);if("ok" in p)return p;
    if(!p.submitted){if(!["stale","expired","cancelled"].includes(p.state))this.revoke(p,"cancelled");return this.dto(p);}
    const job=this.runtime.jobStores.jobs.get(p.request.jobId);
    if(job&&! ["succeeded","failed","timed-out","cancelled"].includes(job.state))this.owner.cancel(p.request.jobId);
    // A local cancellation is not a remote-stop observation or idle proof.
    return this.dto(p);
  }
}
