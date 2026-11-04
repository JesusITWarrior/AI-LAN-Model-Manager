import React, { useEffect, useRef, useState } from "react";
import type { ApiClient, LifecycleOperation, LifecycleProposal } from "./api.js";
import { jobHash } from "./operations-view.js";

export function lifecycleActions(p:LifecycleProposal):{approve:boolean;execute:boolean;cancel:boolean;prepare:boolean} {
  const blocked=p.reasons.some(r=>r!=="approval-required"&&r!=="allowed-read");
  return {approve:p.state==="approval-required"&&!blocked,execute:!blocked&&(p.state==="prepared"&&!p.requiresApproval||p.state==="approved"),cancel:["prepared","approval-required","approved","submitting"].includes(p.state),prepare:["terminal","cancelled","expired","stale"].includes(p.state)};
}
export type LifecycleReviewAction="approve"|"submit"|"cancel"|"status"|LifecycleOperation;
export function performLifecycleAction(api:ApiClient,modelId:string,proposal:LifecycleProposal|null,action:LifecycleReviewAction):Promise<LifecycleProposal> {
  if(action==="load"||action==="drain"||action==="unload")return api.prepareLifecycle(action,modelId);
  if(!proposal)return Promise.reject(new Error("Prepare a proposal before taking this action."));
  return api.proposalAction(action,proposal.proposalId);
}
/** Approval never submits. Only the separate Execute click starts this exact
 * reviewed proposal; reconnect keeps only an opaque ID, never authority. */
export function LifecycleReview({api,modelId}:{api:ApiClient;modelId:string}) {
  return <ModelLifecycleReview key={modelId} api={api} modelId={modelId}/>;
}
function ModelLifecycleReview({api,modelId}:{api:ApiClient;modelId:string}) {
  const [proposal,setProposal]=useState<LifecycleProposal|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState("");
  const [savedId,setSavedId]=useState<string|null>(null);
  // Invalidate outstanding status reads on forget/action, even if a transport
  // ignores AbortSignal. A synchronous lock also prevents double-click submits.
  const generation=useRef(0),locked=useRef(false);
  const key=`lanmm-lifecycle-review:${modelId}`;
  const remember=(p:LifecycleProposal)=>{if(p.target.modelId!==modelId)throw new Error("The controller returned a different model target.");setProposal(p);setSavedId(p.proposalId);try{sessionStorage.setItem(key,p.proposalId);}catch{/* review still works without storage */}};
  useEffect(()=>{const controller=new AbortController(),version=++generation.current;let id:string|null=null;try{id=sessionStorage.getItem(key);}catch{}setSavedId(id);if(id){locked.current=true;setBusy(true);void api.proposalAction("status",id,controller.signal).then(p=>{if(!controller.signal.aborted&&version===generation.current)remember(p);},e=>{if(!controller.signal.aborted&&version===generation.current)setError(e instanceof Error?e.message:"Saved review is no longer available. Forget it locally to prepare a new proposal.");}).finally(()=>{if(!controller.signal.aborted&&version===generation.current){locked.current=false;setBusy(false);}});}return()=>{controller.abort();generation.current++;};},[api,key]);
  useEffect(()=>{if(busy||proposal?.state!=="submitting")return;const controller=new AbortController(),version=generation.current,timer=setTimeout(()=>{void api.proposalAction("status",proposal.proposalId,controller.signal).then(p=>{if(!controller.signal.aborted&&version===generation.current)remember(p);},e=>{if(!controller.signal.aborted&&version===generation.current)setError(e instanceof Error?e.message:"Status unavailable. Use Refresh status.");});},1000);return()=>{clearTimeout(timer);controller.abort();};},[api,proposal,busy]);
  const run=async(action:LifecycleReviewAction)=>{if(locked.current)return;locked.current=true;const version=++generation.current;setBusy(true);setError("");try{const next=await performLifecycleAction(api,modelId,proposal,action);if(version===generation.current)remember(next);}catch(e){if(version===generation.current)setError(e instanceof Error?e.message:"Lifecycle request failed. Refresh status before retrying execution.");}finally{if(version===generation.current){locked.current=false;setBusy(false);}}};
  const forget=()=>{if(locked.current||proposal?.state==="submitting")return;generation.current++;setProposal(null);setSavedId(null);setError("");try{sessionStorage.removeItem(key);}catch{}};
  const actions=proposal?lifecycleActions(proposal):null;
  return <section className="lifecycleReview" aria-labelledby="lifecycle-title">
    <h3 id="lifecycle-title">Model lifecycle</h3>
    <p>Inventory alone does not establish serving readiness or remote idle. Policy, trust, resources and active work are checked by the controller.</p>
    {((!proposal&&!savedId)||actions?.prepare)&&<div className="controls">
      {(["load","drain","unload"] as const).map(operation=><button type="button" disabled={busy} key={operation} onClick={()=>void run(operation)}>Prepare {operation}</button>)}
    </div>}
    {proposal&&<div className="notice lifecycleNotice" aria-live="polite">
      <h4>Review {proposal.operation}</h4>
      {/* Host/provider IDs distinguish otherwise identical model names. Keep the
          exact target readable; bookkeeping IDs are not review instructions. */}
      <dl className="lifecycleTarget" aria-label="Reviewed target">
        <div><dt>Model</dt><dd>{proposal.target.canonicalName}</dd></div>
        <div><dt>Host</dt><dd>{proposal.target.hostId}</dd></div>
        <div><dt>Provider</dt><dd>{proposal.target.providerId}</dd></div>
      </dl>
      <details><summary>Technical target details</summary><p>Model record ID: {proposal.target.modelId}</p></details>
      <p>{proposal.consequence}</p>
      <p>Review expires: <time>{proposal.expiresAt}</time></p>
      <p>State: {proposal.state}{proposal.jobState?` · Job: ${proposal.jobState}`:proposal.state==="terminal"?" · Execution rejected before a durable job was created":" · No durable job yet"}</p>
      {proposal.reasons.length>0&&<ul>{proposal.reasons.map(reason=><li key={reason}>{reason.replaceAll("-"," ")}</li>)}</ul>}
      {["stale","expired"].includes(proposal.state)&&<p>This review cannot execute. Prepare a new proposal and review it again.</p>}
      <div className="controls">
        {actions?.approve&&<button type="button" disabled={busy} onClick={()=>void run("approve")}>Approve reviewed proposal</button>}
        {actions?.execute&&<button type="button" disabled={busy} onClick={()=>void run("submit")}>Execute reviewed {proposal.operation}</button>}
        {actions?.cancel&&<button type="button" disabled={busy} onClick={()=>void run("cancel")}>{proposal.state==="submitting"?"Request cancellation":"Cancel review"}</button>}
        <button type="button" disabled={busy} onClick={()=>void run("status")}>Refresh status</button>
        {proposal.jobId&&<a href={jobHash(proposal.jobId)}>Follow durable job</a>}
      </div>
      <p>Cancellation reduces local authority; it is not proof that the remote provider stopped. Drain never implicitly unloads.</p>
    </div>}
    {(proposal||savedId)&&<div className="notice lifecycleNotice">
      <p>Forget only removes this local review from this browser session. It does not cancel controller authority or any execution, and does not prepare or execute anything. If execution may have started, retain the durable job link or track it in Operations before forgetting.</p>
      {proposal?.state==="submitting"&&<p>Execution is active. Keep this review for status and the durable job link; forgetting is disabled until a terminal status is known.</p>}
      <button type="button" disabled={busy||proposal?.state==="submitting"} onClick={forget}>Forget local review</button>
    </div>}
    {error&&<p role="alert" className="notice warning lifecycleNotice">{error}</p>}
  </section>;
}
