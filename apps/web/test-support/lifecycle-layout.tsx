import React from "react";
import { createRoot } from "react-dom/client";
import { flushSync } from "react-dom";
import { LifecycleReview } from "../src/lifecycle-review.js";
import type { ApiClient, LifecycleProposal } from "../src/api.js";

const check=(value:unknown,message:string)=>{if(!value)throw new Error(message);};
const tick=()=>new Promise(resolve=>setTimeout(resolve,10));
async function until(fn:()=>boolean,message:string){for(let i=0;i<300;i++){if(fn())return;await tick();}throw new Error(message);}
const target={modelId:`model-${"m".repeat(120)}`,hostId:`host-${"h".repeat(120)}`,providerId:`provider-${"p".repeat(115)}`,canonicalName:`organization/${"long-model-name".repeat(16)}:latest`};
const base:LifecycleProposal={proposalId:"a".repeat(64),operation:"load",target,consequence:"Load this exact model into the provider. This may allocate host memory and accelerator resources.",expiresAt:"2026-11-04T20:00:00.000Z",requiresApproval:true,reasons:["approval-required"],state:"approval-required",jobId:null,jobState:null};
const button=(name:string)=>Array.from(document.querySelectorAll("button")).find(b=>b.textContent===name);
function geometry(label:string){
 const panel=document.querySelector<HTMLElement>(".modelDetailPanel")!,review=document.querySelector<HTMLElement>(".lifecycleReview")!;
 const bounds=panel.getBoundingClientRect();
 check(document.documentElement.scrollWidth<=innerWidth+1,`${label}: page overflow ${document.documentElement.scrollWidth}/${innerWidth}`);
 check(review.scrollWidth<=review.clientWidth+1,`${label}: review overflow`);
 for(const element of review.querySelectorAll<HTMLElement>("h4,p,dt,dd,li,button,a,summary,.controls")){
  if(!element.getClientRects().length)continue;
  const rect=element.getBoundingClientRect();
  check(rect.width>0&&rect.height>0,`${label}: empty ${element.textContent}`);
  check(rect.left>=bounds.left-1&&rect.right<=bounds.right+1,`${label}: clipped ${element.tagName} ${element.textContent}`);
  check(rect.bottom<=bounds.bottom+1,`${label}: vertically clipped ${element.textContent}`);
  check(element.scrollWidth<=element.clientWidth+1,`${label}: text overflow ${element.textContent}`);
 }
 const notice=review.querySelector<HTMLElement>(".lifecycleNotice")!;
 check(getComputedStyle(notice).display==="grid",`${label}: notice must stack`);
 const heading=notice.querySelector("h4");
 const reasons=notice.querySelector("ul");
 if(heading&&reasons)check(reasons.getBoundingClientRect().top>heading.getBoundingClientRect().bottom,`${label}: reasons not below heading`);
}
async function cases(){
 const root=createRoot(document.getElementById("root")!);let proposal=base;
 const api={prepareLifecycle:async()=>proposal,proposalAction:async()=>proposal} as unknown as ApiClient;
 let count=0;
 for(const state of ["blocked","approval-required","approved","submitting","stale","expired","terminal","cancelled"] as const){
  sessionStorage.clear();
  proposal={...base,state:state==="blocked"?"prepared":state,reasons:state==="blocked"?["operation-disabled","stale-host","insufficient-resources","active-requests"]:["approval-required"],...(state==="submitting"?{jobId:"internal-job-record",jobState:"accepted" as const}:{})};
  flushSync(()=>root.render(<div className="shell"><aside className="rail">Fixture navigation</aside><main><div className="modelStage"><section className="panel modelListPanel">Inventory fixture</section><aside className="panel modelDetailPanel"><div className="modelDetail"><LifecycleReview key={state} api={api} modelId={target.modelId}/></div></aside></div></main></div>));
  await until(()=>!!button("Prepare load"),`${state}: prepare available`);button("Prepare load")!.click();
  await until(()=>!!document.querySelector("h4")&&!button("Refresh status")?.disabled,`${state}: prepared rendered`);
  geometry(`${innerWidth}/${state}`);
  const text=document.querySelector(".lifecycleReview")!.textContent!;
  for(const value of [target.canonicalName,target.hostId,target.providerId,`State: ${proposal.state}`,proposal.consequence,"Cancellation reduces local authority","Drain never implicitly unloads"] )check(text.includes(value),`${state}: missing ${value}`);
  check(!text.includes(base.proposalId)&&!text.includes("internal-job-record"),`${state}: raw bookkeeping identifiers`);
  check(!!button("Approve reviewed proposal")===(state==="approval-required"),`${state}: approval control`);
  check(!!button("Execute reviewed load")===(state==="approved"),`${state}: execute control`);
  if(state==="blocked")for(const reason of proposal.reasons)check(text.includes(reason.replaceAll("-"," ")),`missing safety reason ${reason}`);
  if(state==="submitting"){check(button("Forget local review")!.disabled,"forget disabled during execution");check(document.querySelector("a")?.getAttribute("href")==="#/operations/job/internal-job-record","durable job link retained");}
  const details=document.querySelector<HTMLDetailsElement>(".lifecycleReview details")!;
  check(!details.open,"technical target details initially collapsed");details.open=true;geometry(`${innerWidth}/${state}/expanded`);check(details.textContent?.includes(target.modelId),"exact model record accessible");
  count++;
 }
 // An error while recovering a saved review must also wrap in the panel.
 flushSync(()=>root.unmount());sessionStorage.setItem(`lanmm-lifecycle-review:${target.modelId}`,base.proposalId);
 const errorRoot=createRoot(document.querySelector(".modelDetail")??document.getElementById("root")!);
 const errorApi={...api,proposalAction:async()=>{throw new Error(`Status unavailable: ${"long-status-detail".repeat(30)}`);}};
 flushSync(()=>errorRoot.render(<div className="panel modelDetailPanel"><div className="modelDetail"><LifecycleReview api={errorApi} modelId={target.modelId}/></div></div>));
 await until(()=>!!document.querySelector('[role="alert"]'),"recovery error rendered");geometry(`${innerWidth}/error`);
 button("Forget local review")!.click();await until(()=>!!button("Prepare load"),"forget enables explicit prepare");
 flushSync(()=>errorRoot.unmount());return count+1;
}
async function run(){
 if(window.parent!==window){try{const count=await cases();parent.postMessage({ok:true,count,width:innerWidth},location.origin);}catch(error){parent.postMessage({ok:false,error:String(error),width:innerWidth},location.origin);}return;}
 const widths=[320,375,768,1050,1280,1920];let casesCount=0;
 for(const width of widths){
  const frame=document.createElement("iframe");frame.style.cssText=`width:${width}px;height:1000px;border:0`;frame.src="/case";
  const result=new Promise<any>(resolve=>{const listener=(event:MessageEvent)=>{if(event.source===frame.contentWindow){removeEventListener("message",listener);resolve(event.data);}};addEventListener("message",listener);});document.body.append(frame);
  const report=await result;check(report.ok,JSON.stringify(report));check(report.width===width,"actual frame viewport");casesCount+=report.count;frame.remove();
 }
 await fetch("/test/result",{method:"POST",body:JSON.stringify({ok:true,widths,cases:casesCount})});
}
run().catch(error=>fetch("/test/result",{method:"POST",body:JSON.stringify({ok:false,error:String(error),stack:error.stack})}));
