import React from "react";
import { createRoot } from "react-dom/client";
import { flushSync } from "react-dom";
import { createApiClient, type ApiClient, type LifecycleProposal } from "../src/api.js";
import { LifecycleReview } from "../src/lifecycle-review.js";
const root=createRoot(document.getElementById("root")!);
const api=createApiClient(fetch,()=>"fixture-csrf");
const check=(condition:unknown,message:string)=>{if(!condition)throw new Error(message);};
const tick=()=>new Promise(resolve=>setTimeout(resolve,10));
async function until(condition:()=>boolean,message:string){for(let i=0;i<500;i++){if(condition())return;await tick();}throw new Error(message);}
const button=(text:string)=>Array.from(document.querySelectorAll("button")).find(b=>b.textContent===text);
const click=(text:string)=>{const b=button(text);check(b&&!b.disabled,`enabled button: ${text}`);b!.focus();b!.click();};
// Storage and fetch completion can precede React's commit. Synchronize on the
// rendered control, never on a side effect that happens before setState commits.
const ready=(label:string)=>until(()=>!!button(label)&&!button(label)!.disabled,`rendered enabled button: ${label}`);
const key=(model:string)=>`lanmm-lifecycle-review:${model}`;
const mount=(client=api,model="model-1")=>flushSync(()=>root.render(<LifecycleReview api={client} modelId={model}/>));
const text=()=>document.getElementById("root")!.textContent!;
async function settle(){await until(()=>Array.from(document.querySelectorAll("button")).every(b=>!b.disabled),"actions did not settle");}
async function run(){
 let cases=0;
 for(const approved of [false,true])for(const action of ["Refresh status","Execute reviewed load","Cancel review"]){
  sessionStorage.clear();flushSync(()=>root.render(null));
  await fetch(`/test/configure?approval=${approved}`,{method:"POST"});mount();
  click("Prepare load");await ready(approved?"Approve reviewed proposal":"Execute reviewed load");
  if(approved){click("Approve reviewed proposal");await ready("Execute reviewed load");}
  const old=sessionStorage.getItem(key("model-1"));check(old?.length===64,"server opaque id stored");
  await fetch("/test/restart",{method:"POST"});click(action);
  await until(()=>!!document.querySelector('[role="alert"]'),"restart 409 alert");await settle();
  check(!button("Prepare load"),"no automatic reprepare");check(!text().includes("State: cancelled"),"no false cancellation");
  check(text().includes("No durable job yet"),"no fabricated job");check(!document.querySelector('a[href^="#/operations/job/"]'),"no fabricated durable link");
  click("Forget local review");await until(()=>!!button("Prepare load"),"forget exposes prepare");
  check(sessionStorage.getItem(key("model-1"))===null,"forget clears opaque id");
  await tick();check(sessionStorage.getItem(key("model-1"))===null,"forget does not prepare");
  click("Prepare load");await ready("Forget local review");
  check(sessionStorage.getItem(key("model-1"))!==null,"explicit reprepare");
  check(sessionStorage.getItem(key("model-1"))!==old,"new server-generated proposal ID");
  click("Forget local review");await until(()=>!!button("Prepare load"),"forget without execution");cases++;
 }
 // A saved opaque ID unavailable after restart also requires explicit local abandonment.
 await fetch("/test/configure?approval=false",{method:"POST"});click("Prepare load");
 await ready("Execute reviewed load");
 const saved=sessionStorage.getItem(key("model-1"));await fetch("/test/restart",{method:"POST"});
 flushSync(()=>root.render(null));mount();await until(()=>!!document.querySelector('[role="alert"]'),"saved ID restore error");await settle();
 check(!button("Prepare load"),"unavailable saved review must be explicitly forgotten");
 click("Forget local review");await until(()=>!!button("Prepare load"),"saved ID forgotten");
 check(sessionStorage.getItem(key("model-1"))===null,"unavailable saved ID cleared");
 click("Prepare load");await ready("Execute reviewed load");
 check(sessionStorage.getItem(key("model-1"))!==saved,"restored recovery gets new server ID");click("Forget local review");
 // Exercise the real component's polling effect with a deliberately abort-ignoring
 // transport. A late old status must not resurrect a forgotten/new-model review.
 const sample:LifecycleProposal={proposalId:"a".repeat(64),operation:"load",target:{modelId:"model-1",hostId:"h",providerId:"p",canonicalName:"late-test"},consequence:"Fixture",expiresAt:"2026-11-04T06:00:00.000Z",requiresApproval:false,reasons:[],state:"prepared",jobId:null,jobState:null};
 let resolvePoll:(p:LifecycleProposal)=>void=()=>{},resolveSubmit:(p:LifecycleProposal)=>void=()=>{},pollStarted=false,submits=0,prepares=0;
 const fake={prepareLifecycle:async()=>{prepares++;return sample;},proposalAction:async(action:string)=>{
  if(action==="submit"){submits++;return new Promise<LifecycleProposal>(resolve=>{resolveSubmit=resolve;});}
  if(!pollStarted){pollStarted=true;return new Promise<LifecycleProposal>(resolve=>{resolvePoll=resolve;});}
  return {...sample,state:"terminal",jobId:"durable-job",jobState:"succeeded"} as LifecycleProposal;
 }} as unknown as ApiClient;
 flushSync(()=>root.render(null));sessionStorage.clear();mount(fake);
 click("Prepare load");await ready("Execute reviewed load");
 const execute=button("Execute reviewed load")!;execute.click();execute.click();
 await until(()=>Array.from(document.querySelectorAll("button")).every(b=>b.disabled),"all actions disabled while request busy");
 resolveSubmit({...sample,state:"submitting",jobId:"durable-job",jobState:"running"});await until(()=>text().includes("State: submitting"),"submitting");
 check(submits===1&&prepares===1,"no duplicate submit or auto prepare");
 check(button("Forget local review")?.disabled,"active submitting cannot be forgotten");
 check(document.querySelector('a')?.getAttribute("href")?.includes("durable-job"),"active durable job link retained");
 await until(()=>pollStarted,"poll started");await ready("Refresh status");click("Refresh status");await until(()=>text().includes("State: terminal"),"terminal refresh");await ready("Forget local review");
 click("Forget local review");await until(()=>!!button("Prepare load"),"terminal forget");
 resolvePoll({...sample,state:"submitting",jobId:"durable-job",jobState:"running"});await tick();await tick();
 check(!text().includes("late-test")&&sessionStorage.getItem(key("model-1"))===null,"late status cannot resurrect forgotten review");
 sessionStorage.setItem(key("model-1"),sample.proposalId);mount(fake,"model-2");await tick();
 check(!!button("Prepare load")&&!text().includes("late-test"),"model keys isolated");check(sessionStorage.getItem(key("model-1"))===sample.proposalId,"other model saved ID untouched");
 flushSync(()=>root.unmount());return {cases,checks:"real controller close/reopen 409; actual mounted button handlers; explicit forget/reprepare; no jobs; async race; model isolation; busy/duplicate guard; durable tracking"};
}
run().then(result=>fetch("/test/result",{method:"POST",body:JSON.stringify({ok:true,...result})}),error=>fetch("/test/result",{method:"POST",body:JSON.stringify({ok:false,error:String(error),stack:error.stack})}));
