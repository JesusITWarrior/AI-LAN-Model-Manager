import React from "react";
import {createRoot} from "react-dom/client";
import {flushSync} from "react-dom";
import {createApiClient} from "../src/api.js";
import {SettingsView} from "../src/settings-view.js";
const root=createRoot(document.getElementById("root")!),api=createApiClient(fetch,()=>"fixture-csrf");
const check=(v:unknown,m:string)=>{if(!v)throw new Error(m);};
const tick=()=>new Promise(r=>setTimeout(r,10));
async function until(fn:()=>boolean,m:string){for(let i=0;i<500;i++){if(fn())return;await tick();}throw new Error(m);}
const text=()=>document.getElementById("root")!.textContent!;
const button=(name:string)=>Array.from(document.querySelectorAll("button")).find(b=>b.textContent===name);
const click=(name:string)=>{const b=button(name);check(b&&!b.disabled,`enabled ${name}`);b!.click();};
const input=(label:string)=>Array.from(document.querySelectorAll("label")).find(l=>l.textContent?.startsWith(label))!.querySelector("input")!;
async function type(label:string,value:string){const element=input(label);Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value")!.set!.call(element,value);element.dispatchEvent(new Event("input",{bubbles:true}));await tick();}
const mode=async(value:string)=>{await fetch(`/test/mode?value=${value}`,{method:"POST"});};
async function run(){
 // Keep UI expiry comparisons aligned with the real controller fixture clock.
 Date.now=()=>Date.parse("2026-09-29T10:00:00.000Z");
 let unhandled=0;addEventListener("unhandledrejection",()=>{unhandled++;});
 flushSync(()=>root.render(<SettingsView api={api}/>));await until(()=>!!button("Save operation policy"),"settings mounted");
 check(text().includes("Inference eligibility: unknown")&&text().includes("Client connectivity: not verified"),"no invented readiness");check(text().includes("Policy version 1"),"default observe only");check(!input("Allow model-load").checked,"no autoallow");
 input("Allow model-load").click();await tick();input("Require approval for model-load").click();await type("Memory reserve (bytes)","2");
 const save=button("Save operation policy")!;save.click();save.click();await until(()=>text().includes("Policy version 2"),"policy saved through mapped client");check(text().includes("Prompted operations: model-load"),"approval retained");
 await mode("conflict");click("Save operation policy");await until(()=>text().includes("Policy changed elsewhere"),"CAS error displayed");await until(()=>!button("Save operation policy")!.disabled,"save settles");await mode("normal");
 await type("Token label","Mounted fixture");await mode("issue-fail");click("Issue token");await until(()=>text().includes("Token issuance failed"),"issue failure visible");check(!text().includes("synthetic-secret-error"),"redacted issue failure");await mode("normal");click("Issue token");await until(()=>!!button("Copy token"),"issued shown once");
 const secret=document.querySelector(".secretReveal code")!.textContent!;check(secret.length===43,"issued credential displayed");check(!Object.values(localStorage).some(v=>v.includes(secret))&&!Object.values(sessionStorage).some(v=>v.includes(secret)),"no storage secret");
 Object.defineProperty(navigator,"clipboard",{configurable:true,value:{writeText:async()=>{throw new Error("synthetic-secret-error");}}});click("Copy token");await until(()=>text().includes("Copy failed"),"clipboard failure visible");check(!button("Copied"),"no false copied");
 await mode("all-fail");click("Revoke all");await until(()=>text().includes("Revoke all failed"),"all failure visible");check(document.querySelector(".secretReveal code")?.textContent===secret,"issued secret retained on failed action");
 await mode("all-zero");click("Revoke all");await until(()=>text().includes("Controller confirmed 0 token revocations"),"zero revocations reported exactly");await until(()=>!button("Reload settings")!.disabled,"zero revoke settles");check(text().includes("active metadata"),"zero count does not revoke metadata");
 await mode("normal");click("Reload settings");await until(()=>!!button("Issue token")&&!button("Reload settings")!.disabled,"reload settles");await tick();check(document.querySelector(".secretReveal code")?.textContent===secret,"issued secret retained through refresh");
 click("I have stored it");await until(()=>!button("Copy token"),"explicit acknowledgment hides secret");check(!text().includes(secret),"secret removed after acknowledgment");
 await mode("revoke-false");click("Revoke");await until(()=>text().includes("Revocation was not confirmed"),"false revocation truthful");check(text().includes("active metadata"),"false revoke not success");
 await mode("revoke-fail");click("Revoke");await until(()=>text().includes("Token revocation failed"),"revocation failure visible");
 await mode("normal");click("Revoke");await until(()=>text().includes("revoked / expired"),"successful revoke refreshed");await until(()=>!button("Reload settings")!.disabled,"refresh done");
 const confirmation=input("Type");await type("Type","ENABLE NO-PROMPT");await mode("toggle-fail");click("Enable no-prompt mode");await until(()=>text().includes("No-prompt change failed"),"toggle error visible");check(text().includes("Prompted operations: model-load"),"failed toggle retains policy");
 await mode("normal");click("Enable no-prompt mode");await until(()=>text().includes("Policy version 3")&&text().includes("Prompted operations: none"),"explicit toggle succeeds separately");
 await type("Token label","Second fixture client");click("Issue token");await until(()=>!!button("Copy token"),"second issued credential");const secondSecret=document.querySelector(".secretReveal code")!.textContent!;click("Revoke all");await until(()=>text().includes("Controller confirmed 1 token revocations"),"real revoke all exact count");await until(()=>!button("Reload settings")!.disabled,"revoke all no stuck busy");check(document.querySelector(".secretReveal code")?.textContent===secondSecret,"credential retained through successful revocation until ack");click("I have stored it");
 check(unhandled===0,"no unhandled promises");check(!text().includes("synthetic-secret-error"),"no raw errors");flushSync(()=>root.unmount());return {cases:["policy-save","CAS-conflict","issue-failure","issue-success","clipboard-failure","revoke-all-failure","revoke-all-zero","secret-retention","revoke-false","revoke-failure","revoke-success","toggle-failure","toggle-success","revoke-all-success"]};
}
async function sharedGateCases(){
 const counts:Record<string,number>={};let rejectPending:((e:Error)=>void)|undefined;
 const snapshot={version:1,noPromptEnabled:false,allowedOperations:["observe","model-load"],approvalOperations:["model-load"],hardLimits:{minimumMemoryHeadroomBytes:0,minimumVramHeadroomBytes:0,minimumStorageHeadroomBytes:0,maxConcurrentOperations:1,maxOperationsPerMinute:1}};
 const metadata=(tokenId:string)=>({tokenId,label:tokenId,scopes:["inference:invoke","model:list"] as const,createdAt:"2026-09-29T10:00:00.000Z",lastUsedAt:null,expiresAt:null,revokedAt:null});
 const pending=(name:string)=>{counts[name]=(counts[name]??0)+1;return new Promise<never>((_,reject)=>{rejectPending=reject;});};
 const gatedApi={...api,tokens:async()=>[metadata("row-one"),metadata("row-two")],policySettings:async()=>snapshot,savePolicy:()=>pending("save"),setNoPrompt:()=>pending("toggle"),issueToken:()=>pending("issue"),revokeAllTokens:()=>pending("all"),revokeToken:(id:string)=>pending(id)};
 const mounted=createRoot(document.getElementById("root")!);flushSync(()=>mounted.render(<SettingsView api={gatedApi}/>));await until(()=>!!button("Save operation policy"),"shared gate mounted");await type("Type","ENABLE NO-PROMPT");await type("Token label","gate client");
 const actions=()=>({save:document.querySelector<HTMLButtonElement>("fieldset button")!,toggle:button("Enable no-prompt mode")!,issue:button("Issue token")!,all:button("Revoke all")!,"row-one":document.querySelectorAll<HTMLButtonElement>(".tokenList button")[0]!,"row-two":document.querySelectorAll<HTMLButtonElement>(".tokenList button")[1]!});
 const pairs=[["save","toggle"],["toggle","save"],["save","issue"],["issue","save"],["save","all"],["all","save"],["row-one","save"],["save","row-one"],["row-one","toggle"],["toggle","row-one"],["row-one","issue"],["issue","row-one"],["row-one","all"],["all","row-one"],["row-one","row-two"],["row-two","row-one"]] as const;
 for(const [first,second] of pairs){
  const controls=actions();check(!controls[first].disabled&&!controls[second].disabled,`pair enabled ${first}/${second}`);const before=Object.values(counts).reduce((a,b)=>a+b,0),firstBefore=counts[first]??0;
  // One React event turn: both real handlers run before disabled props commit.
  flushSync(()=>{controls[first].click();check(!controls[second].matches(":disabled"),`second still DOM-enabled before commit ${first}/${second}`);controls[second].click();});
  check(Object.values(counts).reduce((a,b)=>a+b,0)===before+1,`one request ${first}/${second}`);check(counts[first]===firstBefore+1,`first owns gate ${first}/${second}`);
  check(Object.values(actions()).every(b=>b.matches(":disabled")),`shared disabled presentation ${first}`);rejectPending!(new Error("synthetic-secret-error"));await until(()=>!actions().save.matches(":disabled")&&!actions()["row-one"].disabled,`failure releases gate ${first}`);
 }
 check(!text().includes("synthetic-secret-error"),"gate failures redacted");flushSync(()=>mounted.unmount());return pairs.length;
}
run().then(async result=>{const sharedGatePairs=await sharedGateCases();await fetch("/test/result",{method:"POST",body:JSON.stringify({ok:true,...result,sharedGatePairs})});},error=>{throw error;}).catch(error=>fetch("/test/result",{method:"POST",body:JSON.stringify({ok:false,error:String(error),stack:error.stack})}));
