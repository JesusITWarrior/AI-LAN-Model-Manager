import test from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { createElement } from "react";
import { createApiClient, parseLifecycleProposal, InvalidResponseError, type LifecycleProposal } from "./api.js";
import { LifecycleReview, lifecycleActions, performLifecycleAction } from "./lifecycle-review.js";
const p:LifecycleProposal={proposalId:"a".repeat(64),operation:"load",target:{modelId:"model-1",hostId:"host-1",providerId:"provider-1",canonicalName:"example:model"},consequence:"Allocate memory to load this model.",expiresAt:"2026-11-04T06:00:00.000Z",requiresApproval:true,reasons:["approval-required"],state:"approval-required",jobId:null,jobState:null};
test("lifecycle DTO strictly rejects authority and malformed fields",()=>{
 assert.equal(parseLifecycleProposal(p).target.modelId,"model-1");
 for(const field of ["capability","requestDigest","approvalId","endpoint","intent","request"])assert.throws(()=>parseLifecycleProposal({...p,[field]:{}}),InvalidResponseError);
 assert.throws(()=>parseLifecycleProposal({...p,target:{...p.target,endpoint:"http://private"}}),InvalidResponseError);
 assert.throws(()=>parseLifecycleProposal({...p,proposalId:"invented"}),InvalidResponseError);
 assert.throws(()=>parseLifecycleProposal({...p,state:"ready"}),InvalidResponseError);
});
test("page workflow prepares, approves, explicitly executes and follows/cancels only the same opaque ID",async()=>{
 const calls:Array<{url:string;body:any}>=[];let state=p.state;
 const api=createApiClient((async(url:unknown,init:RequestInit)=>{const body=JSON.parse(String(init.body));calls.push({url:String(url),body});if(String(url).endsWith("approve"))state="approved";if(String(url).endsWith("submit"))state="submitting";if(String(url).endsWith("cancel"))state="terminal";return {ok:true,status:200,json:async()=>({ok:true,value:{...p,state,jobId:state==="submitting"||state==="terminal"?"job-1":null,jobState:state==="terminal"?"cancelled":state==="submitting"?"accepted":null}})};}) as unknown as typeof fetch,()=>"fixture-csrf");
 const prepared=await performLifecycleAction(api,"model-1",null,"load");assert.deepEqual(calls[0]?.body,{operation:"load",modelId:"model-1"});assert.equal(lifecycleActions(prepared).execute,false);
 const approved=await performLifecycleAction(api,"model-1",prepared,"approve");assert.equal(calls.length,2,"approval must not also submit");assert.equal(lifecycleActions(approved).execute,true);
 const submitted=await performLifecycleAction(api,"model-1",approved,"submit");assert.equal(submitted.jobId,"job-1");assert.equal(lifecycleActions(submitted).execute,false);
 await performLifecycleAction(api,"model-1",submitted,"status");const cancelled=await performLifecycleAction(api,"model-1",submitted,"cancel");assert.equal(cancelled.jobState,"cancelled");
 for(const call of calls.slice(1))assert.deepEqual(call.body,{proposalId:p.proposalId});
 for(const state of ["stale","expired","cancelled","terminal"] as const)assert.equal(lifecycleActions({...p,state}).execute,false);
 assert.equal(lifecycleActions({...p,state:"approved",reasons:["revoked-host","approval-required"]}).execute,false);
 const html=renderToStaticMarkup(createElement(LifecycleReview,{api,modelId:"model-1"}));assert.match(html,/Prepare load/);assert.match(html,/Inventory alone does not establish serving readiness/);assert.doesNotMatch(html,/Execute reviewed/);
});
