import {readFileSync} from "node:fs";
import {test} from "node:test";
import assert from "node:assert/strict";
import {parseCommandRequest} from "./command.js";
import {parseStreamCommand,streamAuthorizationDigest,StreamEventValidator,type StreamCommandRequest} from "./stream-command.js";
const fixture=JSON.parse(readFileSync(new URL("../../../agents/host-agent/internal/command/testdata/stream-v1.json",import.meta.url),"utf8"));
const wire=(v:unknown)=>Buffer.from(JSON.stringify(v));
const request=()=>parseStreamCommand(wire(fixture.request));
test("stream shared fixture digest, ordered terminal and closed buffered parser",()=>{
 const r=request();assert.equal(streamAuthorizationDigest(r),fixture.request.capability.requestDigest);assert.equal(parseCommandRequest(r).ok,false);
 const v=new StreamEventValidator(r);for(const e of fixture.events)v.accept(wire(e));v.finish();assert.throws(()=>v.accept(wire(fixture.events[1])));
});
test("stream digest binds every limit, request, provider and message",()=>{
 for(const field of ["upstreamFrameBytes","maxEventBytes","maxTotalEventBytes","maxEvents"]){const r=structuredClone(fixture.request);r.params[field]--;assert.throws(()=>parseStreamCommand(wire(r)),field);}
 for(const field of ["providerId","modelId","model","requestId","maxRequestBytes","maxResponseBytes","messages"]){const r=structuredClone(fixture.request);r.params.chat[field]=field==="messages"?[]:typeof r.params.chat[field]==="number"?r.params.chat[field]-1:"tampered";assert.throws(()=>parseStreamCommand(wire(r)),field);}
 const raw=JSON.stringify(fixture.request).replace('"schemaVersion":1','"schemaVersion":1,"schemaVersion":1');assert.throws(()=>parseStreamCommand(Buffer.from(raw)));
});
test("stream rejects duplicate, reordered, foreign, unknown, overflow and terminal races",()=>{
 const mutations=[
  (e:any)=>{e.index=1},(e:any)=>{e.hostId="foreign"},(e:any)=>{e.jobId="foreign"},(e:any)=>{e.requestId="foreign"},(e:any)=>{e.commandDigest="0".repeat(64)},
  (e:any)=>{e.extra=1},(e:any)=>{e.chunk.extra=1},(e:any)=>{e.chunk.choices[0].delta.thinking="private"},
  (e:any)=>{e.chunk.model="foreign"},(e:any)=>{e.chunk.id="foreign"},(e:any)=>{e.chunk.usage=null},
 ];
 for(const mutate of mutations){const v=new StreamEventValidator(request()),e=structuredClone(fixture.events[0]);mutate(e);assert.throws(()=>v.accept(wire(e)));assert.throws(()=>v.finish());}
 const v=new StreamEventValidator(request());v.accept(wire(fixture.events[0]));assert.throws(()=>v.accept(wire(fixture.events[0])));assert.throws(()=>v.finish());
 for(const usage of [{prompt_tokens:Number.MAX_SAFE_INTEGER,completion_tokens:1,total_tokens:Number.MAX_SAFE_INTEGER+1},{prompt_tokens:1,completion_tokens:2,total_tokens:4}]){const v=new StreamEventValidator(request());v.accept(wire(fixture.events[0]));const e=structuredClone(fixture.events[1]);e.chunk.usage=usage;assert.throws(()=>v.accept(wire(e)));}
 const dup=JSON.stringify(fixture.events[0]).replace('"index":0','"index":0,"index":0');assert.throws(()=>new StreamEventValidator(request()).accept(Buffer.from(dup)));
 const lone=JSON.stringify(fixture.events[0]).replace('synthetic δ','\\ud800');assert.throws(()=>new StreamEventValidator(request()).accept(Buffer.from(lone)));
});
test("stream total, frame, count limits and EOF never imply success",()=>{
 for(const mode of ["frame","total","count"]){const r=structuredClone(fixture.request) as StreamCommandRequest;
  const p=r.params as any;p.maxEventBytes=1024;p.maxTotalEventBytes=1024;if(mode==="count"){p.maxTotalEventBytes=4096;p.maxEvents=1;}
  (r.capability as any).requestDigest=streamAuthorizationDigest(r);
  const v=new StreamEventValidator(r);const e=structuredClone(fixture.events[0]);e.commandDigest=r.capability.requestDigest;if(mode==="frame")e.chunk.choices[0].delta.content="x".repeat(1024);if(mode==="total")e.chunk.choices[0].delta.content="x".repeat(400);
  if(mode==="frame")assert.throws(()=>v.accept(wire(e)));else{v.accept(wire(e));const terminal=structuredClone(fixture.events[1]);terminal.commandDigest=r.capability.requestDigest;assert.throws(()=>v.accept(wire(terminal)));}assert.throws(()=>v.finish());
 }
 assert.throws(()=>new StreamEventValidator(request()).finish());
 for(const kind of ["failed","cancelled"]){const v=new StreamEventValidator(request());const e={...fixture.events[0],kind,chunk:null,errorCode:kind==="failed"?"STREAM_FAILED":"CANCELLED"};v.accept(wire(e));v.finish();}
});
test("shared raw cross-language rejection vectors",()=>{
 for(const c of fixture.invalidEvents){const v=new StreamEventValidator(request());for(const i of c.prior)v.accept(wire(fixture.events[i]));assert.throws(()=>v.accept(Buffer.from(c.raw)),c.name);assert.throws(()=>v.finish(),c.name);}
});
test("shared raw command rejection vectors including UTF-8 BOM",()=>{
 for(const c of fixture.invalidCommands)assert.throws(()=>parseStreamCommand(Buffer.from(c.raw)),c.name);
});
test("validator isolates later caller request mutation",()=>{
 const r=request(),v=new StreamEventValidator(r);
 (r.capability as any).modelId="foreign";(r.params.chat as any).model="foreign";
 for(const e of fixture.events)v.accept(wire(e));v.finish();
});
