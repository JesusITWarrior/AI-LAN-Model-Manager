import {canonicalAgentPeerAddress} from "./agent-stream-http.js";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import {streamAuthorizationDigest} from "@lan-model-manager/core";
import {AgentStreamRelay} from "./agent-stream-relay.js";
const fixture=JSON.parse(readFileSync(new URL("../../../agents/host-agent/internal/command/testdata/stream-v1.json",import.meta.url),"utf8"));
const wire=(v:unknown)=>Buffer.from(JSON.stringify(v));
function setup(){let now=Date.now();const request=structuredClone(fixture.request);request.deadline=new Date(now+60_000).toISOString();request.capability.expiresAt=request.deadline;request.capability.requestDigest=streamAuthorizationDigest(request);const events=structuredClone(fixture.events);for(const e of events)e.commandDigest=request.capability.requestDigest;const relay=new AgentStreamRelay(()=>now);const handle=relay.open(wire(request));relay.poll(request.hostId);return {request,events,relay,handle,advance:()=>{now+=60_001}};}
const tick=()=>new Promise<void>(resolve=>setImmediate(resolve));
const signal=()=>new AbortController().signal;
test("single bounded slot applies synchronous backpressure; success acceptance owns terminal",async()=>{
 const {request,events,relay,handle}=setup();let ack=false;
 const posting=relay.publish(request.hostId,wire(events[0]),signal()).then(()=>{ack=true});await tick();
 assert.equal(ack,false);assert.equal(relay.stats().events,1);assert.equal(relay.stats().bytes,wire(events[0]).length);
 assert.equal((await handle.next(signal()))?.kind,"chunk");await posting;assert.equal(ack,true);
 const terminal=relay.publish(request.hostId,wire(events[1]),signal());assert.equal((await handle.next(signal()))?.kind,"succeeded");await terminal;handle.cancel();assert.equal(await handle.outcome,"succeeded");
 const result={requestId:request.requestId,jobId:request.jobId,hostId:request.hostId,sequence:request.sequence,status:"succeeded",progress:100,observedAt:new Date().toISOString(),observation:null,errorCode:null};assert.equal(relay.complete(request.hostId,{commandDigest:request.capability.requestDigest,result}),true);assert.equal(relay.complete(request.hostId,{commandDigest:request.capability.requestDigest,result:{...result,status:"failed",errorCode:"STREAM_FAILED"}}),false);
 assert.equal(await handle.next(signal()),null);handle.close();assert.deepEqual(relay.stats(),{streams:0,events:0,bytes:0});assert.throws(()=>relay.open(wire(request)));relay.stop();
});
test("cancel, deadline, restart and disconnect release blocked publishers without requeue",async()=>{
 for(const mode of ["cancel","deadline","restart","disconnect"]){const {request,events,relay,handle,advance}=setup(),abort=new AbortController();const post=relay.publish(request.hostId,wire(events[0]),abort.signal);const rejected=assert.rejects(post);await tick();assert.equal(relay.poll(request.hostId).streamCommand,null);
  if(mode==="cancel")handle.cancel();else if(mode==="deadline"){advance();await handle.next(signal());}else if(mode==="restart")relay.stop();else abort.abort();
  await rejected;assert.equal(await handle.outcome,mode==="restart"?"interrupted":mode==="deadline"?"deadline":"cancelled");handle.close();assert.deepEqual(relay.stats(),{streams:0,events:0,bytes:0});
 }
});
test("missing/foreign/out-of-order/duplicate/raw events and terminal result conflicts fail closed",async()=>{
 for(const change of ["missing","foreign-host","foreign-job","foreign-request","foreign-digest","out-of-order","duplicate-key","BOM"]){const {request,events,relay,handle}=setup();const e=events[0];let raw=wire(e),host=request.hostId;
  if(change==="foreign-host")host="foreign";if(change==="foreign-job")e.jobId="foreign";if(change==="foreign-request")e.requestId="foreign";if(change==="foreign-digest")e.commandDigest="f".repeat(64);if(change==="out-of-order")e.index=1;
  raw=wire(e);if(change==="duplicate-key")raw=Buffer.from(raw.toString().replace('"index":0','"index":0,"index":0'));if(change==="BOM")raw=Buffer.concat([Buffer.from([239,187,191]),raw]);
  const result={requestId:request.requestId,jobId:request.jobId,hostId:request.hostId,sequence:request.sequence,status:"succeeded",progress:100,observedAt:new Date().toISOString(),observation:null,errorCode:null};
  if(change==="missing")assert.equal(relay.complete(request.hostId,{commandDigest:request.capability.requestDigest,result}),false);else await assert.rejects(relay.publish(host,raw,signal()));handle.close();assert.equal((await handle.outcome)==="succeeded",false);relay.stop();
 }
});
test("revocation is rechecked at consumer acceptance, not only before a blocked post",async()=>{
 const {request,events,relay,handle}=setup();let active=true;const post=relay.publish(request.hostId,wire(events[0]),signal(),()=>active),reject=assert.rejects(post);active=false;await assert.rejects(handle.next(signal()));await reject;assert.equal(await handle.outcome,"failed");handle.close();
});
test("concurrent publishers/readers and per-host/global admission are bounded",async()=>{
 const {request,events,relay,handle}=setup();const first=relay.publish(request.hostId,wire(events[0]),signal()),rejected=assert.rejects(first);await assert.rejects(relay.publish(request.hostId,wire(events[0]),signal()));await rejected;handle.close();
 const relay2=new AgentStreamRelay(Date.now,1,1),h=relay2.open(wire(request));const other=structuredClone(request);other.jobId="other-job";other.requestId="other-request";other.params.chat.requestId=other.requestId;other.idempotencyKey="other-idem";other.capability.requestDigest=streamAuthorizationDigest(other);assert.throws(()=>relay2.open(wire(other)));h.close();relay2.stop();
});
test("capability expiry wins over deadline; expired or tampered commands never lease",async()=>{
 let now=Date.now();const request=structuredClone(fixture.request);request.deadline=new Date(now+60_000).toISOString();request.capability.expiresAt=new Date(now+100).toISOString();request.capability.requestDigest=streamAuthorizationDigest(request);
 const relay=new AgentStreamRelay(()=>now),handle=relay.open(wire(request));relay.poll(request.hostId);now+=101;
 const event={...fixture.events[0],commandDigest:request.capability.requestDigest};await assert.rejects(relay.publish(request.hostId,wire(event),signal()));assert.equal(await handle.outcome,"deadline");handle.close();assert.throws(()=>relay.open(wire(request)));
 request.capability.targetId="foreign";assert.throws(()=>new AgentStreamRelay().open(wire(request)));relay.stop();
});
test("consumer cancellation wakes an idle mailbox and rejects multiple simultaneous readers",async()=>{
 const {relay,handle}=setup(),abort=new AbortController();const next=handle.next(abort.signal),rejected=assert.rejects(next);await assert.rejects(handle.next(signal()));abort.abort();await rejected;assert.equal(await handle.outcome,"cancelled");handle.close();assert.deepEqual(relay.stats(),{streams:0,events:0,bytes:0});relay.stop();
});
test("close retains bounded host-bound cancellation beyond mailbox lifetime until deadline grace",async()=>{
 let now=Date.now();const request=structuredClone(fixture.request);request.deadline=new Date(now+60_000).toISOString();request.capability.expiresAt=request.deadline;request.capability.requestDigest=streamAuthorizationDigest(request);
 const relay=new AgentStreamRelay(()=>now,1),h=relay.open(wire(request));relay.poll(request.hostId);h.close();assert.deepEqual(relay.stats(),{streams:0,events:0,bytes:0});
 assert.deepEqual(relay.poll("foreign").cancelledJobIds,[]);for(let i=0;i<3;i++)assert.deepEqual(relay.poll(request.hostId).cancelledJobIds,[request.jobId]);
 const other=structuredClone(request);other.jobId="next-job";other.requestId="next-request";other.params.chat.requestId=other.requestId;other.idempotencyKey="next-idem";other.capability.requestDigest=streamAuthorizationDigest(other);assert.throws(()=>relay.open(wire(other)));
 now+=60_001;assert.deepEqual(relay.poll(request.hostId).cancelledJobIds,[request.jobId]);now+=30_000;assert.deepEqual(relay.poll(request.hostId).cancelledJobIds,[]);relay.stop();
});

test("source address binding canonicalizes only valid native or mapped IPs",()=>{
 for(const address of ["127.0.0.1","::ffff:127.0.0.1","::FFFF:7f00:1"])assert.equal(canonicalAgentPeerAddress(address),"127.0.0.1");
 assert.notEqual(canonicalAgentPeerAddress("127.0.0.2"),canonicalAgentPeerAddress("127.0.0.1"));
 for(const address of [undefined,"127.000.0.1","::ffff:127.0.0.999","fe80::1%eth0","localhost"])assert.equal(canonicalAgentPeerAddress(address),null);
});
