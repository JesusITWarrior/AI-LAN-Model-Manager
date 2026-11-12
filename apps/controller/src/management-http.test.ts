import assert from "node:assert/strict";import test from "node:test";import { EventEmitter } from "node:events";import { createManagementHttpHandler } from "./management-http.js";import { MANAGEMENT_BODY_LIMIT, OWNER_EVIDENCE_PREPARE_BODY_LIMIT } from "./management-api.js";
class Request extends EventEmitter { method="POST";url="/api/v1/policy/install";headers:Record<string,string|string[]|undefined>={};rawHeaders?:string[];resumed=false;wasDestroyed=false;destroyCalls=0;resume(){this.resumed=true;}destroy(){this.wasDestroyed=true;this.destroyCalls++;return this;} }
class Response extends EventEmitter {headersSent=false;writableEnded=false;status=0;headers:Record<string,unknown>={};payload="";writes=0;ends=0;setHeader(k:string,v:unknown){this.headers[k]=v;}writeHead(v:number){this.writes++;this.status=v;this.headersSent=true;return this;}end(v?:string){this.ends++;this.payload=v??"";this.writableEnded=true;queueMicrotask(()=>this.emit("finish"));}}
const handler=createManagementHttpHandler({} as never);
function errorCode(response:Response):string{return JSON.parse(response.payload).error.code;}
test("HTTP adapter rejects malformed and excessive content-length before reading and closes after response completion",async()=>{for(const value of ["nope",String(MANAGEMENT_BODY_LIMIT+1)]){const request=new Request(),response=new Response();request.headers["content-length"]=value;handler(request as never,response as never);assert.equal(response.status,413);assert.equal(errorCode(response),"PAYLOAD_TOO_LARGE");assert.equal(request.resumed,false,"rejection never starts an unbounded drain");await new Promise(resolve=>setImmediate(resolve));assert.equal(request.wasDestroyed,true);assert.equal(request.destroyCalls,1);}});
test("HTTP adapter bounds streamed bodies and rejects hostile repeated headers",async()=>{const oversized=new Request(),a=new Response();handler(oversized as never,a as never);oversized.emit("data",Buffer.alloc(MANAGEMENT_BODY_LIMIT));oversized.emit("data",Buffer.from("x"));oversized.emit("end");assert.equal(a.status,413);assert.equal(errorCode(a),"PAYLOAD_TOO_LARGE");const repeated=new Request(),b=new Response();repeated.headers.cookie=["a","b"];handler(repeated as never,b as never);repeated.emit("end");await new Promise(resolve=>setImmediate(resolve));assert.equal(b.status,400);assert.equal(errorCode(b),"INVALID_REQUEST");});
test("HTTP adapter rejects non-byte stream chunks without invoking routing",()=>{const request=new Request(),response=new Response();handler(request as never,response as never);request.emit("data",{hostile:true});request.emit("end");assert.equal(response.status,413);assert.equal(errorCode(response),"PAYLOAD_TOO_LARGE");});

const TOKEN="a".repeat(43),session={ownerId:"owner-1",credentialVersion:1,sessionVersion:1,createdAt:"2026-01-01T00:00:00.000Z",lastSeenAt:"2026-01-01T00:00:00.000Z",absoluteExpiresAt:"2099-01-01T00:00:00.000Z",idleExpiresAt:"2099-01-01T00:00:00.000Z",revokedAt:null};
const preview={candidateHandle:"candidate-1:abcdef0123456789abcdef0123456789:1",expectedTupleDigest:"a".repeat(64),jobId:"job-1",hostId:"host-1",requestId:"request-1",terminalState:"succeeded",terminalRevision:"rev-1",evidenceKind:"succeeded",payloadBytes:100,responseBytes:20,expiresAt:"2099-01-01T00:00:00.000Z",action:"append-supplemental-native-evidence",disposition:"evidence-only",label:"Owner-provided unsigned evidence; source not independently proven"};
const payload=Buffer.from(JSON.stringify({domain:"lan-model-manager.native-terminal-evidence",kind:"native-terminal-evidence",version:1,disposition:"evidence-only",tuple:{domain:"lan-model-manager.native-terminal-evidence-tuple",hostId:"host-1",jobId:"job-1",requestId:"request-1",commandSequence:1,idempotencyKey:"key-1",authorizationRequestDigest:"a".repeat(64),storedQueueDigest:"b".repeat(64),terminalState:"succeeded",terminalRevision:"rev-1",responseDigest:"c".repeat(64),responseByteLength:20,evidenceKind:"succeeded",holdClass:"none"},responseBase64:"e30=",evidenceSource:"owner é"}));
let invoked=0,captured=Buffer.alloc(0);
const evidenceHandler=createManagementHttpHandler({sessions:{authenticate:(t:string)=>t===TOKEN?session:null,authenticateCsrf:(t:string,c:string)=>t===TOKEN&&c==="csrf"?session:null},allowedOrigins:["https://manager.test"],ownerEvidenceIntake:{prepare:(input:any)=>{invoked++;captured=Buffer.from(input.rawPayloadBytes);return{ok:true,preview};}}} as never);
function prepare():Request{const r=new Request();r.url="/api/v1/native-evidence/prepare";r.headers={cookie:`__Host-lanmm_session=${TOKEN}`,origin:"https://manager.test","x-csrf-token":"csrf","content-type":"application/json"};return r;}
class DestroyableRequest extends Request {}
test("prepare HTTP streams exact-cap UTF-8 bytes and closes an overflowing request without dispatch",async()=>{
 invoked=0;const req=prepare(),res=new Response();const exact=Buffer.concat([payload,Buffer.alloc(OWNER_EVIDENCE_PREPARE_BODY_LIMIT-payload.length,0x20)]);req.headers["content-length"]=String(exact.length);evidenceHandler(req as never,res as never);
 const pos=exact.indexOf(Buffer.from("é")),partA=exact.subarray(0,pos+1),partB=exact.subarray(pos+1),before=Buffer.from(exact);req.emit("data",partA);req.emit("data",partB);req.emit("end");await new Promise(resolve=>setImmediate(resolve));
 assert.equal(res.status,200);assert.equal(invoked,1);assert.deepEqual(captured,exact);assert.deepEqual(exact,before);
 const overReq=new DestroyableRequest(),overRes=new Response();overReq.url="/api/v1/native-evidence/prepare";overReq.headers={cookie:`__Host-lanmm_session=${TOKEN}`,origin:"https://manager.test","x-csrf-token":"csrf","content-type":"application/json"};evidenceHandler(overReq as never,overRes as never);
 const huge=Buffer.alloc(OWNER_EVIDENCE_PREPARE_BODY_LIMIT+1,0x20),saved=Buffer.from(huge);overReq.emit("data",huge);assert.equal(overRes.status,413);overReq.emit("end");overReq.emit("data",Buffer.from("late"));await new Promise(resolve=>setImmediate(resolve));assert.equal(invoked,1);assert.equal(overReq.wasDestroyed,true);assert.deepEqual(huge,saved);
 const declaredReq=prepare(),declaredRes=new Response();declaredReq.headers["content-length"]=String(OWNER_EVIDENCE_PREPARE_BODY_LIMIT+1);evidenceHandler(declaredReq as never,declaredRes as never);assert.equal(declaredRes.status,413);assert.equal(invoked,1);
});
test("prepare HTTP fails closed on duplicate headers, content encoding, and length mismatch",async()=>{
 invoked=0;
 const duplicate=prepare(),a=new Response();duplicate.rawHeaders=["cookie",`__Host-lanmm_session=${TOKEN}`,"Cookie",`__Host-lanmm_session=${TOKEN}`];evidenceHandler(duplicate as never,a as never);assert.equal(a.status,400);
 const framing=prepare(),framingRes=new Response();framing.rawHeaders=["content-length","1","transfer-encoding","chunked"];evidenceHandler(framing as never,framingRes as never);assert.equal(framingRes.status,400);
 const transfer=prepare(),transferRes=new Response();transfer.headers["transfer-encoding"]="gzip";evidenceHandler(transfer as never,transferRes as never);assert.equal(transferRes.status,400);
 const encoded=prepare(),b=new Response();encoded.headers["content-encoding"]="gzip";evidenceHandler(encoded as never,b as never);assert.equal(b.status,415);
 const charset=prepare(),charsetRes=new Response();charset.headers["content-type"]="application/json; charset=utf-8; charset=utf-8";evidenceHandler(charset as never,charsetRes as never);assert.equal(charsetRes.status,415);
 const mismatch=prepare(),c=new Response();mismatch.headers["content-length"]=String(payload.length+1);evidenceHandler(mismatch as never,c as never);mismatch.emit("data",payload);mismatch.emit("end");assert.equal(c.status,400);assert.equal(invoked,0);
 const utf=prepare(),d=new Response();evidenceHandler(utf as never,d as never);utf.emit("data",Buffer.from([0x7b,0x22,0xff,0x7d]));utf.emit("end");await new Promise(resolve=>setImmediate(resolve));assert.equal(d.status,400);assert.equal(invoked,0);
});
test("abort and premature response close fence late events",()=>{
 invoked=0;const aborted=prepare(),a=new Response();evidenceHandler(aborted as never,a as never);aborted.emit("aborted");aborted.emit("data",payload);aborted.emit("end");assert.equal(a.status,0);assert.equal(invoked,0);assert.equal(aborted.listenerCount("data"),0);
 const disconnected=prepare(),b=new Response();evidenceHandler(disconnected as never,b as never);b.emit("close");disconnected.emit("data",payload);disconnected.emit("end");assert.equal(b.status,0);assert.equal(invoked,0);assert.equal(disconnected.listenerCount("data"),0);
});

test("HTTP adapter zeroes every owned buffer on terminal paths and fences late settles",async()=>{
 const bufferApi=Buffer as unknown as {alloc:(...args:any[])=>Buffer;concat:(...args:any[])=>Buffer};
 const originalAlloc=bufferApi.alloc,originalConcat=bufferApi.concat,owned:Buffer[]=[];
 const hugeForOverflow=Buffer.alloc(OWNER_EVIDENCE_PREPARE_BODY_LIMIT+1,0x20),hugeSaved=Buffer.from(hugeForOverflow);
 const seenRejection:unknown[]=[];const onUnhandled=(reason:unknown)=>seenRejection.push(reason);process.on("unhandledRejection",onUnhandled);
 bufferApi.alloc=((...args:any[])=>{const value=originalAlloc(...args);owned.push(value);return value;}) as typeof bufferApi.alloc;
 bufferApi.concat=((...args:any[])=>{const value=originalConcat(...args);owned.push(value);return value;}) as typeof bufferApi.concat;
 const listenerNames=["data","end","error","aborted","close"] as const;
 const zeroed=(label:string)=>{assert.ok(owned.length>0,`${label} exercised owned mutable bytes`);assert.ok(owned.every(value=>value.every(byte=>byte===0)),`${label} wipes all adapter-owned buffers`);owned.length=0;};
 const detached=(request:Request)=>{for(const name of listenerNames)assert.equal(request.listenerCount(name),0,`${name} listener detached`);};
 try {
  invoked=0;
  const success=prepare(),successResponse=new Response(),caller=Buffer.from(payload),saved=Buffer.from(caller);success.headers["content-length"]=String(caller.length);
  evidenceHandler(success as never,successResponse as never);success.emit("data",caller);success.emit("end");await new Promise(resolve=>setImmediate(resolve));
  assert.equal(successResponse.status,200);assert.equal(invoked,1);assert.deepEqual(caller,saved,"incoming Node chunks remain caller-owned");detached(success);assert.equal(successResponse.listenerCount("close"),0);assert.equal(successResponse.writes,1);zeroed("success");

  const mismatch=prepare(),mismatchResponse=new Response();mismatch.headers["content-length"]=String(payload.length+1);evidenceHandler(mismatch as never,mismatchResponse as never);mismatch.emit("data",payload);mismatch.emit("end");await new Promise(resolve=>setImmediate(resolve));
  assert.equal(mismatchResponse.status,400);assert.equal(invoked,1);detached(mismatch);zeroed("content-length mismatch");

  const malformed=prepare(),malformedResponse=new Response(),badJson=Buffer.from('{"tuple":');malformed.headers["content-length"]=String(badJson.length);evidenceHandler(malformed as never,malformedResponse as never);malformed.emit("data",badJson);malformed.emit("end");await new Promise(resolve=>setImmediate(resolve));
  assert.equal(malformedResponse.status,400);assert.equal(invoked,1);detached(malformed);zeroed("parse failure");

  for(const terminal of ["error","aborted","premature close"] as const){
   const request=prepare(),response=new Response();evidenceHandler(request as never,response as never);request.emit("data",payload);
   if(terminal==="error")request.emit("error",new Error("synthetic request error"));else if(terminal==="aborted")request.emit("aborted");else request.emit("close");
   request.emit("data",payload);request.emit("end");await new Promise(resolve=>setImmediate(resolve));assert.equal(response.status,0,terminal);assert.equal(invoked,1,terminal);detached(request);zeroed(terminal);
  }

  const disconnected=prepare(),disconnectedResponse=new Response();evidenceHandler(disconnected as never,disconnectedResponse as never);disconnected.emit("data",payload);disconnected.emit("end");
  // routeManagementRequest has called the service, but its promise continuation
  // must not write after the peer closes the response.
  disconnectedResponse.emit("close");disconnected.emit("data",payload);disconnected.emit("end");await new Promise(resolve=>setImmediate(resolve));
  assert.equal(invoked,2);assert.equal(disconnectedResponse.status,0);assert.equal(disconnectedResponse.writes,0);assert.equal(disconnectedResponse.ends,0);detached(disconnected);assert.equal(disconnectedResponse.listenerCount("close"),0);zeroed("response close / late settle");

  const oversized=new DestroyableRequest(),oversizedResponse=new Response(),prefix=Buffer.from("partial");
  oversized.url="/api/v1/native-evidence/prepare";oversized.headers={cookie:`__Host-lanmm_session=${TOKEN}`,origin:"https://manager.test","x-csrf-token":"csrf","content-type":"application/json"};evidenceHandler(oversized as never,oversizedResponse as never);oversized.emit("data",prefix);oversized.emit("data",hugeForOverflow);oversized.emit("end");await new Promise(resolve=>setImmediate(resolve));
  assert.equal(oversizedResponse.status,413);assert.equal(oversized.wasDestroyed,true,"overflow rejection closes instead of indefinitely draining the request");assert.deepEqual(hugeForOverflow,hugeSaved);assert.equal(invoked,2);detached(oversized);zeroed("overflow");
  await new Promise(resolve=>setImmediate(resolve));assert.deepEqual(seenRejection,[]);
 } finally {
  bufferApi.alloc=originalAlloc;bufferApi.concat=originalConcat;process.off("unhandledRejection",onUnhandled);
 }
});

test("only the exact raw target gets the larger HTTP cap",()=>{
 const aliases=["/api/v1/native-evidence/prepare?","/api/v1/native-evidence/prepare?x=1","/api/v1/native-evidence/%70repare","/api/v1/native-evidence/prepare/","http://127.0.0.1/api/v1/native-evidence/prepare"];
 invoked=0;
 for(const url of aliases){const request=prepare(),response=new Response();request.url=url;request.headers["content-length"]=String(MANAGEMENT_BODY_LIMIT+1);evidenceHandler(request as never,response as never);assert.equal(response.status,413,url);assert.equal(response.headers.connection,"close",url);assert.equal(invoked,0,url);}
 const get=new Request(),getResponse=new Response();get.method="GET";get.url="/api/v1/native-evidence/prepare";get.headers["content-length"]=String(MANAGEMENT_BODY_LIMIT+1);evidenceHandler(get as never,getResponse as never);assert.equal(getResponse.status,413);assert.equal(invoked,0);
 const exact=new Request(),exactResponse=new Response();exact.url="/api/v1/native-evidence/prepare";exact.headers={cookie:`__Host-lanmm_session=${TOKEN}`,origin:"https://manager.test","x-csrf-token":"csrf","content-type":"application/json","content-length":String(OWNER_EVIDENCE_PREPARE_BODY_LIMIT+1)};evidenceHandler(exact as never,exactResponse as never);assert.equal(exactResponse.status,413);assert.equal(invoked,0);
});

test("declared rejection destroys input on response close or bounded timeout without draining",()=>{
 class CloseOnlyResponse extends Response {override end(value?:string){this.ends++;this.payload=value??"";this.writableEnded=true;this.emit("close");}}
 class SilentResponse extends Response {override end(){this.ends++;}}
 const savedSetTimeout=globalThis.setTimeout,savedClearTimeout=globalThis.clearTimeout,scheduled:(()=>void)[]=[],cleared:NodeJS.Timeout[]=[],fakeTimer={unref(){}} as unknown as NodeJS.Timeout;
 globalThis.setTimeout=((callback:(...args:any[])=>void,_delay?:number,...args:any[])=>{scheduled.push(()=>callback(...args));return fakeTimer;}) as typeof globalThis.setTimeout;
 globalThis.clearTimeout=((timer:NodeJS.Timeout)=>{cleared.push(timer);}) as typeof globalThis.clearTimeout;
 try {
  const early=new Request(),closed=new CloseOnlyResponse();early.headers["content-length"]=String(MANAGEMENT_BODY_LIMIT+1);handler(early as never,closed as never);
  assert.equal(closed.status,413);assert.equal(early.destroyCalls,1,"close before finish destroys the request exactly once");assert.equal(early.resumed,false);assert.equal(closed.listenerCount("finish"),0);assert.equal(closed.listenerCount("close"),0);assert.equal(scheduled.length,1);assert.equal(cleared.length,1,"early close clears the finite fallback timer");
  const stalled=new Request(),silent=new SilentResponse();stalled.headers["content-length"]=String(MANAGEMENT_BODY_LIMIT+1);handler(stalled as never,silent as never);
  assert.equal(stalled.destroyCalls,0);assert.equal(scheduled.length,2);scheduled[1]!();assert.equal(stalled.destroyCalls,1,"finite fallback destroys if response never finishes or closes");assert.equal(stalled.resumed,false);assert.equal(silent.listenerCount("finish"),0);assert.equal(silent.listenerCount("close"),0);assert.equal(cleared.length,2);
 } finally {globalThis.setTimeout=savedSetTimeout;globalThis.clearTimeout=savedClearTimeout;}
});

test("HTTP raw-header singleton duplicates are rejected case-insensitively",()=>{
 const base:[string,string][]=[["cookie",`__Host-lanmm_session=${TOKEN}`],["origin","https://manager.test"],["x-csrf-token","csrf"],["content-type","application/json"]];
 const duplicated:[string,string][]=[
  ["cookie",`__Host-lanmm_session=${TOKEN}`],["origin","https://manager.test"],["x-csrf-token","csrf"],["content-type","application/json"],
  ["authorization","Bearer a"],["content-encoding","identity"],["content-length","1"],["transfer-encoding","chunked"],
 ];
 for(const [name,value] of duplicated){const request=prepare(),response=new Response();request.rawHeaders=[...base.flatMap(([k,v])=>[k,v]),name,value,name[0]!.toUpperCase()+name.slice(1),value];evidenceHandler(request as never,response as never);assert.equal(response.status,400,name);assert.equal(invoked,0,name);}
 const mixed=new Request(),mixedResponse=new Response();mixed.url="/api/v1/native-evidence/prepare";mixed.rawHeaders=[...base.flatMap(([k,v])=>[k,v]),"content-length","1","transfer-encoding","chunked"];evidenceHandler(mixed as never,mixedResponse as never);assert.equal(mixedResponse.status,400,"content-length plus transfer-encoding is rejected");
});

test("hostile stream chunk shapes are rejected without property traps or attacker-sized allocation",()=>{
 let traps=0,allocations=0;const api=Buffer as unknown as {alloc:(...args:any[])=>Buffer},originalAlloc=api.alloc;
 api.alloc=((...args:any[])=>{allocations++;return originalAlloc(...args);}) as typeof api.alloc;
 try {
  const hostileProxy=new Proxy(Buffer.from(payload),{get(){traps++;throw new Error("must not inspect proxy");}}),accessor=Buffer.from(payload);
  Object.defineProperty(accessor,"byteLength",{get(){traps++;throw new Error("must not invoke accessor");}});
  class ChunkSubclass extends Uint8Array {}
  const shared=new Uint8Array(new SharedArrayBuffer(32)),subclass=new ChunkSubclass(32),large=new Uint8Array(OWNER_EVIDENCE_PREPARE_BODY_LIMIT+1);
  const detached=new Uint8Array(8);structuredClone(detached.buffer,{transfer:[detached.buffer]});
  const hostile:unknown[]=[hostileProxy,accessor,subclass,shared,detached,large];
  for(const chunk of hostile){const request=prepare(),response=new Response();evidenceHandler(request as never,response as never);request.emit("data",chunk);request.emit("end");assert.notEqual(response.status,200);assert.equal(invoked,0);}
  assert.equal(traps,0,"proxy and accessor traps are never invoked");assert.equal(allocations,0,"malformed, detached, shared, subclassed, and oversized views never drive an allocation");
 } finally {api.alloc=originalAlloc;}
});
