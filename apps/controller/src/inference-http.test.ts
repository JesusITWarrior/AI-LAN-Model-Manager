import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { request as httpRequest } from "node:http";
import { createControllerServer } from "./app.js";
import { createChatCompletionsHandler } from "./inference-chat.js";
import { createInferenceHttpHandler } from "./inference-http.js";

const token={tokenId:"token-a",ownerId:"a".repeat(32),label:"test",scopes:["inference:invoke","model:list"],credentialVersion:1,createdAt:"2026-09-28T10:00:00.000Z",lastUsedAt:null,expiresAt:"2026-09-28T12:00:00.000Z",revokedAt:null};
function server(stream=false){
  const tokens={authenticateAuthorization:(value:unknown)=>value==="Bearer valid"?{ok:true,token}:{ok:false,status:401,challenge:"Bearer"},touchAuthorization:()=>true};
  const chat=createChatCompletionsHandler({
    tokens:tokens as never,
    resolve:async model=>({targetId:"internal-target",model}),
    acquireLease:async()=>({release(){}}),
    transport:async request=>stream
      ? {kind:"stream" as const,events:(async function*(){yield{id:"one",object:"chat.completion.chunk",model:request.model,choices:[{index:0,delta:{role:"assistant",content:"fixture"},finish_reason:"stop"}],usage:{prompt_tokens:1,completion_tokens:1,total_tokens:2}};})()}
      : {kind:"json" as const,value:{id:"one",object:"chat.completion",model:request.model,choices:[]}}
  });
  return createControllerServer(undefined,createInferenceHttpHandler(async()=>({status:404,headers:{"content-type":"application/json"},body:{error:"not_found"}}),chat));
}

test("HTTP adapter bounds and forwards chat JSON without management cookies",async context=>{const instance=server();instance.listen(0,"127.0.0.1");await once(instance,"listening");context.after(()=>instance.close());const address=instance.address();assert.ok(address&&typeof address==="object");const url=`http://127.0.0.1:${address.port}/v1/chat/completions`,payload={model:"m",messages:[{role:"user",content:"hello"}]};const response=await fetch(url,{method:"POST",headers:{authorization:"Bearer valid","content-type":"application/json"},body:JSON.stringify(payload)});assert.equal(response.status,200);assert.equal((await response.json() as {object:string}).object,"chat.completion");const cookie=await fetch(url,{method:"POST",headers:{authorization:"Bearer valid",cookie:"__Host-session=x","content-type":"application/json"},body:JSON.stringify(payload)});assert.equal(cookie.status,401);});

test("HTTP adapter emits ordered SSE and terminal marker",async context=>{const instance=server(true);instance.listen(0,"127.0.0.1");await once(instance,"listening");context.after(()=>instance.close());const address=instance.address();assert.ok(address&&typeof address==="object");const response=await fetch(`http://127.0.0.1:${address.port}/v1/chat/completions`,{method:"POST",headers:{authorization:"Bearer valid","content-type":"application/json"},body:JSON.stringify({model:"m",messages:[{role:"user",content:"hello"}],stream:true})});assert.equal(response.headers.get("content-type"),"text/event-stream; charset=utf-8");assert.match(await response.text(),/^data: .*\n\ndata: \[DONE\]\n\n$/s);});

test("HTTP adapter rejects excessive declared bodies before routing",async context=>{const instance=server();instance.listen(0,"127.0.0.1");await once(instance,"listening");context.after(()=>instance.close());const address=instance.address();assert.ok(address&&typeof address==="object");const status=await new Promise<number>((resolve,reject)=>{const request=httpRequest({host:"127.0.0.1",port:address.port,path:"/v1/chat/completions",method:"POST",headers:{authorization:"Bearer valid","content-type":"application/json","content-length":"1048577"}},response=>{resolve(response.statusCode??0);response.resume();});request.on("error",reject);request.end();});assert.equal(status,413);});

test("HTTP stream failure aborts transport and never emits a success marker",async context=>{
 let upstreamSignal!:AbortSignal,released=0;
 const chat=createChatCompletionsHandler({tokens:{authenticateAuthorization:()=>({ok:true,token}),touchAuthorization:()=>true} as never,resolve:async model=>({targetId:"fixture-target",model}),acquireLease:async()=>({release(){released++;}}),transport:async input=>{upstreamSignal=input.signal;return{kind:"stream",events:(async function*(){yield{id:"fixture",object:"chat.completion.chunk",model:input.model,choices:[{index:0,delta:{role:"assistant",content:"fixture"},finish_reason:null}]};throw new Error("private provider diagnostic");})()};}});
 const instance=createControllerServer(undefined,createInferenceHttpHandler(async()=>({status:404,headers:{},body:{}}),chat));instance.listen(0,"127.0.0.1");await once(instance,"listening");context.after(()=>instance.close());const address=instance.address();assert.ok(address&&typeof address==="object");
 const response=await fetch(`http://127.0.0.1:${address.port}/v1/chat/completions`,{method:"POST",headers:{authorization:"Bearer fixture","content-type":"application/json"},body:JSON.stringify({model:"fixture",messages:[{role:"user",content:"fixture"}],stream:true})});
 const text=await response.text();assert.match(text,/upstream_error/);assert.equal(text.includes("[DONE]"),false);assert.equal(text.includes("private provider diagnostic"),false);assert.equal(upstreamSignal.aborted,true);assert.equal(released,1);
});

test("HTTP owner shutdown joins idle upload and lazy blocked read before teardown",async()=>{
 let shutdown:(()=>Promise<void>)|undefined,closed=0;
 const chat=createChatCompletionsHandler({tokens:{authenticateAuthorization:()=>({ok:true,token}),touchAuthorization:()=>true} as never,resolve:async model=>({targetId:"internal-target",model}),acquireLease:async()=>({release(){closed++;}}),transport:async request=>({kind:"stream",events:{async *[Symbol.asyncIterator](){await new Promise<void>(resolve=>{if(request.signal.aborted)resolve();else request.signal.addEventListener("abort",()=>resolve(),{once:true});});}}})});
 const s=createControllerServer(undefined,createInferenceHttpHandler(async()=>({status:404,headers:{},body:{}}),chat,close=>{shutdown=close;}));s.listen(0,"127.0.0.1");await once(s,"listening");const a=s.address();assert.ok(a&&typeof a==="object");
 const partial=httpRequest({host:"127.0.0.1",port:a.port,path:"/v1/chat/completions",method:"POST",headers:{"content-type":"application/json"}});partial.on("error",()=>{});partial.write("{");
 const active=httpRequest({host:"127.0.0.1",port:a.port,path:"/v1/chat/completions",method:"POST",headers:{authorization:"Bearer valid","content-type":"application/json"}});active.on("error",()=>{});active.end(JSON.stringify({model:"example/model",messages:[{role:"user",content:"synthetic"}],stream:true}));
 await new Promise(r=>setTimeout(r,25));await shutdown!();assert.equal(closed,1);s.closeAllConnections();await new Promise<void>(r=>s.close(()=>r()));
});

test("real public HTTP writable backpressure stops iterator demand until drain, without detached pump",async()=>{
 const {createServer}=await import("node:http");let reads=0,releases=0,unblock!:()=>void,blocked!:Promise<void>;let sawBlocked!:()=>void;blocked=new Promise<void>(r=>{sawBlocked=r;});
 const chat=createChatCompletionsHandler({tokens:{authenticateAuthorization:()=>({ok:true,token}),touchAuthorization:()=>true} as never,resolve:async model=>({targetId:"internal-target",model}),acquireLease:async()=>({release(){releases++;}}),transport:async input=>({kind:"stream",events:{async *[Symbol.asyncIterator](){for(let i=0;i<3;i++){reads++;yield{id:"bounded",object:"chat.completion.chunk",model:input.model,choices:[{index:0,delta:{role:"assistant",content:`part-${i}`},finish_reason:i===2?"stop":null}],...(i===2?{usage:{prompt_tokens:1,completion_tokens:2,total_tokens:3}}:{})};}}}})});
 const handler=createInferenceHttpHandler(async()=>({status:404,headers:{},body:{}}),chat),s=createServer((req,res)=>{
  // Deterministic writable pressure at the actual HTTP boundary; retain the
  // real socket/write path, but hold the first drain until the slow client test
  // explicitly permits further demand.
  const write=res.write.bind(res),emit=res.emit.bind(res);let held=true,first=true;
  res.emit=((event:string,...args:unknown[])=>event==="drain"&&held?false:emit(event,...args)) as typeof res.emit;
  unblock=()=>{held=false;emit("drain");};
  res.write=((...args:Parameters<typeof res.write>)=>{const accepted=write(...args);if(first){first=false;sawBlocked();return false;}return accepted;}) as typeof res.write;
  handler(req,res);
 });s.listen(0,"127.0.0.1");await once(s,"listening");const a=s.address();assert.ok(a&&typeof a==="object");
 try{const response=fetch(`http://127.0.0.1:${a.port}/v1/chat/completions`,{method:"POST",headers:{authorization:"Bearer valid","content-type":"application/json",connection:"close"},body:JSON.stringify({model:"fixture",messages:[{role:"user",content:"synthetic"}],stream:true})});await blocked;await new Promise(r=>setTimeout(r,60));assert.equal(reads,1);unblock();const body=await(await response).text();assert.equal(reads,3);assert.match(body,/part-0/);assert.match(body,/part-1/);assert.match(body,/usage/);assert.match(body,/\[DONE\]/);assert.equal(releases,1);
 }finally{unblock?.();s.closeAllConnections();await new Promise<void>(r=>s.close(()=>r()));}
});
