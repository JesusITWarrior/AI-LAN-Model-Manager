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
      ? {kind:"stream" as const,events:(async function*(){yield{id:"one",object:"chat.completion.chunk",model:request.model,choices:[]};})()}
      : {kind:"json" as const,value:{id:"one",object:"chat.completion",model:request.model,choices:[]}}
  });
  return createControllerServer(undefined,createInferenceHttpHandler(async()=>({status:404,headers:{"content-type":"application/json"},body:{error:"not_found"}}),chat));
}

test("HTTP adapter bounds and forwards chat JSON without management cookies",async context=>{const instance=server();instance.listen(0,"127.0.0.1");await once(instance,"listening");context.after(()=>instance.close());const address=instance.address();assert.ok(address&&typeof address==="object");const url=`http://127.0.0.1:${address.port}/v1/chat/completions`,payload={model:"m",messages:[{role:"user",content:"hello"}]};const response=await fetch(url,{method:"POST",headers:{authorization:"Bearer valid","content-type":"application/json"},body:JSON.stringify(payload)});assert.equal(response.status,200);assert.equal((await response.json() as {object:string}).object,"chat.completion");const cookie=await fetch(url,{method:"POST",headers:{authorization:"Bearer valid",cookie:"__Host-session=x","content-type":"application/json"},body:JSON.stringify(payload)});assert.equal(cookie.status,401);});

test("HTTP adapter emits ordered SSE and terminal marker",async context=>{const instance=server(true);instance.listen(0,"127.0.0.1");await once(instance,"listening");context.after(()=>instance.close());const address=instance.address();assert.ok(address&&typeof address==="object");const response=await fetch(`http://127.0.0.1:${address.port}/v1/chat/completions`,{method:"POST",headers:{authorization:"Bearer valid","content-type":"application/json"},body:JSON.stringify({model:"m",messages:[{role:"user",content:"hello"}],stream:true})});assert.equal(response.headers.get("content-type"),"text/event-stream; charset=utf-8");assert.match(await response.text(),/^data: .*\n\ndata: \[DONE\]\n\n$/s);});

test("HTTP adapter rejects excessive declared bodies before routing",async context=>{const instance=server();instance.listen(0,"127.0.0.1");await once(instance,"listening");context.after(()=>instance.close());const address=instance.address();assert.ok(address&&typeof address==="object");const status=await new Promise<number>((resolve,reject)=>{const request=httpRequest({host:"127.0.0.1",port:address.port,path:"/v1/chat/completions",method:"POST",headers:{authorization:"Bearer valid","content-type":"application/json","content-length":"1048577"}},response=>{resolve(response.statusCode??0);response.resume();});request.on("error",reject);request.end();});assert.equal(status,413);});
