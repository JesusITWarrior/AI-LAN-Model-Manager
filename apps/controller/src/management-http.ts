import { types } from "node:util";
import type { IncomingMessage, ServerResponse } from "node:http";
import { MANAGEMENT_BODY_LIMIT, OWNER_EVIDENCE_PREPARE_BODY_LIMIT, routeManagementRequest, type ManagementApiDependencies, type ManagementHttpResponse } from "./management-api.js";

function send(response:ServerResponse,result:ManagementHttpResponse):void{if(response.headersSent||response.destroyed||response.writableEnded)return;for(const [key,value] of Object.entries(result.headers))response.setHeader(key,value);response.writeHead(result.status);response.end(JSON.stringify(result.body));}
function closeAfterReject(request:IncomingMessage,response:ServerResponse,result:ManagementHttpResponse):void{
 try{if(!response.headersSent)response.setHeader("connection","close");}catch{/* destroy the input even if the response rejects the close header */}
 let settled=false,timer:NodeJS.Timeout|undefined;
 const close=()=>{
  if(settled)return;settled=true;
  response.off?.("finish",close);response.off?.("close",close);
  if(timer)clearTimeout(timer);
  if(typeof request.destroy==="function")request.destroy();else request.socket?.destroy();
 };
 if(!response.destroyed&&!response.writableEnded&&typeof response.once==="function"){
  response.once("finish",close);response.once("close",close);timer=setTimeout(close,1000);timer.unref();
 }else close();
 try{send(response,result);}catch{close();}
}
function simple(status:number,code:string,message:string):ManagementHttpResponse{return Object.freeze({status,headers:Object.freeze({"content-type":"application/json; charset=utf-8","cache-control":"no-store"}),body:Object.freeze({ok:false,error:Object.freeze({code,message})})});}
const singleton=new Set(["content-length","transfer-encoding","content-type","content-encoding","cookie","origin","x-csrf-token","authorization"]);
const exactTarget=(request:IncomingMessage)=>request.method==="POST"&&request.url==="/api/v1/native-evidence/prepare";
function rawHeaderMap(request:IncomingMessage,prepare:boolean,limit:number):{headers:Record<string,string>;error:"bad"|"media"|"too-large"|null;length:number|null}{
 const pairs:Array<[string,string]>=[];const raw=request.rawHeaders;
 if(Array.isArray(raw)&&raw.length){if(raw.length%2)return{headers:{},error:"bad",length:null};for(let i=0;i<raw.length;i+=2){const n=raw[i],v=raw[i+1];if(typeof n!=="string"||typeof v!=="string")return{headers:{},error:"bad",length:null};pairs.push([n,v]);}}
 else for(const [name,value] of Object.entries(request.headers)){if(value===undefined)continue;if(Array.isArray(value))for(const v of value)pairs.push([name,v]);else pairs.push([name,value]);}
 const headers=Object.create(null) as Record<string,string>,counts=new Map<string,number>();
 for(const [name,value] of pairs){if(!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)||/[\r\n\0]/.test(value))return{headers:{},error:"bad",length:null};const key=name.toLowerCase();counts.set(key,(counts.get(key)??0)+1);if(singleton.has(key)&&counts.get(key)!==1)return{headers:{},error:"bad",length:null};if(key in headers)return{headers:{},error:"bad",length:null};headers[key]=value;}
 if(headers["content-length"]!==undefined&&headers["transfer-encoding"]!==undefined)return{headers,error:"bad",length:null};
 if(headers["transfer-encoding"]!==undefined&&headers["transfer-encoding"].trim().toLowerCase()!=="chunked")return{headers,error:"bad",length:null};
 if(prepare&&headers["content-encoding"]!==undefined)return{headers,error:"media",length:null};
 if(headers["content-length"]!==undefined&&!/^\d+$/.test(headers["content-length"]))return{headers,error:"too-large",length:null};
 const length=headers["content-length"]===undefined?null:Number(headers["content-length"]);if(length!==null&&(!Number.isSafeInteger(length)||length>limit))return{headers,error:"too-large",length};
 const contentType=prepare?headers["content-type"]:undefined;
 if(prepare&&contentType===undefined)return{headers,error:"media",length};
 if(prepare&&contentType!==undefined){const parts=contentType.split(";");if(parts.shift()?.trim().toLowerCase()!=="application/json")return{headers,error:"media",length};let charset=0;for(const part of parts){const m=/^\s*charset\s*=\s*(?:"([^"]*)"|([^\s;]+))\s*$/i.exec(part);if(!m||++charset>1||((m[1]??m[2]??"").toLowerCase()!=="utf-8"))return{headers,error:"media",length};}}
 return{headers,error:null,length};
}
const byteLengthGetter=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype),"byteLength")!.get!;
const byteOffsetGetter=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype),"byteOffset")!.get!;
const bufferGetter=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype),"buffer")!.get!;
function erase(chunks:Buffer[],raw:Buffer|null):void{for(const chunk of chunks)chunk.fill(0);chunks.length=0;raw?.fill(0);}
/** Listener-free HTTP seam; Node owns wire framing and this adapter owns only copied body bytes. */
export function createManagementHttpHandler(deps:ManagementApiDependencies):(request:IncomingMessage,response:ServerResponse)=>void{
 return (request,response)=>{
  const prepare=exactTarget(request),limit=prepare?OWNER_EVIDENCE_PREPARE_BODY_LIMIT:MANAGEMENT_BODY_LIMIT,parsedHeaders=rawHeaderMap(request,prepare,limit);
  if(parsedHeaders.error){const status=parsedHeaders.error==="media"?415:parsedHeaders.error==="too-large"?413:400;closeAfterReject(request,response,simple(status,parsedHeaders.error==="media"?"UNSUPPORTED_MEDIA_TYPE":parsedHeaders.error==="too-large"?"PAYLOAD_TOO_LARGE":"INVALID_REQUEST",parsedHeaders.error==="media"?"JSON content type required.":parsedHeaders.error==="too-large"?"Request body too large.":"Invalid request."));return;}
  const chunks:Buffer[]=[];let bytes=0,terminal=false,ended=false,raw:Buffer|null=null;
  const cleanup=()=>{if(terminal)return;terminal=true;erase(chunks,raw);raw=null;request.off("data",onData);request.off("end",onEnd);request.off("error",onError);request.off("aborted",onAbort);request.off("close",onClose);response.off?.("close",onResponseClose);};
  const fail=(status=400,code="INVALID_REQUEST",text="Invalid request.")=>{if(terminal)return;cleanup();send(response,simple(status,code,text));};
  const onData=(chunk:unknown)=>{
   if(terminal)return;
   if(types.isProxy(chunk)||!types.isUint8Array(chunk)){cleanup();closeAfterReject(request,response,simple(413,"PAYLOAD_TOO_LARGE","Request body too large."));return;}
   let size:number,source:Uint8Array;try{const prototype=Object.getPrototypeOf(chunk);if(prototype!==Uint8Array.prototype&&prototype!==Buffer.prototype)throw new TypeError();if(["buffer","byteLength","byteOffset",Symbol.iterator].some(key=>Object.getOwnPropertyDescriptor(chunk,key)!==undefined))throw new TypeError();size=Reflect.apply(byteLengthGetter,chunk,[]) as number;const backing=Reflect.apply(bufferGetter,chunk,[]) as ArrayBuffer,offset=Reflect.apply(byteOffsetGetter,chunk,[]) as number;if(!types.isArrayBuffer(backing))throw new TypeError();source=new Uint8Array(backing,offset,size);}catch{fail();return;}
   if(size>limit-bytes){cleanup();closeAfterReject(request,response,simple(413,"PAYLOAD_TOO_LARGE","Request body too large."));return;}
   let copy:Buffer;try{copy=Buffer.alloc(size);Uint8Array.prototype.set.call(copy,source);}catch{fail();return;}bytes+=size;chunks.push(copy);
  };
  const onError=()=>{cleanup();};const onAbort=()=>{cleanup();};const onClose=()=>{if(!ended)cleanup();};const onResponseClose=()=>{if(!response.writableEnded)cleanup();};
  const onEnd=()=>{
   if(terminal)return;ended=true;if(parsedHeaders.length!==null&&bytes!==parsedHeaders.length){fail();return;}
   raw=Buffer.concat(chunks,bytes);
   const requestInput=prepare?{method:request.method??"",url:request.url??"",headers:parsedHeaders.headers,rawBodyBytes:raw}:{method:request.method??"",url:request.url??"",headers:parsedHeaders.headers,body:raw.toString("utf8")};
   void routeManagementRequest(deps,requestInput).then(result=>{if(!terminal)send(response,result);},()=>{if(!terminal)send(response,simple(400,"INVALID_REQUEST","Invalid request."));}).finally(cleanup);
  };
  request.on("data",onData);request.on("end",onEnd);request.on("error",onError);request.on("aborted",onAbort);request.on("close",onClose);response.on?.("close",onResponseClose);
 };
}
