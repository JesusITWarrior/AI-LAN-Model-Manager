import {isIP} from "node:net";
import {createHash} from "node:crypto";
import type {IncomingMessage,ServerResponse} from "node:http";
import type {TLSSocket} from "node:tls";
import {canonicalCertificateSerial,sameCertificateSerial,parseStreamWireJSON} from "@lan-model-manager/core";
import type {CertificateRepository} from "./certificate-repository.js";
import type {ControllerTransport} from "./transport/controller-transport.js";
import type {AgentStreamAdapter} from "./agent-stream-relay.js";

export function canonicalAgentPeerAddress(address:string|undefined):string|null{
 if(!address)return null;
 const mapped=/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);if(mapped&&isIP(mapped[1]!)===4)return mapped[1]!;
 if(isIP(address)===4)return address;
 if(isIP(address)===6&&!address.includes("%")){const normalized=new URL(`http://[${address}]/`).hostname.slice(1,-1);const hex=/^::ffff:([a-f0-9]{1,4}):([a-f0-9]{1,4})$/.exec(normalized);if(hex){const a=parseInt(hex[1]!,16),b=parseInt(hex[2]!,16);return `${a>>>8}.${a&255}.${b>>>8}.${b&255}`;}return normalized;}
 return null;
}
const EVENT_PATH="/agent/v1/streams/event",RESULT_PATH="/agent/v1/streams/result";
const BODY_LIMIT=180_224,MAX_RATE_KEYS=2048;
/** Opt-in component adapter. Its event budget is independent of fleet's 120/min.
 * At most 16 HTTP bodies/waits globally, two per certificate, one relay slot/request.
 * All status/acks are withheld until consumer acceptance; disconnect cancels work.
 */
export function createAgentStreamHttpHandler(deps:{relay:AgentStreamAdapter;transport:ControllerTransport;certificates:CertificateRepository},clock:()=>number=Date.now):((req:IncomingMessage,res:ServerResponse)=>boolean)&{stats:()=>{inflight:number;retainedBytes:number};shutdown:()=>Promise<void>} {
 const rates=new Map<string,{count:number;reset:number}>(),active=new Map<string,number>();let inflight=0,retainedBytes=0,closed=false;const owners=new Set<()=>void>();const joins=new Set<Promise<void>>();
 const handler=(req:IncomingMessage,res:ServerResponse)=>{
  const message=req.url===EVENT_PATH?"agent.stream.event":req.url===RESULT_PATH?"agent.stream.result":null;
  if(!message)return false;
  const send=(status:number)=>{if(res.destroyed||res.headersSent)return;res.writeHead(status,{"content-type":"application/json","cache-control":"no-store","x-content-type-options":"nosniff"});res.end(status===200?'{"ok":true}':'{"ok":false,"error":"ERR_STREAM_RELAY"}');};
  const reject=(status:number)=>{res.setHeader("connection","close");res.once("finish",()=>req.destroy());send(status);const timer=setTimeout(()=>req.destroy(),100);timer.unref();req.once("close",()=>clearTimeout(timer));return true;};
  if(closed)return reject(503);
  if(req.method!=="POST"||req.headers["content-type"]!=="application/json")return reject(415);
  const socket=req.socket as TLSSocket,peer=socket.getPeerCertificate?.();
  if(!socket.authorized||socket.getProtocol?.()!=="TLSv1.3"||!peer?.raw)return reject(401);
  const fingerprint=createHash("sha256").update(peer.raw).digest("hex"),serial=canonicalCertificateSerial(peer.serialNumber?.toUpperCase());
  if(serial===null)return reject(401);
  const trusted=()=>{const cert=deps.certificates.getBySerial(serial,fingerprint);return cert?.status==="active"&&Date.parse(cert.notBefore)<=clock()&&Date.parse(cert.notAfter)>clock()&&canonicalAgentPeerAddress(socket.remoteAddress)!==null&&canonicalAgentPeerAddress(socket.remoteAddress)===canonicalAgentPeerAddress(cert.binding.address)?cert:null;};
  if(!trusted())return reject(401);
  const now=clock();if(!Number.isSafeInteger(now)||now<0)return reject(500);
  let rate=rates.get(fingerprint);if(!rate||now>=rate.reset){if(!rate&&rates.size>=MAX_RATE_KEYS)return reject(429);rate={count:0,reset:now+60_000};rates.set(fingerprint,rate);}
  // 4096 accepted events per command, two concurrent streams plus bounded overhead.
  if(rate.count++>=8256||inflight>=16||(active.get(fingerprint)??0)>=2)return reject(429);
  const length=req.headers["content-length"];
  if(Array.isArray(length)||length!==undefined&&(!/^\d+$/.test(length)||Number(length)>BODY_LIMIT))return reject(413);
  let joined!:()=>void;const done=new Promise<void>(resolve=>{joined=resolve;});joins.add(done);
  inflight++;active.set(fingerprint,(active.get(fingerprint)??0)+1);
  const controller=new AbortController();let finished=false,total=0,processing=false;const chunks:Buffer[]=[];
  let destroyTimer:ReturnType<typeof setTimeout>|undefined;
  const clearBody=()=>{retainedBytes-=total;total=0;chunks.length=0;};
  const detachUpload=()=>{req.removeListener("data",data);req.removeListener("end",end);};
  const release=()=>{if(finished)return;finished=true;clearTimeout(bodyTimer);if(destroyTimer)clearTimeout(destroyTimer);clearBody();detachUpload();req.removeListener("error",error);req.removeListener("aborted",disconnect);res.removeListener("close",disconnect);res.removeListener("finish",destroyUpload);owners.delete(disconnect);if(!processing){joins.delete(done);joined();}inflight--;const n=(active.get(fingerprint)??1)-1;if(n)active.set(fingerprint,n);else active.delete(fingerprint);};
  const disconnect=()=>{controller.abort();if(!req.complete)req.destroy();if(!res.writableEnded)res.destroy();release();};
  const destroyUpload=()=>{req.destroy();release();};
  const terminate=(status:number)=>{controller.abort();clearTimeout(bodyTimer);clearBody();detachUpload();res.setHeader("connection","close");res.once("finish",destroyUpload);destroyTimer=setTimeout(destroyUpload,100);destroyTimer.unref();send(status);};
  const error=()=>{controller.abort();req.destroy();release();};
  const bodyTimer=setTimeout(()=>terminate(408),10_000);bodyTimer.unref();
  const data=(chunk:Buffer)=>{if(finished)return;if(total+chunk.byteLength>BODY_LIMIT){terminate(413);return;}const copy=Buffer.from(chunk);chunks.push(copy);total+=copy.byteLength;retainedBytes+=copy.byteLength;};
  const end=()=>{clearTimeout(bodyTimer);detachUpload();if(finished)return;processing=true;void(async()=>{
   try{
    const rawBody=Buffer.concat(chunks,total);clearBody();
    const input=parseStreamWireJSON(rawBody,BODY_LIMIT);
    if(input.messageType!==message||input.certFingerprint!==fingerprint||!sameCertificateSerial(input.certSerial,serial))throw Error();
    const accepted=deps.transport.accept(input),cert=trusted();
    if(!accepted.ok||!cert||accepted.envelope.hostId!==cert.binding.candidateId)throw Error();
    if(message==="agent.stream.event"){
     const payload=accepted.envelope.payload as any;
     if(typeof payload!=="object"||payload===null||Array.isArray(payload)||Object.keys(payload).length!==1||typeof payload.eventBase64!=="string"||payload.eventBase64.length>174764)throw Error();
     const raw=Buffer.from(payload.eventBase64,"base64");if(raw.toString("base64")!==payload.eventBase64)throw Error();
     // Validate raw document evidence before any JSON.parse in relay routing.
     parseStreamWireJSON(raw,131072);
     await deps.relay.publish(cert.binding.candidateId,raw,controller.signal,()=>trusted()?.binding.candidateId===cert.binding.candidateId);
    }else if(!deps.relay.complete(cert.binding.candidateId,accepted.envelope.payload))throw Error();
    send(200);
   }catch{send(400);}finally{release();joins.delete(done);joined();}
  })();};
  owners.add(disconnect);res.once("close",disconnect);req.once("error",error);req.once("aborted",disconnect);req.on("data",data);req.once("end",end);
  return true;
 };
 return Object.assign(handler,{stats:()=>({inflight,retainedBytes}),shutdown:async()=>{closed=true;const pending=[...joins];for(const close of [...owners])close();await Promise.allSettled(pending);}});
}
