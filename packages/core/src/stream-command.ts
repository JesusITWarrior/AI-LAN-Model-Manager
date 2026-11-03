/** Local-only command/event contract. No controller transport admits this operation. */
import {commandAuthorizationDigest, parseCommandRequest, parseInferenceChatCommandParams, type CommandRequest, type InferenceChatCommandParams} from "./command.js";

export interface StreamParams {
 readonly schemaVersion:1; readonly chat:InferenceChatCommandParams;
 readonly upstreamFrameBytes:65536; readonly maxEventBytes:number;
 readonly maxTotalEventBytes:number; readonly maxEvents:number;
}
export type StreamCommandRequest=Omit<CommandRequest,"operation"|"params"> & {readonly operation:"inference.chat.stream";readonly params:StreamParams};
export interface StreamChunk {
 readonly id:string; readonly object:"chat.completion.chunk";readonly model:string;
 readonly choices:readonly [{readonly index:0;readonly delta:{readonly role:"assistant";readonly content:string};readonly finish_reason:"stop"|"length"|null}];
 readonly usage?:{readonly prompt_tokens:number;readonly completion_tokens:number;readonly total_tokens:number};
}
export interface StreamEvent {
 readonly schemaVersion:1;readonly hostId:string;readonly jobId:string;readonly requestId:string;
 readonly commandDigest:string;readonly index:number;readonly kind:"chunk"|"succeeded"|"failed"|"cancelled";
 readonly chunk:StreamChunk|null;readonly errorCode:"STREAM_FAILED"|"CANCELLED"|null;
}
const reject=():never=>{throw new Error("ERR_STREAM")};
function exact(value:unknown,keys:readonly string[]):Record<string,any>{
 if(typeof value!=="object"||value===null||Array.isArray(value))return reject();
 const d=Object.getOwnPropertyDescriptors(value),own=Reflect.ownKeys(value);
 if(![Object.prototype,null].includes(Object.getPrototypeOf(value))||own.length!==keys.length||own.some(k=>typeof k!=="string"||!keys.includes(k))||keys.some(k=>!d[k]||!("value" in d[k]!)))return reject();
 return Object.fromEntries(keys.map(k=>[k,d[k]!.value]));
}
function wellFormed(s:string):boolean{return !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(s);}
function canonicalModel(s:string):boolean{return s===s.toLowerCase()&&/^[a-z0-9][a-z0-9._:/-]{0,255}$/.test(s)&&s.split("/").every(v=>v!==""&&!v.startsWith(".")&&!v.endsWith("."));}
function integer(n:unknown,min:number,max:number):n is number{return typeof n==="number"&&Number.isSafeInteger(n)&&n>=min&&n<=max;}
/** Raw boundary only: rejects duplicate keys before JSON.parse loses evidence. */
function strictJSON(raw:Uint8Array,max:number):any {
 if(raw.byteLength>max||(raw[0]===0xef&&raw[1]===0xbb&&raw[2]===0xbf))return reject();const text=new TextDecoder("utf-8",{fatal:true}).decode(raw);
 let i=0;const ws=()=>{while(/[\x20\t\r\n]/.test(text[i]??"x"))i++;};
 const string=():string=>{const start=i++;while(i<text.length){const c=text[i++]!;if(c==='"')return JSON.parse(text.slice(start,i));if(c==='\\')i++;}return reject();};
 const value=(depth:number):void=>{
  if(depth>16)return reject();ws();const c=text[i];
  if(c==="{"){i++;ws();const keys=new Set<string>();if(text[i]==="}"){i++;return;}while(i<text.length){ws();if(text[i]!== '"')return reject();const k=string();if(keys.has(k))return reject();keys.add(k);ws();if(text[i++]!==':')return reject();value(depth+1);ws();const end=text[i++];if(end==='}')return;if(end!==',')return reject();}return reject();}
  if(c==='['){i++;ws();if(text[i]===']'){i++;return;}while(i<text.length){value(depth+1);ws();const end=text[i++];if(end===']')return;if(end!==',')return reject();}return reject();}
  if(c==='"'){const s=string();if(!wellFormed(s))return reject();return;}
  const match=/^(?:true|false|null|-?(?:0|[1-9][0-9]*))/.exec(text.slice(i));if(!match||match[0]==="-0")return reject();i+=match[0].length;
 };
 value(0);ws();if(i!==text.length)return reject();return JSON.parse(text);
}
export function streamAuthorizationDigest(request:StreamCommandRequest):string {
 return commandAuthorizationDigest(request as unknown as CommandRequest);
}
export function parseStreamCommand(raw:Uint8Array):StreamCommandRequest {
 try {
 const r=exact(strictJSON(raw,550000),["requestId","jobId","hostId","operation","idempotencyKey","sequence","deadline","capability","params"]);
 if(r.operation!=="inference.chat.stream")return reject();
 const p=exact(r.params,["schemaVersion","chat","upstreamFrameBytes","maxEventBytes","maxTotalEventBytes","maxEvents"]);
 if(p.schemaVersion!==1||p.upstreamFrameBytes!==65536||!integer(p.maxEventBytes,1024,131072)||!integer(p.maxTotalEventBytes,p.maxEventBytes,1048576)||!integer(p.maxEvents,1,4096)||Buffer.byteLength(JSON.stringify(p))>524288)return reject();
 const chat=parseInferenceChatCommandParams(p.chat);if(!chat.ok||chat.value.requestId!==r.requestId||!canonicalModel(chat.value.model))return reject();
 if(chat.value.messages.some(m=>Buffer.from(m.contentBase64,"base64").toString("base64")!==m.contentBase64))return reject();
 for(const stamp of [r.deadline,r.capability?.expiresAt]){if(typeof stamp!=="string"||Number.isNaN(Date.parse(stamp))||new Date(stamp).toISOString()!==stamp)return reject();}
 // Reuse ordinary authentication grammar without admitting stream into OPS.
 // Re-sign only this validation copy; the original digest is checked below.
 const proxy={...r,operation:"inference.chat",params:p.chat,capability:{...r.capability}} as unknown as CommandRequest;
 (proxy.capability as {requestDigest:string}).requestDigest=commandAuthorizationDigest(proxy);
 if(!parseCommandRequest(proxy).ok||r.capability.targetKind!=="model"||r.capability.targetId!==chat.value.modelId||r.capability.modelId!==chat.value.modelId)return reject();
 const result=r as unknown as StreamCommandRequest;
 if(streamAuthorizationDigest(result)!==result.capability.requestDigest)return reject();
 return structuredClone(result);
 }catch{return reject();}
}
/** Single consumer, fail-closed. finish() rejects ordinary EOF without terminal. */
export class StreamEventValidator {
 private next=0;private total=0;private terminal=false;private invalid=false;
 private readonly request:StreamCommandRequest;
 constructor(request:StreamCommandRequest){this.request=parseStreamCommand(Buffer.from(JSON.stringify(request)));}
 accept(raw:Uint8Array):StreamEvent {
  try {
   const r=this.request,p=r.params;
   if(this.invalid||this.terminal||this.next>=p.maxEvents||raw.byteLength>p.maxTotalEventBytes-this.total)return reject();
   const e=exact(strictJSON(raw,p.maxEventBytes),["schemaVersion","hostId","jobId","requestId","commandDigest","index","kind","chunk","errorCode"]);
   if(e.schemaVersion!==1||e.hostId!==r.hostId||e.jobId!==r.jobId||e.requestId!==r.requestId||e.commandDigest!==r.capability.requestDigest||!integer(e.index,0,4095)||e.index!==this.next)return reject();
   if(e.kind==="chunk"||e.kind==="succeeded"){
    const c=exact(e.chunk,e.kind==="succeeded"?["id","object","model","choices","usage"]:["id","object","model","choices"]);
    if(e.errorCode!==null||c.id!==r.requestId||c.object!=="chat.completion.chunk"||c.model!==p.chat.model||!Array.isArray(c.choices)||c.choices.length!==1)return reject();
    const choice=exact(c.choices[0],["index","delta","finish_reason"]),delta=exact(choice.delta,["role","content"]);
    if(choice.index!==0||delta.role!=="assistant"||typeof delta.content!=="string"||!wellFormed(delta.content))return reject();
    if(e.kind==="chunk"){if(choice.finish_reason!==null)return reject();}else{
     if(!["stop","length"].includes(choice.finish_reason))return reject();
     const u=exact(c.usage,["prompt_tokens","completion_tokens","total_tokens"]);
     if(!integer(u.prompt_tokens,0,Number.MAX_SAFE_INTEGER)||!integer(u.completion_tokens,0,Number.MAX_SAFE_INTEGER-u.prompt_tokens)||!integer(u.total_tokens,0,Number.MAX_SAFE_INTEGER)||u.total_tokens!==u.prompt_tokens+u.completion_tokens)return reject();
    }
   }else if(e.kind==="failed"||e.kind==="cancelled"){
    if(e.chunk!==null||e.errorCode!==(e.kind==="failed"?"STREAM_FAILED":"CANCELLED"))return reject();
   }else return reject();
   this.next++;this.total+=raw.byteLength;this.terminal=e.kind!=="chunk";
   return e as unknown as StreamEvent;
  }catch{this.invalid=true;return reject();}
 }
 finish():void{if(this.invalid||!this.terminal)return reject();}
}
