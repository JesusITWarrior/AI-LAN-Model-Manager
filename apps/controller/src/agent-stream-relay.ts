import {parseCommandResponse, parseStreamCommand, parseStreamWireJSON, StreamEventValidator, type StreamCommandRequest, type StreamEvent} from "@lan-model-manager/core";

export type StreamRelayOutcome="succeeded"|"failed"|"cancelled"|"interrupted"|"deadline";
type Slot={event:StreamEvent;bytes:number;authorized:()=>boolean;resolve:()=>void;reject:(error:Error)=>void};
type Entry={request:StreamCommandRequest;validator:StreamEventValidator;leased:boolean;slot:Slot|null;wake:(()=>void)|null;reading:boolean;terminal:StreamEvent["kind"]|null;outcome:StreamRelayOutcome|null;timer:ReturnType<typeof setTimeout>;resolve:(value:StreamRelayOutcome)=>void};
export interface StreamRelayHandle {
 /** Transfer of one bounded event to the sole consumer is its acceptance point. */
 next(signal:AbortSignal):Promise<StreamEvent|null>;
 readonly outcome:Promise<StreamRelayOutcome>;
 /** Synchronous first-terminal proof, including before promise continuations. */
 readonly settledOutcome:StreamRelayOutcome|null;
 cancel():void;
 /** Required on consumer disconnect/final cleanup; releases all retained bytes. */
 close():void;
}
const failure=()=>new Error("ERR_STREAM_RELAY");
/** Component-only, ephemeral relay. No public submission route or capability issuer.
 * Callers must already own routing/admission/lease authority before opening work.
 * IDs are one-shot for this instance, including failures; no output replay exists.
 */
export class AgentStreamRelay {
 private readonly entries=new Map<string,Entry>();
 private readonly used=new Set<string>();
 private readonly cancellations=new Map<string,{hostId:string;expires:number}>();
 private pruneCancellations():void{for(const [id,value] of this.cancellations)if(this.clock()>=value.expires)this.cancellations.delete(id);}
 private stopped=false;
 constructor(private readonly clock:()=>number=Date.now,private readonly globalLimit=16,private readonly hostLimit=1){
  if(!Number.isSafeInteger(globalLimit)||globalLimit<1||globalLimit>16||!Number.isSafeInteger(hostLimit)||hostLimit<1||hostLimit>1)throw failure();
 }
 open(raw:Uint8Array):StreamRelayHandle {
  this.pruneCancellations();
  const request=parseStreamCommand(raw),now=this.clock(),end=Math.min(Date.parse(request.deadline),Date.parse(request.capability.expiresAt));
  if(this.stopped||!Number.isSafeInteger(now)||end<=now||end-now>300_000||this.used.size+new Set([request.jobId,request.requestId,request.idempotencyKey]).size>4096||this.used.has(request.jobId)||this.used.has(request.requestId)||this.used.has(request.idempotencyKey)||new Set([...this.entries.keys(),...this.cancellations.keys()]).size>=this.globalLimit||[...this.entries.values()].filter(e=>e.request.hostId===request.hostId).length>=this.hostLimit)throw failure();
  const outcome=new Promise<StreamRelayOutcome>(resolve=>{
   const entry:Entry={request,validator:new StreamEventValidator(request),leased:false,slot:null,wake:null,reading:false,terminal:null,outcome:null,timer:setTimeout(()=>this.end(request.jobId,"deadline"),end-now),resolve};
   entry.timer.unref();this.entries.set(request.jobId,entry);
  });
  for(const id of [request.jobId,request.requestId,request.idempotencyKey])this.used.add(id);
  const entry=this.entries.get(request.jobId)!;
  return {get settledOutcome(){return entry.outcome;},next:signal=>this.next(request.jobId,signal),outcome,cancel:()=>this.end(request.jobId,"cancelled"),close:()=>{this.end(request.jobId,"cancelled");this.entries.delete(request.jobId);}};
 }
 /** Destructive lease: never requeue, even on polling disconnect or lost response. */
 busy(hostId:string):boolean{return [...this.entries.values()].some(e=>e.request.hostId===hostId&&e.leased&&e.outcome===null);}
 poll(hostId:string,lease=true):{streamCommand:StreamCommandRequest|null;cancelledJobIds:readonly string[]} {
  this.pruneCancellations();
  const matching=[...this.entries.values()].filter(e=>e.request.hostId===hostId);
  const cancelledJobIds=[...this.cancellations].filter(([,value])=>value.hostId===hostId).map(([id])=>id);
  const entry=lease?matching.find(e=>!e.leased&&e.outcome===null):undefined;
  if(entry){this.check(entry);entry.leased=true;}
  return {streamCommand:entry&&entry.outcome===null?structuredClone(entry.request):null,cancelledJobIds};
 }
 async publish(hostId:string,raw:Uint8Array,signal:AbortSignal,authorized:()=>boolean=()=>true):Promise<void>{
  // Read only routing metadata here; the strict validator below owns all bindings.
  // The HTTP adapter has already preserved/validated the raw bytes before this call.
  let jobId:unknown;try{jobId=parseStreamWireJSON(raw,131072).jobId;}catch{throw failure();}
  const e=typeof jobId==="string"?this.entries.get(jobId):undefined;
  if(!e||e.request.hostId!==hostId||!e.leased)throw failure();
  this.check(e);
  if(e.outcome!==null||e.slot||signal.aborted){this.end(e.request.jobId,"failed");throw failure();}
  let event:StreamEvent;try{event=e.validator.accept(raw);}catch{this.end(e.request.jobId,"failed");throw failure();}
  await new Promise<void>((resolve,reject)=>{
   const abort=()=>{this.check(e);this.end(e.request.jobId,"cancelled");};
   signal.addEventListener("abort",abort,{once:true});
   e.slot={event,bytes:raw.byteLength,authorized,resolve:()=>{signal.removeEventListener("abort",abort);resolve();},reject:error=>{signal.removeEventListener("abort",abort);reject(error);}};
   e.wake?.();
  });
 }
 complete(hostId:string,input:unknown):boolean {
  if(typeof input!=="object"||input===null||Array.isArray(input)||Object.keys(input).length!==2||!("commandDigest" in input)||!("result" in input))return false;
  const parsed=parseCommandResponse(input.result);if(!parsed.ok)return false;
  const r=parsed.value,e=this.entries.get(r.jobId);
  if(!e||input.commandDigest!==e.request.capability.requestDigest||hostId!==e.request.hostId||r.hostId!==hostId||r.requestId!==e.request.requestId||r.sequence!==e.request.sequence||!e.leased)return false;
  this.check(e);
  // Buffered result observations can never substitute for stream events.
  if(r.observation!==null||!["succeeded","failed","cancelled"].includes(r.status)||e.slot)return false;
  if(e.outcome!==null)return e.outcome===r.status;
  const expected=e.terminal;
  if(expected!==null&&expected!==r.status)return false;
  if(r.status==="succeeded"&&expected!=="succeeded")return false;
  this.end(r.jobId,r.status as StreamRelayOutcome);return true;
 }
 private async next(jobId:string,signal:AbortSignal):Promise<StreamEvent|null>{
  const e=this.entries.get(jobId);if(!e)throw failure();
  if(e.reading)throw failure();e.reading=true;
  try{for(;;){
   this.check(e);
   if(signal.aborted){this.end(jobId,"cancelled");throw failure();}
   if(e.slot){const slot=e.slot;if(!slot.authorized()){this.end(jobId,"failed");throw failure();}e.slot=null;if(slot.event.kind!=="chunk"){e.terminal=slot.event.kind;this.end(jobId,slot.event.kind);}slot.resolve();return slot.event;}
   if(e.outcome!==null)return null;
   await new Promise<void>(resolve=>{const wake=()=>{signal.removeEventListener("abort",wake);e.wake=null;resolve();};e.wake=wake;signal.addEventListener("abort",wake,{once:true});});
  }}finally{e.reading=false;}
 }
 private check(e:Entry):void{if(this.clock()>=Math.min(Date.parse(e.request.deadline),Date.parse(e.request.capability.expiresAt)))this.end(e.request.jobId,"deadline");}
 private end(jobId:string,outcome:StreamRelayOutcome):void{
  const e=this.entries.get(jobId);if(!e||e.outcome!==null)return;
  if(e.leased&&outcome!=="succeeded")this.cancellations.set(jobId,{hostId:e.request.hostId,expires:Date.parse(e.request.deadline)+30_000});
  e.outcome=outcome;clearTimeout(e.timer);const slot=e.slot;e.slot=null;slot?.reject(failure());e.wake?.();e.resolve(outcome);
 }
 /** Runtime owner must call before teardown/restart. New instances restore no work. */
 stop():void{this.stopped=true;for(const id of this.entries.keys())this.end(id,"interrupted");this.entries.clear();}
 stats():{streams:number;events:number;bytes:number}{return {streams:this.entries.size,events:[...this.entries.values()].filter(e=>e.slot!==null).length,bytes:[...this.entries.values()].reduce((n,e)=>n+(e.slot?.bytes??0),0)};}
}
