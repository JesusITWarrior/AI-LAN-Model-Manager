import type {StreamChunk} from "@lan-model-manager/core";
import type { ChatDependencies, ChatUpstreamRequest } from "./inference-chat.js";
import type { RemoteInferenceService } from "./remote-inference.js";

/** No queue, cache, persistent command store or second admission lease. The
 * inference owner alone acquires and settles the authoritative execution lease. */
export function createRemoteInferenceChat(service:RemoteInferenceService):Omit<ChatDependencies,"tokens"|"rateLimit"> {
 return {
  async resolve(model,signal,context){if(signal.aborted)return null;const selected=service.select(context,model),target=Object.freeze({targetId:selected.modelId,model:selected.model});return target;},
  async acquireLease(){return {release(){/* execution owner settles the only lease */}};},
  async transport(request:ChatUpstreamRequest){
   // Resolve again immediately before dispatch; no client-supplied target binding
   // or stale selection survives an asynchronous adapter boundary.
   if(!request.context)throw new Error("ERR_REMOTE_INFERENCE");
   const selected=service.select(request.context,request.model);
   if(selected.modelId!==request.targetId)throw new Error("ERR_REMOTE_INFERENCE");
   const handle=service.open(request.context,selected,request,request.signal);
   let ended=false,claimed=false;
   const events:AsyncIterable<unknown>={ [Symbol.asyncIterator](){if(claimed)throw new Error("ERR_REMOTE_INFERENCE");claimed=true;return {
    async next(){if(ended)return {done:true,value:undefined};const event=await handle.next(request.signal);if(!event||event.kind==="failed"||event.kind==="cancelled"){ended=true;handle.close();throw new Error("ERR_REMOTE_INFERENCE");}if(event.kind==="succeeded"){if(handle.settledOutcome!=="succeeded")throw new Error("ERR_REMOTE_INFERENCE");ended=true;}return {done:false,value:event.chunk};},
    async return(){ended=true;handle.close();return {done:true,value:undefined};},
    async throw(){ended=true;handle.close();throw new Error("ERR_REMOTE_INFERENCE");},
   };}};
   if(request.stream)return {kind:"stream",events};
   // Only the nonstream request performs bounded ephemeral aggregation. Relay
   // already validates exact chunks, ordering, usage and total event budget.
   let content="",bytes=0,terminal:StreamChunk|null=null;
   try{for await(const value of events){const chunk=value as StreamChunk,part=chunk.choices[0].delta.content;bytes+=Buffer.byteLength(part);if(bytes>262144)throw new Error("ERR_REMOTE_INFERENCE");content+=part;if(chunk.usage)terminal=chunk;}
    if(!terminal||handle.settledOutcome!=="succeeded"||request.signal.aborted)throw new Error("ERR_REMOTE_INFERENCE");
    return {kind:"json",value:{id:terminal.id,object:"chat.completion",model:request.model,choices:[{index:0,message:{role:"assistant",content},finish_reason:terminal.choices[0].finish_reason}],usage:terminal.usage}};
   }finally{content="";handle.close();}
  },
 };
}
