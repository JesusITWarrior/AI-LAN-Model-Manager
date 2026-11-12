import type { ControllerConfig, ControllerPathPlan } from "./config.js";
import { createControllerRuntime, type ControllerRuntimeHandle, type RuntimeDependencies } from "./controller-runtime.js";
import { createControllerServer } from "./app.js";
import { createAuthHttpHandler } from "./owner-http.js";
import { createConsoleStaticHandler, type ConsoleStaticOptions } from "./console-static.js";
import { createManagementDependencies } from "./management-runtime.js";
import { createManagementHttpHandler } from "./management-http.js";
import { createRuntimeInferenceHandler, type InferenceRuntimeOptions } from "./inference-runtime.js";
import { createEnrollmentHttpHandler } from "./enrollment-http.js";
import { DiscoveryListener } from "./discovery/listener.js";
import type { OperatorServiceOptions } from "./operator-service.js";
import {createProductionAgentPlane,ensureAgentPlaneMaterial,scheduleAgentPlaneRotation} from "./agent-plane.js";
import { createAllowedOrigins } from "./origin.js";

export type ControllerApplicationErrorCode="ERR_APP_START"|"ERR_APP_LISTEN"|"ERR_APP_STOP"|"ERR_APP_CLOSED";
export class ControllerApplicationError extends Error{readonly code:ControllerApplicationErrorCode;constructor(code:ControllerApplicationErrorCode){super(code);this.name="ControllerApplicationError";this.code=code;}}
export interface ApplicationServer{listen(port:number,host:string,callback:()=>void):unknown;close(callback:(error?:Error)=>void):unknown;once?(event:"error",listener:(error:Error)=>void):unknown;off?(event:"error",listener:(error:Error)=>void):unknown}
export interface SignalSource{on(signal:"SIGINT"|"SIGTERM",listener:()=>void):unknown;off(signal:"SIGINT"|"SIGTERM",listener:()=>void):unknown}
export interface ControllerApplicationOptions{readonly config:ControllerConfig;readonly plan:ControllerPathPlan;readonly consoleStaticOptions?:ConsoleStaticOptions;readonly runtimeDependencies?:RuntimeDependencies;readonly inferenceOptions?:InferenceRuntimeOptions;readonly operatorOptions?:OperatorServiceOptions;readonly ownerEvidence?:boolean;readonly runtimeFactory?:(options:{config:ControllerConfig;plan:ControllerPathPlan;dependencies?:RuntimeDependencies;ownerEvidence?:Readonly<{allowedOrigins:readonly string[];originOptions?:{readonly allowLoopbackHttpDevelopment?:boolean}}>})=>ControllerRuntimeHandle;readonly serverFactory?:()=>ApplicationServer;readonly signalSource?:SignalSource;readonly closeTimeoutMs?:number}
export interface ControllerApplication{readonly runtime:ControllerRuntimeHandle;readonly isStarted:boolean;readonly isClosed:boolean;start():Promise<void>;stop():Promise<void>;close():Promise<void>}

export function createControllerApplication(options:ControllerApplicationOptions):ControllerApplication{
 const makeRuntime=options.runtimeFactory??(value=>createControllerRuntime(value));
 const host=options.config.bindHost.includes(":")?`[${options.config.bindHost}]`:options.config.bindHost;
 const originOptions=Object.freeze({allowLoopbackHttpDevelopment:true} as const);
 const allowedOrigins=createAllowedOrigins([`http://${host}:${options.config.port}`],originOptions);
 const runtime=makeRuntime({config:options.config,plan:options.plan,...(options.runtimeDependencies?{dependencies:options.runtimeDependencies}:{}),...(options.ownerEvidence?{ownerEvidence:{allowedOrigins,originOptions}}:{})});
 const discovery=options.operatorOptions?.discovery??new DiscoveryListener(options.runtimeDependencies?.now?{now:options.runtimeDependencies.now}:{});
 const operatorOptions={...options.operatorOptions,discovery};
 const makeServer=options.serverFactory??(()=>{
  const enrollment={
   begin:async(binding:{candidateId:string;address:string;port:number;protocolMajor:number;protocolMinor:number})=>{
    const candidate=discovery.list().find(value=>value.id===binding.candidateId&&value.address===binding.address&&value.agentPort===binding.port&&value.protocolVersion.major===binding.protocolMajor&&value.protocolVersion.minor===binding.protocolMinor);
    if(!candidate)return null;
    const created=runtime.services.pairing.createAuthorized(candidate);
    if(!created||!runtime.services.pairing.present(created.challengeId))return null;
    return created;
   },
   pairing:runtime.services.pairing,
   certificates:runtime.services.certificates,
  };
  return createControllerServer(
   createManagementHttpHandler(createManagementDependencies(runtime,allowedOrigins,originOptions,operatorOptions,options.runtimeDependencies?.now)),
   createRuntimeInferenceHandler(runtime,{...options.inferenceOptions,...(options.runtimeDependencies?.now?{clock:options.runtimeDependencies.now}:{})}),
   createAuthHttpHandler({owner:runtime.services.owner,sessions:runtime.services.sessions,allowedOrigins,originOptions}),
   createConsoleStaticHandler(options.consoleStaticOptions),
   createEnrollmentHttpHandler(enrollment,options.runtimeDependencies?.now?{clock:()=>Date.parse(options.runtimeDependencies!.now!())}:{}),
  ) as ApplicationServer;
 });
 const signals=options.signalSource,timeout=options.closeTimeoutMs??5000;
 if(!Number.isSafeInteger(timeout)||timeout<1||timeout>30000){runtime.close();throw new ControllerApplicationError("ERR_APP_START");}
 let server:ApplicationServer|null=null,agentServer:ApplicationServer|null=null,stopAgentRotation:(()=>void)|null=null,started=false,closed=false,signalsBound=false,closing:Promise<void>|null=null,stopping:Promise<void>|null=null;
 const signal=()=>{void close();};
 function bind(){if(!signals||signalsBound)return;signals.on("SIGINT",signal);signals.on("SIGTERM",signal);signalsBound=true;}
 function unbind(){if(!signals||!signalsBound)return;signals.off("SIGINT",signal);signals.off("SIGTERM",signal);signalsBound=false;}
 async function start(){if(stopping)await stopping;if(closed)throw new ControllerApplicationError("ERR_APP_CLOSED");if(started)return;let next:ApplicationServer|null=null;try{runtime.start();if(!options.serverFactory&&options.config.discoveryEnabled)discovery.start?.();next=makeServer();await new Promise<void>((resolve,reject)=>{let settled=false;const fail=()=>{if(settled)return;settled=true;next?.off?.("error",fail);reject(new ControllerApplicationError("ERR_APP_LISTEN"));};next!.once?.("error",fail);try{next!.listen(options.config.port,options.config.bindHost,()=>{if(settled)return;settled=true;next?.off?.("error",fail);resolve();});}catch{fail();}});if(options.config.agentPlaneEnabled){runtime.services.certificates.initialize();const material=ensureAgentPlaneMaterial(options.plan.certificateDir,options.config.agentPlaneAdvertisedAddress!);const enrollment={begin:async(binding:{candidateId:string;address:string;port:number;protocolMajor:number;protocolMinor:number})=>{const candidate=discovery.list().find(value=>value.id===binding.candidateId&&value.address===binding.address&&value.agentPort===binding.port&&value.protocolVersion.major===binding.protocolMajor&&value.protocolVersion.minor===binding.protocolMinor);if(!candidate)return null;const created=runtime.services.pairing.createAuthorized(candidate);if(!created||!runtime.services.pairing.present(created.challengeId))return null;return created;},pairing:runtime.services.pairing,certificates:runtime.services.certificates};const enrollmentHandler=createEnrollmentHttpHandler(enrollment,options.runtimeDependencies?.now?{clock:()=>Date.parse(options.runtimeDependencies!.now!())}:{});const plane=createProductionAgentPlane(runtime,material,enrollmentHandler,options.runtimeDependencies?.now);agentServer=plane;await new Promise<void>((resolve,reject)=>{plane.once("error",reject);plane.listen(options.config.agentPlanePort!,options.config.agentPlaneHost!,()=>resolve());});stopAgentRotation=scheduleAgentPlaneRotation(plane,options.plan.certificateDir,options.config.agentPlaneAdvertisedAddress!);}server=next;started=true;bind();}catch(error){
   // start() may already have closed the runtime. Never dereference services
   // after that transition, and never let failed owner cleanup skip listeners.
   try{await shutdownOwners();}catch{/* preserve the original startup error */}finally{
    unbind();stopAgentRotation?.();stopAgentRotation=null;
    await Promise.allSettled([...(agentServer?[closeServer(agentServer,timeout)]:[]),...(next?[closeServer(next,timeout)]:[])]);
    agentServer=null;server=null;try{discovery.stop?.();}catch{}
    try{runtime.close();}catch{/* startup error remains authoritative */}finally{closed=true;started=false;}
   }
   throw error instanceof ControllerApplicationError?error:new ControllerApplicationError("ERR_APP_START");
  }}
 async function shutdownOwners():Promise<void>{
  if(runtime.isClosed)return;
  const services=runtime.services;
  // Invoke both owners in this stack: lifecycle must close admission before
  // stop() returns its promise, not in a later microtask. Still join both when
  // either owner throws synchronously.
  const invoke=(close:()=>Promise<void>)=>{try{return close();}catch(error){return Promise.reject(error);}};
  const results=await Promise.allSettled([invoke(()=>services.inference.shutdown()),invoke(()=>services.lifecycle.shutdown())]);
  if(results.some(result=>result.status==="rejected"))throw new Error("ERR_APP_STOP");
 }

 async function stop():Promise<void>{
  if(stopping)return stopping;
  if(closed)return;
  stopping=(async()=>{
   unbind();const current=server,currentAgent=agentServer;
   server=null;agentServer=null;stopAgentRotation?.();stopAgentRotation=null;started=false;
   const deadline=Date.now()+timeout,remaining=()=>Math.max(1,deadline-Date.now());
   try{
    // Reject new lifecycle submissions and release owned HTTP waits while all
    // repositories and listeners are still alive. Never close DB under a waiter.
    await shutdownOwners();
    await Promise.all([...(currentAgent?[closeServer(currentAgent,remaining())]:[]),...(current?[closeServer(current,remaining())]:[])]);
    try{discovery.stop?.();}catch{}runtime.stop();
   }catch{
    // Cleanup every listener even if an owner rejects its shutdown contract.
    await Promise.allSettled([...(currentAgent?[closeServer(currentAgent,remaining())]:[]),...(current?[closeServer(current,remaining())]:[])]);
    try{discovery.stop?.();}catch{}try{runtime.close();}catch{/* stable application stop error */}finally{closed=true;}
    throw new ControllerApplicationError("ERR_APP_STOP");
   }
  })();
  try{await stopping;}finally{stopping=null;}
 }

 async function close(){if(closing)return closing;closing=(async()=>{if(closed)return;try{await stop();}finally{unbind();runtime.close();closed=true;started=false;server=null;agentServer=null;stopAgentRotation?.();stopAgentRotation=null;}})();return closing;}
 return Object.freeze({get runtime(){return runtime},get isStarted(){return started},get isClosed(){return closed},start,stop,close});
}
function closeServer(server:ApplicationServer,timeout:number):Promise<void>{return new Promise((resolve,reject)=>{let settled=false;const timer=setTimeout(()=>{if(!settled){settled=true;reject(new Error("timeout"));}},timeout);try{server.close(error=>{if(settled)return;settled=true;clearTimeout(timer);error?reject(error):resolve();});}catch(error){if(!settled){settled=true;clearTimeout(timer);reject(error);}}});}
