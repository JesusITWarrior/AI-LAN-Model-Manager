import test from"node:test";import assert from"node:assert/strict";import{createControllerApplication,ControllerApplicationError,type ApplicationServer}from"./controller-application.js";import type{ControllerRuntimeHandle}from"./controller-runtime.js";import{mkdtempSync,rmSync}from"node:fs";import{tmpdir}from"node:os";import{join}from"node:path";import{openControllerDatabase}from"./database.js";import{createControllerRuntime}from"./controller-runtime.js";import type{DatabaseSync}from"node:sqlite";import{OwnerNativeEvidenceCandidateRegistry}from"./owner-native-evidence-candidates.js";function observeEvidenceClose(events:string[]){const proto=OwnerNativeEvidenceCandidateRegistry.prototype as unknown as{close:()=>void},original=proto.close;proto.close=function(){events.push("evidence-close");original.call(this);};return()=>{proto.close=original;};}const config={bindHost:"127.0.0.1",port:7340,inferenceHost:"127.0.0.1",inferencePort:7341,dataDir:"/tmp/lanmm-test",logLevel:"info",discoveryEnabled:false,publicInferenceEnabled:false,tlsRequired:true,mutualTlsRequired:true}as const,plan={rootDir:config.dataDir,databasePath:`${config.dataDir}/controller.sqlite3`,artifactDir:`${config.dataDir}/artifacts`,cacheDir:`${config.dataDir}/cache`,stagingDir:`${config.dataDir}/staging`,quarantineDir:`${config.dataDir}/quarantine`,auditDir:`${config.dataDir}/audit`,certificateDir:`${config.dataDir}/certificates`};function fixture(overrides:{listenFail?:boolean;closeFail?:boolean}={}){const events:string[]=[],listeners=new Map<string,()=>void>(),runtime={services:{inference:{async shutdown(){events.push("inference-shutdown")}},lifecycle:{async shutdown(){events.push("lifecycle-shutdown")}}},start(){events.push("runtime-start")},stop(){events.push("runtime-stop")},close(){events.push("runtime-close")},get isActive(){return false},get isClosed(){return false}}as unknown as ControllerRuntimeHandle,server={once(_e:string,fn:(error:Error)=>void){listeners.set("error",()=>fn(new Error("private listen failure")))},off(){},listen(port:number,host:string,done:()=>void){events.push(`listen:${host}:${port}`);overrides.listenFail?listeners.get("error")?.():done()},close(done:(e?:Error)=>void){events.push("server-close");done(overrides.closeFail?new Error("private"):undefined)}}as unknown as ApplicationServer,signals=new Map<string,()=>void>(),signalSource={on(name:string,fn:()=>void){events.push(`on:${name}`);signals.set(name,fn)},off(name:string){events.push(`off:${name}`);signals.delete(name)}};const app=createControllerApplication({config,plan,runtimeFactory:()=>runtime,serverFactory:()=>server,signalSource:signalSource as never,closeTimeoutMs:100});return{app,events,signals};}
test("starts runtime before exact loopback listener and binds signals",async()=>{const x=fixture();await x.app.start();await x.app.start();assert.deepEqual(x.events,["runtime-start","listen:127.0.0.1:7340","on:SIGINT","on:SIGTERM"]);assert.equal(x.app.isStarted,true);await x.app.close();});test("close removes signals closes listener before runtime and is idempotent",async()=>{const x=fixture();await x.app.start();await Promise.all([x.app.close(),x.app.close()]);assert.deepEqual(x.events.slice(4),["off:SIGINT","off:SIGTERM","inference-shutdown","lifecycle-shutdown","server-close","runtime-stop","runtime-close"]);assert.equal(x.app.isClosed,true);await assert.rejects(x.app.start(),e=>e instanceof ControllerApplicationError&&e.code==="ERR_APP_CLOSED");});test("listen failure closes runtime with redacted stable error",async()=>{const x=fixture({listenFail:true});await assert.rejects(x.app.start(),e=>e instanceof ControllerApplicationError&&e.code==="ERR_APP_LISTEN"&&!e.message.includes("private"));assert.deepEqual(x.events,["runtime-start","listen:127.0.0.1:7340","inference-shutdown","lifecycle-shutdown","server-close","runtime-close"]);});test("stop failure closes runtime and reports stable error",async()=>{const x=fixture({closeFail:true});await x.app.start();await assert.rejects(x.app.stop(),e=>e instanceof ControllerApplicationError&&e.code==="ERR_APP_STOP");assert.ok(x.events.indexOf("server-close")<x.events.indexOf("runtime-close"));});test("signal initiates graceful close without process exit",async()=>{const x=fixture();await x.app.start();x.signals.get("SIGTERM")?.();await new Promise(resolve=>setTimeout(resolve,0));assert.equal(x.app.isClosed,true);assert.ok(x.events.includes("server-close"));});

test("runtime startup already closed never reads services or masks application error",async()=>{
 let runtimeClosed=false,reads=0,stops=0;
 const runtime={start(){runtimeClosed=true;throw new Error("private startup failure");},get isClosed(){return runtimeClosed;},get services(){reads++;throw new Error("ERR_RUNTIME_CLOSED");},close(){runtimeClosed=true;}} as unknown as ControllerRuntimeHandle;
 const app=createControllerApplication({config,plan,runtimeFactory:()=>runtime,operatorOptions:{discovery:{stop(){stops++;}} as never},serverFactory:()=>{throw new Error("unreachable");}});
 await assert.rejects(app.start(),e=>e instanceof ControllerApplicationError&&e.code==="ERR_APP_START");assert.equal(reads,0);assert.equal(stops,1);assert.equal(app.isClosed,true);
});
test("failed owner cleanup preserves listen failure and always closes listener discovery runtime",async()=>{
 const events:string[]=[];let closed=false;
 const runtime={start(){},get isClosed(){return closed;},services:{inference:{async shutdown(){events.push("inference");throw new Error("private cleanup");}},lifecycle:{async shutdown(){events.push("lifecycle");}}},close(){events.push("runtime");closed=true;}} as unknown as ControllerRuntimeHandle;
 const server={listen(){throw new Error("private listen");},close(done:()=>void){events.push("listener");done();}} as unknown as ApplicationServer;
 const app=createControllerApplication({config,plan,runtimeFactory:()=>runtime,serverFactory:()=>server,operatorOptions:{discovery:{stop(){events.push("discovery");}} as never}});
 await assert.rejects(app.start(),e=>e instanceof ControllerApplicationError&&e.code==="ERR_APP_LISTEN");assert.deepEqual(events,["inference","lifecycle","listener","discovery","runtime"]);assert.equal(app.isClosed,true);
});
test("failed shutdown still cleans listener discovery and runtime",async()=>{
 const events:string[]=[];let closed=false;
 const runtime={start(){},get isClosed(){return closed;},services:{inference:{async shutdown(){throw new Error("private cleanup");}},lifecycle:{async shutdown(){}}},close(){closed=true;events.push("runtime");}} as unknown as ControllerRuntimeHandle;
 const server={listen(_p:number,_h:string,done:()=>void){done();},close(done:()=>void){events.push("listener");done();}} as unknown as ApplicationServer;
 const app=createControllerApplication({config,plan,runtimeFactory:()=>runtime,serverFactory:()=>server,operatorOptions:{discovery:{stop(){events.push("discovery");}} as never}});await app.start();await assert.rejects(app.stop(),/ERR_APP_STOP/);assert.deepEqual(events,["listener","discovery","runtime"]);assert.equal(app.isClosed,true);
});

test("application opt-in passes one canonical IPv6 origin policy and dependencies into runtime composition",()=>{
 const x=fixture();let captured:unknown;
 const ipv6Config={...config,bindHost:"::1"};
 const now=()=>"2026-09-27T05:00:00.000Z";
 createControllerApplication({config:ipv6Config,plan:{...plan,rootDir:ipv6Config.dataDir},ownerEvidence:true,runtimeDependencies:{now},runtimeFactory:options=>{captured=options;return x.app.runtime;},serverFactory:()=>({listen(){},close(done){done();}})});
 const composed=captured as {ownerEvidence?:{allowedOrigins:readonly string[];originOptions?:{allowLoopbackHttpDevelopment?:boolean}};dependencies?:{now?:()=>string}};
 assert.deepEqual(composed.ownerEvidence?.allowedOrigins,["http://[::1]:7340"]);
 assert.equal(composed.ownerEvidence?.originOptions?.allowLoopbackHttpDevelopment,true);
 assert.equal(composed.dependencies?.now,now);
 let omitted:unknown;
 createControllerApplication({config,plan,runtimeFactory:options=>{omitted=options;return x.app.runtime;},serverFactory:()=>({listen(){},close(done){done();}})});
 assert.equal("ownerEvidence" in (omitted as object),false,"application opt-in remains absent by default");
});

test("failed application start and stop retire the real runtime evidence graph before database close",async()=>{
 for(const phase of ["start","stop"] as const){
  const root=mkdtempSync(join(tmpdir(),`lanmm-app-evidence-${phase}-`)),appConfig={...config,dataDir:join(root,"controller")},appPlan={rootDir:appConfig.dataDir,databasePath:join(appConfig.dataDir,"controller.sqlite3"),artifactDir:join(appConfig.dataDir,"artifacts"),cacheDir:join(appConfig.dataDir,"cache"),stagingDir:join(appConfig.dataDir,"staging"),quarantineDir:join(appConfig.dataDir,"quarantine"),auditDir:join(appConfig.dataDir,"audit"),certificateDir:join(appConfig.dataDir,"certificates")};
  let runtime:ControllerRuntimeHandle|undefined,dbCloseCount=0,serverCloseCount=0;const signals=new Map<string,()=>void>(),events:string[]=[],restoreEvidenceClose=observeEvidenceClose(events);
  const app=createControllerApplication({config:appConfig,plan:appPlan,ownerEvidence:true,closeTimeoutMs:100,
   runtimeFactory:options=>{runtime=createControllerRuntime(options);return runtime;},
   runtimeDependencies:{openDatabase:path=>{const raw=openControllerDatabase(path);return new Proxy(raw,{get(target,property){if(property==="close")return()=>{events.push("db-close");dbCloseCount++;target.close();};const value=Reflect.get(target,property,target);return typeof value==="function"?value.bind(target):value;}}) as DatabaseSync;}},
   serverFactory:()=>{let onError:((error:Error)=>void)|undefined;return{once(_event,listener){onError=listener;},off(){},listen(_port,_host,done){phase==="start"?onError?.(new Error("private listen")):done();},close(done){serverCloseCount++;done(phase==="stop"?new Error("private close"):undefined);}} as ApplicationServer;},
   signalSource:{on(name,listener){signals.set(name,listener);},off(name){signals.delete(name);}},
  });
  try{
   if(phase==="start")await assert.rejects(app.start(),error=>error instanceof ControllerApplicationError&&error.code==="ERR_APP_LISTEN");
   else{await app.start();await assert.rejects(app.stop(),error=>error instanceof ControllerApplicationError&&error.code==="ERR_APP_STOP");}
   assert.equal(dbCloseCount,1);assert.ok(serverCloseCount>=1);assert.equal(app.isClosed,true);assert.equal(signals.size,0);
   assert.deepEqual(events,["evidence-close","db-close"],`${phase} failure closes actual evidence exactly once before DB`);
  }finally{restoreEvidenceClose();await app.close();rmSync(root,{recursive:true,force:true});}
 }
});
