import assert from "node:assert/strict";
import test from "node:test";
import {randomBytes,X509Certificate} from "node:crypto";
import {ensureAgentPlaneMaterial} from "./agent-plane.js";
import {execFileSync,spawn} from "node:child_process";
import {chmodSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join,resolve} from "node:path";
import {createServer,request as httpRequest} from "node:http";
import {request as httpsRequest} from "node:https";
import {once} from "node:events";
import {connect} from "node:net";
import {signTransportSignedEnvelope} from "@lan-model-manager/core";
import {createControllerApplication} from "./controller-application.js";
import {createControllerRuntime} from "./controller-runtime.js";
import {parseTransportParsedLeaf} from "./transport/trust-resolver.js";
import {buildTransportNativeSigner} from "./transport/transport-signer.js";
const delay=(ms:number)=>new Promise(r=>setTimeout(r,ms));
async function port(){const s=createServer();s.listen(0,"127.0.0.1");await once(s,"listening");const a=s.address();assert.ok(a&&typeof a==="object");await new Promise<void>(r=>s.close(()=>r()));return a.port;}

for(const serialHex of ["0111111111111111111111111111111111111111","0ABCDEF123456789111111111111111111111111","1111111111111111111111111111111111111111"]){
test(`default production application joins signed polls, partial uploads and stream; real serial ${serialHex}`,{timeout:30000},async()=>{
 const root=mkdtempSync(join(tmpdir(),"lanmm-app-inference-")),publicPort=await port(),agentPort=await port();
 const config={bindHost:"127.0.0.1",port:publicPort,inferenceHost:"127.0.0.1",inferencePort:7341,dataDir:root,logLevel:"info",discoveryEnabled:false,publicInferenceEnabled:false,tlsRequired:true,mutualTlsRequired:true,agentPlaneEnabled:true,agentPlaneHost:"127.0.0.1",agentPlanePort:agentPort,agentPlaneAdvertisedAddress:"127.0.0.1"} as const;
 const plan={rootDir:root,databasePath:join(root,"controller.db"),artifactDir:join(root,"artifacts"),cacheDir:join(root,"cache"),stagingDir:join(root,"staging"),quarantineDir:join(root,"quarantine"),auditDir:join(root,"audit"),certificateDir:join(root,"certificates")};
 let dbClosed=false,afterClose=0;
 const runtime=createControllerRuntime({config,plan,dependencies:{random:n=>n===20?Buffer.from(serialHex,"hex"):randomBytes(n)}});const db=runtime.repositories.db,prepare=db.prepare.bind(db),close=db.close.bind(db);
 db.prepare=((...args:Parameters<typeof db.prepare>)=>{if(dbClosed)afterClose++;return prepare(...args);}) as typeof db.prepare;
 db.close=()=>{dbClosed=true;close();};
 const app=createControllerApplication({config,plan,runtimeFactory:()=>runtime,closeTimeoutMs:1500});
 try{
 const services=runtime.services,repos=runtime.repositories,credentials={username:"Owner",password:"synthetic-integration-password"};await services.owner.bootstrapOwner(credentials);const session=await services.sessions.create(credentials);assert.ok(session);const token=await services.inferenceTokens.issue(session.sessionToken,{label:"fixture"});assert.ok(token);
 const ca=services.certificates.initialize();ensureAgentPlaneMaterial(plan.certificateDir,"127.0.0.1",{random:()=>Buffer.from(serialHex.slice(0,32),"hex")});const keyPath=join(root,"host-key.pem"),csrPath=join(root,"host.csr");execFileSync("openssl",["genpkey","-algorithm","EC","-pkeyopt","ec_paramgen_curve:P-256","-out",keyPath],{stdio:"ignore"});chmodSync(keyPath,0o600);execFileSync("openssl",["req","-new","-key",keyPath,"-subj","/CN=agent-1","-addext","subjectAltName=IP:127.0.0.1,URI:spiffe://lanmodelmanager/host/agent-1","-out",csrPath],{stdio:"ignore"});
 const enrolled=services.certificates.enroll({ownerId:token.metadata.ownerId,challengeId:"c".repeat(64),transcriptDigest:"d".repeat(64),authorizedAt:new Date().toISOString(),binding:{candidateId:"agent-1",address:"127.0.0.1",port:7443,protocolMajor:1,protocolMinor:0}},readFileSync(csrPath,"utf8"));assert.ok(enrolled);
 const rawSerial=new X509Certificate(enrolled.certificate.certificatePem).serialNumber;
 assert.equal(rawSerial,serialHex);assert.equal(enrolled.certificate.serial,serialHex.replace(/^0+/,""));
 // A deployed pre-fix row can retain Node byte padding. No history rewrite is
 // needed: exact fingerprint plus numeric serial must still resolve it.
 db.prepare("UPDATE host_certificates SET serial=? WHERE fingerprint=?").run(rawSerial,enrolled.certificate.fingerprint);
 const leaf=parseTransportParsedLeaf(enrolled.certificate.certificatePem,ca.certificatePem);assert.ok(leaf.ok);const signer=buildTransportNativeSigner(readFileSync(keyPath,"utf8"),leaf.value);assert.ok(signer.ok);
 const seed=()=>{const observedAt=new Date().toISOString();repos.hosts.upsert({hostId:"agent-1",displayName:"Fixture",platform:"linux",online:true,freshness:"fresh",observedAt,snapshot:{resource:{hostId:"agent-1",platform:"linux",observedAt,cpuLogicalCores:4,cpuUtilizationPercent:0,memory:{totalBytes:100,usedBytes:10,availableBytes:90},storage:{totalBytes:100,usedBytes:10,availableBytes:90},accelerators:[]}}});repos.providers.upsert({providerId:"provider-1",hostId:"agent-1",kind:"ollama",endpoint:"http://127.0.0.1:11434",health:"ready",version:"",versionKnown:false,observedAt,snapshot:{}});repos.models.upsert({modelId:"model-1",providerId:"provider-1",hostId:"agent-1",canonicalName:"synthetic-model:fixture",state:"running",type:"llm",digest:"",digestKnown:false,observedAt,snapshot:{modelId:"model-1",providerId:"provider-1",displayName:"synthetic-model:fixture",runtimeState:"loaded-idle",activeRequests:0,managedTemporary:false,artifactState:"installed",observedAt}});db.prepare("INSERT INTO fleet_liveness(host_id,certificate_fingerprint,protocol_minor,last_sequence,last_observed_at,last_request_id,idle,updated_at) VALUES(?,?,0,1,?,'fixture',1,?) ON CONFLICT(host_id) DO UPDATE SET last_observed_at=excluded.last_observed_at").run("agent-1",enrolled.certificate.fingerprint,observedAt,observedAt);};
 services.admissions.register("model-1");assert.ok(services.policy.install({version:1,allowedOperations:["model-inference"],approvalOperations:[],allowArtifactAcquisition:false,allowArtifactRemoval:false,allowSubstitution:false,allowPublicExposure:false,minimumMemoryHeadroomBytes:1,minimumVramHeadroomBytes:0,minimumStorageHeadroomBytes:1,maxConcurrentOperations:10,maxOperationsPerMinute:100},{ok:true,session:{ownerId:token.metadata.ownerId,sessionVersion:1,revokedAt:null}}).ok);
 let sequence=0;
 const poll=(waitMs:number)=>{sequence++;const signed=signTransportSignedEnvelope({protocolVersion:{major:1,minor:0},messageType:"agent.command.poll",hostId:"agent-1",requestId:`poll-${sequence}`,sequence,sentAt:new Date().toISOString(),nonce:sequence.toString(16).padStart(32,"0"),bodyDigest:"0".repeat(64),certFingerprint:enrolled.certificate.fingerprint,certSerial:enrolled.certificate.serial,signature:"0".repeat(70),payload:{waitMs}},signer.value);assert.ok(signed.ok);let request!:ReturnType<typeof httpsRequest>;const result=new Promise<{status:number;body:any}>((resolve,reject)=>{request=httpsRequest({host:"127.0.0.1",port:agentPort,path:"/agent/v1/commands/poll",method:"POST",key:readFileSync(keyPath),cert:enrolled.certificate.certificatePem,ca:ca.certificatePem,agent:false,headers:{"content-type":"application/json"}},response=>{let text="";response.on("data",b=>text+=b);response.once("end",()=>resolve({status:response.statusCode!,body:JSON.parse(text)}));});request.once("error",reject);request.end(JSON.stringify(signed.value));});void result.catch(()=>{});return{request,result};};
 await app.start();
 // Actual default application routes and production agent-plane composition,
 // not a separately assembled approximation, drive the signed Go stream chain.
 writeFileSync(join(root,"enrollment.json"),JSON.stringify({controllerUrl:`https://127.0.0.1:${agentPort}`,pinnedCaFingerprintSha256:ca.fingerprint,challengeId:"c".repeat(64),binding:enrolled.certificate.binding,certificatePem:enrolled.certificate.certificatePem,caPem:ca.certificatePem,enrolledAt:new Date().toISOString()}),{mode:0o600});
 seed();const successful=fetch(`http://127.0.0.1:${publicPort}/v1/chat/completions`,{method:"POST",signal:AbortSignal.timeout(8000),headers:{authorization:`Bearer ${token.token}`,"content-type":"application/json",connection:"close"},body:JSON.stringify({model:"synthetic-model:fixture",messages:[{role:"user",content:"synthetic default composition"}],stream:true})});
 for(let i=0;i<100&&services.inference.activeCount!==1;i++)await delay(5);assert.equal(services.inference.activeCount,1);
 const go=new Promise<string>((resolveChild,reject)=>{const child=spawn("go",["test","./internal/fleet","-run","^TestCrossLanguageStreamHelper$","-count=1","-v"],{cwd:resolve(import.meta.dirname,"../../../agents/host-agent"),env:{...process.env,LANMM_STREAM_CERT_DIR:root,LANMM_STREAM_MODE:"normal"}});let output="";child.stdout.on("data",b=>output+=b);child.stderr.on("data",b=>output+=b);child.once("error",reject);child.once("close",code=>code===0?resolveChild(output):reject(new Error(output)));});void go.catch(()=>{});
 const response=await Promise.race([successful,go.then(()=>successful)]);assert.equal(response.status,200);const text=await response.text();assert.match(text,/usage/);assert.match(text,/data: \[DONE\]/);assert.match(await go,/STREAM_OUTCOME=succeeded/);assert.equal(services.admissions.snapshot("model-1").draining,false);
 sequence=Number(db.prepare("SELECT high_water FROM transport_replay_state WHERE certificate_fingerprint=?").get(enrolled.certificate.fingerprint)!.high_water);
 // Successful normal responses must not be classified as disconnect aborts.
 assert.equal((await poll(0).result).status,200);assert.equal((await poll(40).result).status,200);
 const abandoned=poll(30000);await delay(60);abandoned.request.destroy();await assert.rejects(abandoned.result);assert.equal((await poll(0).result).status,200);
 for(let generation=0;generation<2;generation++){
 seed();const publicRequest=httpRequest({host:"127.0.0.1",port:publicPort,path:"/v1/chat/completions",method:"POST",signal:AbortSignal.timeout(8000),headers:{authorization:`Bearer ${token.token}`,"content-type":"application/json"}});publicRequest.on("error",()=>{});publicRequest.end(JSON.stringify({model:"synthetic-model:fixture",messages:[{role:"user",content:"synthetic private"}],stream:true}));
 for(let i=0;i<100&&services.inference.activeCount!==1;i++)await delay(5);assert.equal(services.inference.activeCount,1);
 // First signed poll leases this generation's stream. The next is genuinely idle.
 assert.ok((await poll(0).result).body.payload.streamCommand);const idle=poll(30000);await delay(60);const partials:Array<{request:ReturnType<typeof httpsRequest>;body:string;readonly status:number}>=["/agent/v1/commands/poll","/agent/v1/fleet/heartbeat","/agent/v1/certificate/rotate"].map(path=>{
  let body:string;
  if(path.endsWith("rotate"))body=JSON.stringify({csrPem:readFileSync(csrPath,"utf8")});
  else{sequence++;const signed=signTransportSignedEnvelope({protocolVersion:{major:1,minor:0},messageType:path.endsWith("poll")?"agent.command.poll":"transport.heartbeat",hostId:"agent-1",requestId:`partial-${sequence}`,sequence,sentAt:new Date().toISOString(),nonce:sequence.toString(16).padStart(32,"0"),bodyDigest:"0".repeat(64),certFingerprint:enrolled.certificate.fingerprint,certSerial:rawSerial,signature:"0".repeat(70),payload:path.endsWith("poll")?{waitMs:30000}:{platform:"linux",protocolMinor:0,idle:true,observedAt:new Date().toISOString(),sequence}},signer.value);assert.ok(signed.ok);body=JSON.stringify(signed.value);}

  const request:ReturnType<typeof httpsRequest>=httpsRequest({host:"127.0.0.1",port:agentPort,path,method:"POST",key:readFileSync(keyPath),cert:enrolled.certificate.certificatePem,ca:ca.certificatePem,agent:false,headers:{"content-type":"application/json","content-length":String(Buffer.byteLength(body))}});
  let responseStatus=0;request.on("response",response=>{responseStatus=response.statusCode!;response.resume();});request.on("error",()=>{});request.write(body.slice(0,body.length-8));
  return {request,body,get status(){return responseStatus;}};
 });await delay(100);for(const partial of partials){assert.equal(partial.status,0);assert.equal(partial.request.destroyed,false);}
 // In the second generation, an incomplete public HTTP header deliberately
 // makes server.close hit the application deadline. Fleet uploads must already
 // be destroyed and their callbacks fenced before the catch path closes DB.
 const blocker=generation===1?connect(publicPort,"127.0.0.1"):null;
 if(blocker){blocker.on("error",()=>{});await once(blocker,"connect");blocker.write("GET / HTTP/1.1\r\nHost: localhost");}
 if(generation===1&&serialHex.startsWith("11")){runtime.close();assert.equal(dbClosed,true);}
 const before=Date.now();try{if(blocker)await assert.rejects(app.stop(),/ERR_APP_STOP/);else await app.stop();}finally{blocker?.destroy();}

 for(const partial of partials){partial.request.end(partial.body.slice(-8));}
 await delay(50);for(const partial of partials)assert.equal(partial.request.socket?.destroyed,true);
await idle.result.catch(()=>null);assert.ok(Date.now()-before<(generation===1?3500:1500));if(generation===1)assert.equal(dbClosed,true);assert.equal(services.inference.activeCount,0);assert.equal(services.admissions.snapshot("model-1").active,0);assert.equal(afterClose,0);
 if(generation===0){services.admissions.confirmIdle("model-1");services.admissions.resumeAdmission("model-1");await app.start();assert.equal((await poll(0).result).body.payload.streamCommand,null);}
 }
 await app.close();assert.equal(dbClosed,true);await delay(100);assert.equal(afterClose,0);
 }finally{await app.close();rmSync(root,{recursive:true,force:true});}
});

}

test("real runtime start-hook failure closes DB before guarded application cleanup without secondary service lookup",async()=>{
 const root=mkdtempSync(join(tmpdir(),"lanmm-app-start-failure-")),config={bindHost:"127.0.0.1",port:7340,inferenceHost:"127.0.0.1",inferencePort:7341,dataDir:root,logLevel:"info",discoveryEnabled:false,publicInferenceEnabled:false,tlsRequired:true,mutualTlsRequired:true} as const,plan={rootDir:root,databasePath:join(root,"controller.db"),artifactDir:join(root,"artifacts"),cacheDir:join(root,"cache"),stagingDir:join(root,"staging"),quarantineDir:join(root,"quarantine"),auditDir:join(root,"audit"),certificateDir:join(root,"certificates")};
 const runtime=createControllerRuntime({config,plan,hooks:{onStart(){throw new Error("private startup hook");}}});let listeners=0;const app=createControllerApplication({config,plan,runtimeFactory:()=>runtime,serverFactory:()=>{listeners++;throw new Error("unreachable listener");}});
 try{await assert.rejects(app.start(),e=>e instanceof Error&&e.message==="ERR_APP_START");assert.equal(runtime.isClosed,true);assert.equal(app.isClosed,true);assert.equal(listeners,0);await app.close();}finally{await app.close();rmSync(root,{recursive:true,force:true});}
});
