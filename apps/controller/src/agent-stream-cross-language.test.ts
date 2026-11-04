import assert from "node:assert/strict";
import {execFileSync,spawn} from "node:child_process";
import {createHash,X509Certificate} from "node:crypto";
import {once} from "node:events";
import {chmodSync,mkdtempSync,mkdirSync,readFileSync,rmSync,writeFileSync} from "node:fs";
import {createServer,request as httpsRequest} from "node:https";
import type {IncomingMessage} from "node:http";
import {tmpdir} from "node:os";
import {join,resolve} from "node:path";
import test from "node:test";
import {streamAuthorizationDigest} from "@lan-model-manager/core";
import {OpenSslCertificateEngine} from "./certificate-adapter.js";
import {CertificateRepository} from "./certificate-repository.js";
import {openControllerDatabase} from "./database.js";
import {createFleetAgentHttpHandler} from "./fleet-agent-http.js";
import {FleetService} from "./fleet-service.js";
import {createControllerRepositories} from "./repositories.js";
import {ControllerTransport} from "./transport/controller-transport.js";
import {PersistentReplayStore} from "./transport/replay-store.js";
import {buildTransportNativeSigner,buildTransportNativeVerifier} from "./transport/transport-signer.js";
import {AgentCommandService,AgentCommandStore} from "./agent-command-channel.js";
import {createJobStores} from "./jobs-store.js";
import {AgentStreamRelay} from "./agent-stream-relay.js";
import {createAgentStreamHttpHandler} from "./agent-stream-http.js";

import {createServer as createPublicServer} from "node:http";
import {createOwnerBootstrapService} from "./owner-service.js";
import {InferenceTokenManager} from "./inference-manager.js";
import {PolicyService} from "./policy-service.js";
import {createAdmissionController} from "./admission-accounting.js";
import {RemoteInferenceService} from "./remote-inference.js";
import {createRemoteInferenceChat} from "./remote-inference-chat.js";
import {createChatCompletionsHandler} from "./inference-chat.js";
import {createInferenceHttpHandler} from "./inference-http.js";

const fixture=JSON.parse(readFileSync(new URL("../../../agents/host-agent/internal/command/testdata/stream-v1.json",import.meta.url),"utf8"));
function leaf(root:string,caDir:string){const d=join(root,"server");mkdirSync(d);const run=(args:string[])=>execFileSync("openssl",args,{cwd:d,stdio:"ignore"});run(["genpkey","-algorithm","EC","-pkeyopt","ec_paramgen_curve:P-256","-out","key.pem"]);run(["req","-new","-key","key.pem","-subj","/CN=127.0.0.1","-out","request.pem"]);writeFileSync(join(d,"ext"),"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n");run(["x509","-req","-in","request.pem","-CA",join(caDir,"ca-cert.pem"),"-CAkey",join(caDir,"ca-key.pem"),"-set_serial","0x2001","-days","1","-extfile","ext","-out","cert.pem"]);return {key:readFileSync(join(d,"key.pem")),cert:readFileSync(join(d,"cert.pem"))};}
const delay=(ms:number)=>new Promise<void>(r=>setTimeout(r,ms));

test("real TLS1.3 Go ExecuteStream ↔ authenticated TS bounded relay; control remains independent",{timeout:120_000},async()=>{
 const root=mkdtempSync(join(tmpdir(),"lanmm-stream-cross-")),caDir=join(root,"ca"),agentDir=join(root,"agent");mkdirSync(agentDir,{mode:0o700});
 const db=openControllerDatabase(":memory:");let server:ReturnType<typeof createServer>|undefined;
 try{
  const engine=new OpenSslCertificateEngine(),now=new Date().toISOString(),ca=engine.initializeCa({directory:caDir,now});
  execFileSync("openssl",["genpkey","-algorithm","EC","-pkeyopt","ec_paramgen_curve:P-256","-out",join(agentDir,"host-key.pem")],{stdio:"ignore"});chmodSync(join(agentDir,"host-key.pem"),0o600);
  execFileSync("openssl",["req","-new","-key",join(agentDir,"host-key.pem"),"-subj","/CN=agent-1","-addext","subjectAltName=IP:127.0.0.1,URI:spiffe://lanmodelmanager/host/agent-1","-out",join(agentDir,"request.pem")],{stdio:"ignore"});
  const binding={candidateId:"agent-1",address:"127.0.0.1",port:7443,protocolMajor:1,protocolMinor:0},issued=engine.issueHost({directory:caDir,csrPem:readFileSync(join(agentDir,"request.pem"),"utf8"),binding,serial:"1234ABCD",now:new Date().toISOString()});
  const certificates=new CertificateRepository(db);certificates.insertCa(ca);certificates.insertHost({certificateId:issued.fingerprint,serial:issued.serial,fingerprint:issued.fingerprint,certificatePem:issued.certificatePem,caId:ca.caId,caVersion:1,binding,spiffeUri:"spiffe://lanmodelmanager/host/agent-1",challengeId:"c".repeat(64),transcriptDigest:"d".repeat(64),notBefore:issued.notBefore,notAfter:issued.notAfter,status:"active",version:1,issuedAt:now,revokedAt:null});
  const agentLeaf=new X509Certificate(issued.certificatePem),parsed:any={fingerprint:issued.fingerprint,serial:issued.serial,commonName:"agent-1",address:"127.0.0.1",spiffe:"spiffe://lanmodelmanager/host/agent-1",notBefore:issued.notBefore,notAfter:issued.notAfter,issuerFingerprint:ca.fingerprint,isCa:false};
  const verifier=buildTransportNativeVerifier(agentLeaf.publicKey.export({type:"spki",format:"pem"}).toString(),parsed);assert.ok(verifier.ok);if(!verifier.ok)return;
  const transport=new ControllerTransport({certificateRepository:certificates,replayStore:new PersistentReplayStore(db),verifier:()=>verifier.value}),fleet=new FleetService(db,transport,certificates,createControllerRepositories(db));
  const tls=leaf(root,caDir),serverLeaf=new X509Certificate(tls.cert),serverParsed:any={...parsed,fingerprint:createHash("sha256").update(serverLeaf.raw).digest("hex"),serial:serverLeaf.serialNumber.replace(/^0+/,"")||"0",commonName:"controller",spiffe:"spiffe://lanmodelmanager/controller",notBefore:new Date(serverLeaf.validFrom).toISOString(),notAfter:new Date(serverLeaf.validTo).toISOString()},signer=buildTransportNativeSigner(tls.key.toString(),serverParsed);assert.ok(signer.ok);if(!signer.ok)return;
  let handler:(req:IncomingMessage,res:import("node:http").ServerResponse)=>void=()=>{};const statuses:number[]=[];const uploads:IncomingMessage[]=[];
  server=createServer({key:tls.key,cert:tls.cert,ca:ca.certificatePem,minVersion:"TLSv1.3",maxVersion:"TLSv1.3",requestCert:true,rejectUnauthorized:true},(req,res)=>{if(req.headers["x-partial-upload"]==="fixture"){uploads.push(req);}res.on("finish",()=>statuses.push(res.statusCode));handler(req,res);});server.listen(0,"127.0.0.1");await once(server,"listening");const address=server.address();assert.ok(address&&typeof address==="object");
  writeFileSync(join(agentDir,"enrollment.json"),JSON.stringify({controllerUrl:`https://127.0.0.1:${address.port}`,pinnedCaFingerprintSha256:ca.fingerprint,challengeId:"c".repeat(64),binding,certificatePem:issued.certificatePem,caPem:ca.certificatePem,enrolledAt:now})+"\n",{mode:0o600});
  const run=(mode:string)=>new Promise<string>((resolveChild,reject)=>{const child=spawn("go",["test",...(process.env.LANMM_STREAM_GO_RACE==="1"?["-race"]:[]),"./internal/fleet","-run","^TestCrossLanguageStreamHelper$","-count=1","-v"],{cwd:join(resolve(import.meta.dirname,"../../.."),"agents/host-agent"),env:{...process.env,LANMM_STREAM_CERT_DIR:agentDir,LANMM_STREAM_MODE:mode}});let output="";child.stdout.on("data",v=>output+=v);child.stderr.on("data",v=>output+=v);child.once("error",reject);child.once("close",code=>code===0?resolveChild(output):reject(new Error(output)));});
  const uploadRelay=new AgentStreamRelay(),uploadHandler=createAgentStreamHttpHandler({relay:uploadRelay,transport,certificates});
  handler=createFleetAgentHttpHandler({fleet,certificates,streams:uploadHandler});
  const partial=(overflow:boolean)=>new Promise<number>((resolveUpload,rejectUpload)=>{
   const request=httpsRequest({hostname:"127.0.0.1",port:address.port,path:"/agent/v1/streams/event",method:"POST",key:readFileSync(join(agentDir,"host-key.pem")),cert:issued.certificatePem,ca:ca.certificatePem,minVersion:"TLSv1.3",maxVersion:"TLSv1.3",agent:false,headers:{"content-type":"application/json","x-partial-upload":"fixture"}},response=>{response.resume();response.once("end",()=>resolveUpload(response.statusCode!));});
   request.once("error",rejectUpload);request.write(Buffer.alloc(170_000,32));if(overflow)request.write(Buffer.alloc(20_000,32));
  });
  for(let round=0;round<2;round++){
   const pending=[partial(false),partial(false)];for(let i=0;i<200&&uploadHandler.stats().retainedBytes<340_000;i++)await delay(5);
   assert.deepEqual(uploadHandler.stats(),{inflight:2,retainedBytes:340_000});assert.deepEqual(await Promise.all(pending),[408,408]);
   for(let i=0;i<100&&uploadHandler.stats().inflight;i++)await delay(5);assert.deepEqual(uploadHandler.stats(),{inflight:0,retainedBytes:0});
  }
  for(let i=0;i<3;i++){assert.equal(await partial(true),413);for(let j=0;j<100&&uploadHandler.stats().inflight;j++)await delay(5);assert.deepEqual(uploadHandler.stats(),{inflight:0,retainedBytes:0});}
  for(let i=0;i<100&&uploads.some(req=>!req.destroyed);i++)await delay(5);
  assert.equal(uploads.length,7);for(const request of uploads){assert.equal(request.destroyed,true);assert.equal(request.socket.destroyed,true);assert.ok(!request.listeners("data").some(fn=>fn.name==="data"),request.listeners("data").map(fn=>fn.name).join(","));assert.ok(!request.listeners("end").some(fn=>fn.name==="end"),request.listeners("end").map(fn=>fn.name).join(","));assert.ok(request.listenerCount("data")<=1);assert.ok(request.listenerCount("end")<=1);assert.ok(!request.listeners("end").some(fn=>fn.name==="end"));}
  // Normal signed streaming below proves healthy requests work after repeated failures.
  uploadRelay.stop();
  let n=0;
  for(const mode of ["normal","slow","runner","close-read","budget","replay","cancel","deadline","restart","foreign","order","duplicate","bom","envelope-duplicate","envelope-bom","missing","conflict","unauthorized","source-mismatch","revoked"]){
   const relay=new AgentStreamRelay(),request=structuredClone(fixture.request);n++;request.hostId="agent-1";request.capability.hostId="agent-1";request.jobId=`synthetic-job-${n}`;request.requestId=`synthetic-request-${n}`;request.params.chat.requestId=request.requestId;request.idempotencyKey=`synthetic-idem-${n}`;request.deadline=new Date(Date.now()+(mode==="deadline"?1800:15_000)).toISOString();request.capability.expiresAt=request.deadline;request.capability.requestDigest=streamAuthorizationDigest(request);
   const handle=relay.open(Buffer.from(JSON.stringify(request))),commands=new AgentCommandService(transport,certificates,new AgentCommandStore(db),createJobStores(db),signer.value,{streams:relay});
   const streamCertificates=mode==="source-mismatch"?{getBySerial(serial:string,fingerprint:string){const value=certificates.getBySerial(serial,fingerprint);return value?{...value,binding:{...value.binding,address:"127.0.0.2"}}:null;}} as CertificateRepository:certificates;
   handler=createFleetAgentHttpHandler({fleet,certificates,commands,streams:createAgentStreamHttpHandler({relay,transport,certificates:streamCertificates})});
   if(mode==="revoked")assert.equal(certificates.revoke(issued.fingerprint,new Date().toISOString()),true);
   const running=run(mode);void running.catch(()=>{});
   if(["normal","slow","runner","budget","replay"].includes(mode)){
    // Wait until POST has a slot, then prove no HTTP acknowledgement occurred.
    for(let i=0;i<500&&relay.stats().events===0;i++)await delay(10);assert.equal(relay.stats().events,1,mode);
    const before=statuses.length;await delay(mode==="runner"?1300:mode==="slow"?250:60);if(mode!=="replay")assert.ok(statuses.length>before,`control polls continue while publisher blocked: ${mode}`);assert.equal(relay.stats().events,1);
    for(let i=0;i<(mode==="budget"?130:1);i++)assert.equal((await handle.next(new AbortController().signal))?.kind,"chunk");assert.equal((await handle.next(new AbortController().signal))?.kind,"succeeded");assert.equal(await handle.outcome,"succeeded");
   }else if(mode==="close-read"){
    for(let i=0;i<500;i++){try{readFileSync(join(agentDir,"provider-read-entered"));break;}catch{await delay(10);}}
    assert.equal(readFileSync(join(agentDir,"provider-read-entered"),"utf8"),"entered");assert.equal(relay.stats().events,0);
    handle.close();assert.deepEqual(relay.stats(),{streams:0,events:0,bytes:0});
    assert.deepEqual(relay.poll("foreign-host").cancelledJobIds,[]);assert.ok(relay.poll("agent-1").cancelledJobIds.includes(request.jobId));
   }else if(mode==="cancel"||mode==="restart"){
    for(let i=0;i<500&&relay.stats().events===0;i++)await delay(10);assert.equal(relay.stats().events,1);if(mode==="cancel")handle.cancel();else relay.stop();assert.equal(await handle.outcome,mode==="cancel"?"cancelled":"interrupted");
   }
   const output=await running;
   if(mode==="close-read")assert.match(output,/STREAM_CLOSE_READ_CALLS=1 RELEASES=1/);else if(mode==="replay")assert.match(output,/STREAM_REPLAY_REJECTED/);else if(mode==="runner")assert.match(output,/STREAM_RUNNER_CALLS=1/);else if(mode==="normal"||mode==="slow"||mode==="budget")assert.match(output,/STREAM_OUTCOME=succeeded POLLS=[1-9]\d* CALLS=1/);else if(["cancel","deadline","restart"].includes(mode))assert.match(output,/STREAM_OUTCOME=(failed|cancelled) POLLS=\d+ CALLS=1/);else assert.match(output,/STREAM_REJECTED/);
   if(mode==="deadline")assert.ok(["deadline","cancelled"].includes(await handle.outcome),"deadline/cancel race must not succeed");
   handle.close();relay.stop();assert.deepEqual(relay.stats(),{streams:0,events:0,bytes:0});
  }
  // Actual public bearer HTTP -> same owner -> signed command poll -> Go
  // ExecuteStream -> authenticated TLS POST -> bounded JSON and ordered SSE.
  db.exec("UPDATE host_certificates SET status='active',revoked_at=NULL");
  const repos=createControllerRepositories(db),jobs=createJobStores(db),ownerId="a".repeat(32);
  const owner=createOwnerBootstrapService(db,{ownerId:()=>ownerId});await owner.bootstrapOwner({username:"Owner",password:"synthetic-integration-password"});
  let random=10;const tokens=new InferenceTokenManager(db,async()=>true,{random:n=>Buffer.alloc(n,++random)}),token=await tokens.issue("management",{label:"synthetic"});assert.ok(token);
  const policy=new PolicyService(db,{stores:jobs}),admissions=createAdmissionController();
  assert.ok(policy.install({version:1,allowedOperations:["model-inference"],approvalOperations:[],allowArtifactAcquisition:false,allowArtifactRemoval:false,allowSubstitution:false,allowPublicExposure:false,minimumMemoryHeadroomBytes:1,minimumVramHeadroomBytes:0,minimumStorageHeadroomBytes:1,maxConcurrentOperations:10,maxOperationsPerMinute:100},{ok:true,session:{ownerId,sessionVersion:1,revokedAt:null}}).ok);
  const model=fixture.request.params.chat.model,modelId=fixture.request.params.chat.modelId,providerId=fixture.request.params.chat.providerId;
  const seed=()=>{const observedAt=new Date().toISOString();repos.hosts.upsert({hostId:"agent-1",displayName:"Synthetic",platform:"linux",observedAt,online:true,freshness:"fresh",snapshot:{resource:{hostId:"agent-1",platform:"linux",observedAt,cpuLogicalCores:4,cpuUtilizationPercent:0,memory:{totalBytes:100,usedBytes:10,availableBytes:90},storage:{totalBytes:100,usedBytes:10,availableBytes:90},accelerators:[]}}});repos.providers.upsert({providerId,hostId:"agent-1",kind:"ollama",endpoint:"http://127.0.0.1:11434",health:"ready",version:"",versionKnown:false,observedAt,snapshot:{}});repos.models.upsert({modelId,providerId,hostId:"agent-1",canonicalName:model,state:"running",type:"llm",digest:"",digestKnown:false,observedAt,snapshot:{modelId,providerId,displayName:model,artifactState:"installed",runtimeState:"loaded-idle",activeRequests:0,managedTemporary:false,observedAt}});db.prepare("INSERT INTO fleet_liveness(host_id,certificate_fingerprint,protocol_minor,last_sequence,last_observed_at,last_request_id,idle,updated_at) VALUES(?,?,0,1,?,'synthetic-live',1,?) ON CONFLICT(host_id) DO UPDATE SET last_observed_at=excluded.last_observed_at,health='active',revoked_at=NULL").run("agent-1",issued.fingerprint,observedAt,observedAt);};
  seed();admissions.register(modelId);const inference=new RemoteInferenceService(repos,tokens,policy,admissions,jobs),streams=createAgentStreamHttpHandler({relay:inference.streams,transport,certificates});inference.ownHttp(streams.shutdown);
  const commands=new AgentCommandService(transport,certificates,new AgentCommandStore(db),jobs,signer.value,{streams:inference.streams});handler=createFleetAgentHttpHandler({fleet,certificates,commands,streams});
  const publicServer=createPublicServer(createInferenceHttpHandler(async()=>({status:404,headers:{},body:{}}),createChatCompletionsHandler({...createRemoteInferenceChat(inference),tokens}),close=>inference.ownHttp(close)));publicServer.listen(0,"127.0.0.1");await once(publicServer,"listening");const publicAddress=publicServer.address();assert.ok(publicAddress&&typeof publicAddress==="object");const url=`http://127.0.0.1:${publicAddress.port}/v1/chat/completions`;
  try{assert.equal((await fetch(url,{method:"POST",headers:{"content-type":"application/json"},body:"{}"})).status,401);
   for(const stream of [false,true]){seed();const pending:Promise<Response>=fetch(url,{method:"POST",headers:{authorization:`Bearer ${token.token}`,"content-type":"application/json",connection:"close"},body:JSON.stringify({model,messages:[{role:"user",content:"synthetic-private-http-prompt"}],stream})});
    const running=run("normal");void running.catch(()=>{});const response:Response=await pending;assert.equal(response.status,200);const text=await response.text();if(stream){assert.match(text,/data: /);assert.match(text,/usage/);assert.ok(text.indexOf('"usage"')<text.indexOf("[DONE]"));assert.equal(text.split("[DONE]").length,2);}else{const body=JSON.parse(text);assert.equal(body.object,"chat.completion");assert.ok(body.usage);assert.equal(body.model,model);}assert.match(await running,/STREAM_OUTCOME=succeeded/);assert.equal(admissions.snapshot(modelId).active,0);assert.equal(admissions.snapshot(modelId).draining,false);
   }
   const dump=JSON.stringify(db.prepare("SELECT * FROM inference_executions").all())+JSON.stringify(db.prepare("SELECT * FROM agent_commands").all())+JSON.stringify(jobs.audit.list());for(const secret of ["synthetic-private-http-prompt",Buffer.from("synthetic-private-http-prompt").toString("base64"),token.token])assert.equal(dump.includes(secret),false);
  }finally{await inference.shutdown();publicServer.closeAllConnections();await new Promise<void>(r=>publicServer.close(()=>r()));}
  assert.ok(statuses.includes(401));assert.ok(statuses.includes(400));
 }finally{if(server){server.closeAllConnections();await new Promise<void>(r=>server!.close(()=>r()));}db.close();rmSync(root,{recursive:true,force:true});}
});
