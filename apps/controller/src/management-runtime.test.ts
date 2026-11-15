import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { createServer } from "node:net";
import { execFileSync } from "node:child_process";
import { createControllerApplication, type ControllerApplication } from "./controller-application.js";
import { createManagementDependencies, createReadManagementDependencies } from "./management-runtime.js";
import { routeManagementRequest } from "./management-api.js";
import { createControllerRuntime } from "./controller-runtime.js";
import { CertificateRepository } from "./certificate-repository.js";
import { OpenSslCertificateEngine } from "./certificate-adapter.js";
import { AgentCommandStore } from "./agent-command-channel.js";
import { CommandDispatcher } from "./command-dispatch.js";
import { buildOwnerNativeEvidenceSnapshot } from "./owner-native-evidence-snapshot.js";
import { encodeNativeTerminalEvidence } from "./native-terminal-evidence-codec.js";
import { commandAuthorizationDigest, commandPolicyOperation, type CommandRequest, type CommandResponse } from "@lan-model-manager/core";
import { readFileSync, mkdirSync } from "node:fs";
import { openControllerDatabase } from "./database.js";
import type { ControllerConfig, ControllerPathPlan } from "./config.js";
import type { PasswordCryptoEngine } from "./credentials.js";
import type { DatabaseSync } from "node:sqlite";

function crypto():PasswordCryptoEngine{return{random:n=>Buffer.alloc(n,3),async derive(password,salt,p){const x=createHash("sha256").update(Buffer.from(password)).update(Buffer.from(salt)).digest();return Buffer.alloc(p.keyLength,x[0])},equal:(a,b)=>Buffer.from(a).equals(Buffer.from(b))}}
function plan(dataDir:string):ControllerPathPlan{return{rootDir:dataDir,databasePath:join(dataDir,"controller.sqlite3"),artifactDir:join(dataDir,"artifacts"),cacheDir:join(dataDir,"cache"),stagingDir:join(dataDir,"staging"),quarantineDir:join(dataDir,"quarantine"),auditDir:join(dataDir,"audit"),certificateDir:join(dataDir,"certificates")}}
async function availablePort():Promise<number>{const probe=createServer();await new Promise<void>((resolve,reject)=>probe.once("error",reject).listen(0,"127.0.0.1",resolve));const address=probe.address();assert.ok(address&&typeof address==="object");const port=address.port;await new Promise<void>((resolve,reject)=>probe.close(error=>error?reject(error):resolve()));return port}
function application(dataDir:string,port:number):ControllerApplication{const randomByte={value:42},config:ControllerConfig={bindHost:"127.0.0.1",port,inferenceHost:"127.0.0.1",inferencePort:port+1,dataDir,logLevel:"info",discoveryEnabled:false,publicInferenceEnabled:false,tlsRequired:true,mutualTlsRequired:true};return createControllerApplication({config,plan:plan(dataDir),runtimeDependencies:{now:()=>"2026-09-29T07:00:00.000Z",random:n=>Buffer.alloc(n,randomByte.value++),ownerId:()=>"a".repeat(32),passwordCrypto:crypto()}})}
function sessionCookie(response:Response):string{const value=response.headers.get("set-cookie");assert.ok(value);assert.match(value,/; HttpOnly;/);return value.split(";",1)[0]!}
async function json(response:Response):Promise<any>{return response.json()}

// Production composition proof: genuine auth handler and management handler share
// the runtime-owned session manager and persistent database.
test("authenticated management reads are live and owner sessions persist across restart",async()=>{
 const dir=mkdtempSync(join(tmpdir(),"lanmm-mgmt-"));const port=await availablePort(),base=`http://127.0.0.1:${port}`,origin=base;let first:ControllerApplication|null=null,second:ControllerApplication|null=null;
 try{
  first=application(dir,port);
  const readDeps=createReadManagementDependencies(first.runtime,[origin],{allowLoopbackHttpDevelopment:true});
  const productionDeps=createManagementDependencies(first.runtime,[origin],{allowLoopbackHttpDevelopment:true});
  assert.equal("ownerEvidenceIntake" in readDeps,false,"read adapter has no evidence capability");
  assert.equal("ownerEvidenceIntake" in productionDeps,false,"default production runtime has no evidence capability");
  await first.start();
  const postHeaders={"content-type":"application/json",origin,connection:"close"};
  const credentials={username:"admin",password:"correct-horse-battery-staple-123"};
  const bootstrap=await fetch(`${base}/auth/v1/bootstrap`,{method:"POST",headers:postHeaders,body:JSON.stringify(credentials)});
  assert.equal(bootstrap.status,200);assert.match(bootstrap.headers.get("set-cookie")??"",/; HttpOnly;/);await json(bootstrap);
  const login=await fetch(`${base}/auth/v1/login`,{method:"POST",headers:postHeaders,body:JSON.stringify(credentials)});
  assert.equal(login.status,200);const cookie=sessionCookie(login),loginBody=await json(login),csrf=loginBody.value.csrfToken;assert.equal(typeof csrf,"string");

  const get=async(path:string)=>{const response=await fetch(`${base}${path}`,{headers:{cookie,connection:"close"}});return{response,body:await json(response)}};
  let result=await get("/api/v1/fleet/summary");assert.equal(result.response.status,200);assert.equal(result.body.ok,true);assert.equal(result.body.value.hosts,0);
  result=await get("/api/v1/policy/settings");assert.equal(result.response.status,200);assert.equal(result.body.value.noPromptEnabled,false);
  result=await get("/api/v1/policy/approvals");assert.equal(result.response.status,200);assert.deepEqual(result.body.value,[]);
  result=await get("/api/v1/audit?limit=5");assert.equal(result.response.status,200);assert.deepEqual(result.body.value.items,[]);
  result=await get("/api/v1/jobs?state=running&limit=1");assert.equal(result.response.status,200);assert.deepEqual(result.body.value.items,[]);

  const issued=await fetch(`${base}/api/v1/inference/tokens`,{method:"POST",headers:{...postHeaders,cookie,"x-csrf-token":csrf},body:JSON.stringify({label:"console",scopes:["inference:invoke","model:list"]})});
  assert.equal(issued.status,200);const issuedBody=await json(issued);assert.equal(typeof issuedBody.value.token,"string");assert.equal("ownerId" in issuedBody.value.metadata,false);
  result=await get("/api/v1/inference/tokens");assert.equal(result.response.status,200);assert.equal(result.body.value.length,1);assert.equal(result.body.value[0].label,"console");assert.equal("ownerId" in result.body.value[0],false);assert.equal("token" in result.body.value[0],false);

  const noCsrf=await fetch(`${base}/api/v1/lifecycle/operations`,{method:"POST",headers:{...postHeaders,cookie},body:"{}"});assert.equal(noCsrf.status,403);
  const deferred=await fetch(`${base}/api/v1/lifecycle/operations`,{method:"POST",headers:{...postHeaders,cookie,"x-csrf-token":csrf},body:"{}"});assert.equal(deferred.status,400);
  assert.equal((await fetch(`${base}/api/v1/fleet/summary`,{headers:{authorization:"Bearer not-a-management-session",connection:"close"}})).status,401);

  await first.close();first=null;
  second=application(dir,port);await second.start();
  const afterRestart=await fetch(`${base}/api/v1/fleet/summary`,{headers:{cookie,connection:"close"}});assert.equal(afterRestart.status,200);assert.equal((await json(afterRestart)).ok,true);
  const tokensAfterRestart=await fetch(`${base}/api/v1/inference/tokens`,{headers:{cookie,connection:"close"}});assert.equal(tokensAfterRestart.status,200);assert.equal((await json(tokensAfterRestart)).value.length,1);
 }finally{await first?.close();await second?.close();rmSync(dir,{recursive:true,force:true})}
});

test("opted-in production facade routes real SQLite prepare/confirm stored, duplicate, and conflict outcomes",async()=>{
 const root=mkdtempSync(join(tmpdir(),"lanmm-management-evidence-route-"));const dataDir=join(root,"controller"),origin="https://manager.example";let db!:DatabaseSync;
 const config:ControllerConfig={bindHost:"127.0.0.1",port:7340,inferenceHost:"127.0.0.1",inferencePort:7341,dataDir,logLevel:"info",discoveryEnabled:false,publicInferenceEnabled:false,tlsRequired:true,mutualTlsRequired:false};
 let now=new Date(Date.now()-10_000).toISOString();const runtimePlan=plan(dataDir),openDatabase=(path:string)=>{db=openControllerDatabase(path);return db};
 const runtime=createControllerRuntime({config,plan:runtimePlan,ownerEvidence:{allowedOrigins:[origin]},dependencies:{now:()=>now,ownerId:()=>"a".repeat(32),passwordCrypto:crypto(),openDatabase}});
 const defaultDir=join(root,"default"),defaultConfig={...config,dataDir:defaultDir},defaultRuntime=createControllerRuntime({config:defaultConfig,plan:plan(defaultDir)});
 try{
  const evidence=runtime.services.ownerEvidence;assert.ok(evidence);
  const production=createManagementDependencies(runtime,[origin]);const read=createReadManagementDependencies(runtime,[origin]);const defaultProduction=createManagementDependencies(defaultRuntime,[origin]);
  assert.equal(production.ownerEvidenceIntake,evidence,"production adapter exposes the exact runtime facade");assert.equal("ownerEvidenceIntake" in read,false,"read adapter has neither prepare nor confirm");assert.equal("ownerEvidenceIntake" in defaultProduction,false,"default production remains absent");
  const owner=await runtime.services.owner.bootstrapOwner({username:"owner",password:"owner-password-123"});const session=await runtime.services.sessions.create({username:"owner",password:"owner-password-123"});assert.ok(session);assert.equal(session.metadata.ownerId,owner.ownerId);
  const caDir=join(runtimePlan.certificateDir,"ca"),hostDir=join(runtimePlan.certificateDir,"host");mkdirSync(hostDir,{recursive:true,mode:0o700});const engine=new OpenSslCertificateEngine();const ca=engine.initializeCa({directory:caDir,now:new Date(Date.now()-2_000).toISOString()});
  execFileSync("openssl",["genpkey","-algorithm","EC","-pkeyopt","ec_paramgen_curve:P-256","-out",join(hostDir,"key.pem")],{stdio:"ignore"});execFileSync("openssl",["req","-new","-key",join(hostDir,"key.pem"),"-subj","/CN=host-1","-addext","subjectAltName=IP:192.0.2.10,URI:spiffe://lanmodelmanager/host/host-1","-out",join(hostDir,"request.pem")],{stdio:"ignore"});
  const certNow=new Date().toISOString(),binding={candidateId:"host-1",address:"192.0.2.10",port:7443,protocolMajor:1,protocolMinor:0},issued=engine.issueHost({directory:caDir,csrPem:readFileSync(join(hostDir,"request.pem"),"utf8"),binding,serial:"ABCDEF1234",now:certNow});new CertificateRepository(db).insertCa(ca);new CertificateRepository(db).insertHost({certificateId:issued.fingerprint,serial:issued.serial,fingerprint:issued.fingerprint,certificatePem:issued.certificatePem,caId:ca.caId,caVersion:ca.version,binding,spiffeUri:"spiffe://lanmodelmanager/host/host-1",challengeId:"e".repeat(64),transcriptDigest:"f".repeat(64),notBefore:issued.notBefore,notAfter:issued.notAfter,status:"active",version:1,issuedAt:certNow,revokedAt:null});
  now=new Date().toISOString();const operation="probe",jobId="job-1",hostId="host-1";const request:CommandRequest={requestId:"request-1",jobId,hostId,operation,idempotencyKey:"idem-1",sequence:1,deadline:new Date(Date.parse(now)+300_000).toISOString(),capability:{operation:commandPolicyOperation(operation),targetKind:"host",targetId:hostId,hostId,modelId:null,requestDigest:"",expiresAt:new Date(Date.parse(now)+300_000).toISOString()},params:{providerId:"provider-1",model:"model:latest"}};(request.capability as {requestDigest:string}).requestDigest=commandAuthorizationDigest(request);const commands=runtime.services.commands as AgentCommandStore;assert.equal(new CommandDispatcher(runtime.jobStores,commands,()=>now).dispatch(request).ok,true);assert.ok(commands.poll(hostId).command);
  const response:CommandResponse={requestId:request.requestId,jobId,hostId,sequence:1,status:"failed",progress:null,observedAt:new Date(Date.parse(now)+1_000).toISOString(),observation:null,errorCode:"ADAPTER_FAILED"};now=response.observedAt;assert.ok(commands.complete(hostId,response));const builtResult:{value:ReturnType<typeof buildOwnerNativeEvidenceSnapshot>}={value:null};runtime.jobStores.withAuditTransaction(tx=>{builtResult.value=buildOwnerNativeEvidenceSnapshot(db,tx,jobId,Buffer.from(JSON.stringify(response)),"synthetic",now)});const built=builtResult.value;assert.ok(built);const encoded=encodeNativeTerminalEvidence(built.snapshot);assert.equal(encoded.ok,true);if(!encoded.ok)return;const payload=Uint8Array.from(Buffer.from(encoded.payloadBase64,"base64")),headers={cookie:`__Host-lanmm_session=${session.sessionToken}`,origin, "x-csrf-token":session.csrfToken,"content-type":"application/json"};
  const prepare=async(requestHeaders=headers)=>{const result=await routeManagementRequest(production,{method:"POST",url:"/api/v1/native-evidence/prepare",headers:requestHeaders,rawBodyBytes:payload});assert.equal(result.status,200);return (result.body as any).value as {candidateHandle:string;expectedTupleDigest:string}};const confirm=async(prepared:{candidateHandle:string;expectedTupleDigest:string},requestHeaders=headers)=>routeManagementRequest(production,{method:"POST",url:"/api/v1/native-evidence/confirm",headers:requestHeaders,body:JSON.stringify({candidateHandle:prepared.candidateHandle,expectedTupleDigest:prepared.expectedTupleDigest,action:"append-supplemental-native-evidence",disposition:"evidence-only"})});
  const protectedState=()=>JSON.stringify({jobs:db.prepare("SELECT * FROM jobs ORDER BY job_id").all(),histories:db.prepare("SELECT * FROM job_history ORDER BY history_id").all(),commands:db.prepare("SELECT * FROM agent_commands ORDER BY job_id").all(),owners:db.prepare("SELECT * FROM owners").all(),sessions:db.prepare("SELECT * FROM sessions").all(),hosts:db.prepare("SELECT * FROM host_certificates").all(),authorities:db.prepare("SELECT * FROM certificate_authorities").all(),trust:db.prepare("SELECT * FROM transport_replay_state").all()});const evidenceCount=()=>Number((db.prepare("SELECT COUNT(*) AS n FROM supplemental_native_evidence").get() as {n:number}).n),auditCount=()=>Number((db.prepare("SELECT COUNT(*) AS n FROM audit_events").get() as {n:number}).n);const protectedBefore=protectedState(),evidenceBefore=evidenceCount(),auditBefore=auditCount();
  const first=await prepare(),stored=await confirm(first);assert.equal(stored.status,201);assert.deepEqual(stored.body,{ok:true,outcome:"stored"});assert.equal(evidenceCount(),evidenceBefore+1);assert.equal(auditCount(),auditBefore+1);assert.equal(protectedState(),protectedBefore);const originalConsent=(db.prepare("SELECT consented_at FROM supplemental_native_evidence WHERE tuple_digest=?").get(first.expectedTupleDigest) as {consented_at:string}).consented_at;
  const second=await prepare(),duplicate=await confirm(second);assert.equal(duplicate.status,200);assert.deepEqual(duplicate.body,{ok:true,outcome:"already_stored"});assert.equal(evidenceCount(),evidenceBefore+1);assert.equal(auditCount(),auditBefore+1);assert.equal((db.prepare("SELECT consented_at FROM supplemental_native_evidence WHERE tuple_digest=?").get(first.expectedTupleDigest) as {consented_at:string}).consented_at,originalConsent);assert.equal(protectedState(),protectedBefore);
  const secondSession=await runtime.services.sessions.create({username:"owner",password:"owner-password-123"});assert.ok(secondSession);const secondHeaders={cookie:`__Host-lanmm_session=${secondSession.sessionToken}`,origin,"x-csrf-token":secondSession.csrfToken,"content-type":"application/json"};const protectedBeforeConflict=protectedState(),third=await prepare(secondHeaders),conflict=await confirm(third,secondHeaders);assert.equal(conflict.status,409);assert.equal(JSON.stringify(conflict.body),JSON.stringify({ok:false,error:{code:"CONFLICT",message:"Request conflicts with current state."}}));assert.equal(evidenceCount(),evidenceBefore+1);assert.equal(auditCount(),auditBefore+1);assert.equal(protectedState(),protectedBeforeConflict);
 }finally{runtime.close();defaultRuntime.close();rmSync(root,{recursive:true,force:true})}
});
