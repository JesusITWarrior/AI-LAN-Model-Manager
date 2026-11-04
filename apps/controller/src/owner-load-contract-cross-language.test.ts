import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:net";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { commandAuthorizationDigest, type OperationPolicy } from "@lan-model-manager/core";
import { createControllerApplication } from "./controller-application.js";
import { CertificateRepository } from "./certificate-repository.js";

// Capture the real owner HTTP proposal's immutable command, not separately
// assembled test params, and hand those exact bytes to the real Go registry.
for (const kind of ["ollama", "lmstudio"] as const) test(`owner prepared ${kind} load reaches Go registry with reviewed provider-specific retention`, {timeout:30_000}, async()=>{
 const root=mkdtempSync(join(tmpdir(),"lanmm-owner-load-contract-")), now="2026-09-29T10:00:00.000Z";
 const probe=createServer();await new Promise<void>(r=>probe.listen(0,"127.0.0.1",r));const address=probe.address();assert.ok(address&&typeof address==="object");const port=address.port;await new Promise<void>(r=>probe.close(()=>r()));
 let random=1;
 const app=createControllerApplication({config:{bindHost:"127.0.0.1",port,inferenceHost:"127.0.0.1",inferencePort:port+1,dataDir:root,logLevel:"info",discoveryEnabled:false,publicInferenceEnabled:false,tlsRequired:true,mutualTlsRequired:true},plan:{rootDir:root,databasePath:join(root,"controller.sqlite3"),artifactDir:join(root,"artifacts"),cacheDir:join(root,"cache"),stagingDir:join(root,"staging"),quarantineDir:join(root,"quarantine"),auditDir:join(root,"audit"),certificateDir:join(root,"certificates")},runtimeDependencies:{now:()=>now,random:n=>Buffer.alloc(n,random++),ownerId:()=>"a".repeat(32),passwordCrypto:{random:n=>Buffer.alloc(n,3),async derive(password,salt,p){return Buffer.alloc(p.keyLength,createHash("sha256").update(password).update(salt).digest()[0]);},equal:(a,b)=>Buffer.from(a).equals(Buffer.from(b))}}});
 try {
  await app.start();
  const base=`http://127.0.0.1:${port}`;
  const post=(path:string,body:unknown,headers:Record<string,string>={})=>fetch(base+path,{method:"POST",headers:{"content-type":"application/json",origin:base,connection:"close",...headers},body:JSON.stringify(body)});
  const credentials={username:"Owner",password:"synthetic-contract-password-123"};assert.equal((await post("/auth/v1/bootstrap",credentials)).status,200);
  const login=await post("/auth/v1/login",credentials);assert.equal(login.status,200);const cookie=login.headers.get("set-cookie")!.split(";",1)[0]!,csrf=(await login.json() as any).value.csrfToken,headers={cookie,"x-csrf-token":csrf};
  const repos=app.runtime.repositories,certs=new CertificateRepository(repos.db),pem="-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n",fp="b".repeat(64);
  certs.insertCa({caId:"c".repeat(64),version:1,serial:"10",fingerprint:"c".repeat(64),certificatePem:pem,notBefore:"2026-01-01T00:00:00.000Z",notAfter:"2036-01-01T00:00:00.000Z",createdAt:now});
  certs.insertHost({certificateId:fp,serial:"ABCD",fingerprint:fp,certificatePem:pem,caId:"c".repeat(64),caVersion:1,binding:{candidateId:"host-1",address:"192.0.2.10",port:7443,protocolMajor:1,protocolMinor:0},spiffeUri:"spiffe://lanmodelmanager/host/host-1",challengeId:"d".repeat(64),transcriptDigest:"e".repeat(64),notBefore:"2026-01-01T00:00:00.000Z",notAfter:"2027-01-01T00:00:00.000Z",status:"active",version:1,issuedAt:now,revokedAt:null});
  repos.hosts.upsert({hostId:"host-1",displayName:"Synthetic",platform:"linux",observedAt:now,online:true,freshness:"fresh",snapshot:{resource:{hostId:"host-1",platform:"linux",observedAt:now,cpuLogicalCores:4,cpuUtilizationPercent:0,memory:{totalBytes:100,usedBytes:10,availableBytes:90},storage:{totalBytes:100,usedBytes:10,availableBytes:90},accelerators:[]}}});
  const providerId=kind==="ollama"?"ollama-main":"lmstudio-main",model=kind==="ollama"?"acme/bert:latest":"acme/bert";
  repos.providers.upsert({providerId,hostId:"host-1",kind,endpoint:"http://127.0.0.1:11434",health:"ready",version:"",versionKnown:false,observedAt:now,snapshot:{}});
  repos.models.upsert({modelId:"model-1",providerId,hostId:"host-1",canonicalName:model,state:"installed",type:"llm",digest:"",digestKnown:false,observedAt:now,snapshot:{runtimeState:"unloaded",activeRequests:0}});
  repos.db.prepare("INSERT INTO fleet_liveness(host_id,certificate_fingerprint,protocol_minor,last_sequence,last_observed_at,last_request_id,idle,updated_at) VALUES(?,?,?,?,?,?,?,?)").run("host-1",fp,0,1,now,"heartbeat-1",1,now);
  const policy:OperationPolicy={version:1,allowedOperations:["model-load"],approvalOperations:["model-load"],allowArtifactAcquisition:false,allowArtifactRemoval:false,allowSubstitution:false,allowPublicExposure:false,minimumMemoryHeadroomBytes:1,minimumVramHeadroomBytes:0,minimumStorageHeadroomBytes:1,maxConcurrentOperations:10,maxOperationsPerMinute:100};
  assert.equal((await post("/api/v1/policy/install",policy,headers)).status,200);
  const prepared=await post("/api/v1/lifecycle/proposals/prepare",{operation:"load",modelId:"model-1"},headers);assert.equal(prepared.status,200);const review=(await prepared.json() as any).value;
  assert.equal(review.state,"approval-required");assert.equal(/5 minutes/.test(review.consequence),kind==="ollama");
  assert.equal(app.runtime.services.commands.poll("host-1").command,null);assert.equal((repos.db.prepare("SELECT COUNT(*) n FROM jobs").get() as any).n,0);
  const before=repos.db.prepare("SELECT command_digest FROM lifecycle_proposal_authorizations").get() as any;
  assert.equal((await post("/api/v1/lifecycle/proposals/approve",{proposalId:review.proposalId},headers)).status,200);
  assert.equal(app.runtime.services.commands.poll("host-1").command,null);
  assert.equal((await post("/api/v1/lifecycle/proposals/submit",{proposalId:review.proposalId},headers)).status,200);
  const command=app.runtime.services.commands.poll("host-1").command;assert.ok(command);assert.equal(commandAuthorizationDigest(command),before.command_digest);
  assert.deepEqual(command.params,{providerId,model,keepAlive:kind==="ollama"?"5m":0});
  const paramsPath=join(root,"params.json");writeFileSync(paramsPath,JSON.stringify(command.params));
  const output=execFileSync("go",["test","./internal/command","-run","^TestOwnerPreparedLoadContractHelper$","-count=1","-v"],{cwd:join(resolve(import.meta.dirname,"../../.."),"agents/host-agent"),env:{...process.env,LANMM_OWNER_LOAD_PARAMS:paramsPath,LANMM_OWNER_LOAD_KIND:kind},encoding:"utf8"});assert.match(output,/OWNER_LOAD_CONTRACT=verified/);
 } finally {await app.close();rmSync(root,{recursive:true,force:true});}
});
