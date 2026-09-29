import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { createServer } from "node:net";
import { createControllerApplication, type ControllerApplication } from "./controller-application.js";
import type { ControllerConfig, ControllerPathPlan } from "./config.js";
import type { PasswordCryptoEngine } from "./credentials.js";

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
  first=application(dir,port);await first.start();
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
  const deferred=await fetch(`${base}/api/v1/lifecycle/operations`,{method:"POST",headers:{...postHeaders,cookie,"x-csrf-token":csrf},body:"{}"});assert.equal(deferred.status,405);
  assert.equal((await fetch(`${base}/api/v1/fleet/summary`,{headers:{authorization:"Bearer not-a-management-session",connection:"close"}})).status,401);

  await first.close();first=null;
  second=application(dir,port);await second.start();
  const afterRestart=await fetch(`${base}/api/v1/fleet/summary`,{headers:{cookie,connection:"close"}});assert.equal(afterRestart.status,200);assert.equal((await json(afterRestart)).ok,true);
  const tokensAfterRestart=await fetch(`${base}/api/v1/inference/tokens`,{headers:{cookie,connection:"close"}});assert.equal(tokensAfterRestart.status,200);assert.equal((await json(tokensAfterRestart)).value.length,1);
 }finally{await first?.close();await second?.close();rmSync(dir,{recursive:true,force:true})}
});
