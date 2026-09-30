import {createHash,createPublicKey,randomBytes,X509Certificate} from "node:crypto";
import {spawnSync} from "node:child_process";
import {chmodSync,closeSync,existsSync,fsyncSync,lstatSync,mkdirSync,mkdtempSync,openSync,readFileSync,renameSync,rmSync,writeFileSync} from "node:fs";
import {join} from "node:path";
import {createServer,type Server} from "node:https";
import type {RequestListener} from "node:http";
import type {TLSSocket} from "node:tls";
import type {TransportSigner} from "@lan-model-manager/core";
import {parseTransportParsedLeaf} from "./transport/trust-resolver.js";
import {buildTransportNativeSigner,buildTransportNativeVerifier} from "./transport/transport-signer.js";
import {ControllerTransport} from "./transport/controller-transport.js";
import {CertificateRepository} from "./certificate-repository.js";
import {FleetService} from "./fleet-service.js";
import {createFleetAgentHttpHandler} from "./fleet-agent-http.js";
import {AgentCommandService,AgentCommandStore} from "./agent-command-channel.js";
import type {ControllerRuntimeHandle} from "./controller-runtime.js";

export interface AgentPlaneMaterial{readonly key:string;readonly certificate:string;readonly ca:string;readonly generation:string}
type OpenSslRunner=(cwd:string,args:readonly string[])=>void;
const GENERATION=/^[a-f0-9]{32}$/;
const RENEW_BEFORE_MS=7*24*60*60*1000;
const serverRotators=new WeakMap<Server,(material:AgentPlaneMaterial)=>void>();
function openssl(cwd:string,args:readonly string[]):void{const r=spawnSync("openssl",args,{cwd,stdio:"ignore",timeout:15_000,shell:false});if(r.status!==0)throw new Error("ERR_AGENT_PLANE_CERTIFICATE")}
function regular(path:string,max=65536):number{try{const s=lstatSync(path);if(!s.isFile()||s.isSymbolicLink()||(s.mode&0o177)!==0||s.size<1||s.size>max)throw 0;return s.size}catch{throw new Error("ERR_AGENT_PLANE_CERTIFICATE")}}
function secureDirectory(path:string,create=false):void{try{if(!existsSync(path)){if(!create)throw 0;mkdirSync(path,{mode:0o700})}const s=lstatSync(path);if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o077)!==0)throw 0;chmodSync(path,0o700)}catch{throw new Error("ERR_AGENT_PLANE_CERTIFICATE")}}
function pathEntryExists(path:string):boolean{try{lstatSync(path);return true}catch(error){if((error as NodeJS.ErrnoException).code==="ENOENT")return false;throw new Error("ERR_AGENT_PLANE_CERTIFICATE")}}
function optionalRegular(path:string,max=65536):boolean{if(!pathEntryExists(path))return false;regular(path,max);return true}
function readGeneration(directory:string):string|null{const pointer=join(directory,"agent-plane-current");if(!pathEntryExists(pointer))return null;regular(pointer,128);const value=readFileSync(pointer,"utf8").trim();if(!GENERATION.test(value))throw new Error("ERR_AGENT_PLANE_CERTIFICATE");return value}
function readMaterial(directory:string,generation:string,address:string,now:number):AgentPlaneMaterial|null{const root=join(directory,"agent-plane-generations",generation);if(!pathEntryExists(root))return null;secureDirectory(root);const keyPath=join(root,"key.pem"),certPath=join(root,"cert.pem"),caPath=join(directory,"ca-cert.pem");if(!optionalRegular(keyPath)||!optionalRegular(certPath))return null;regular(caPath);try{const material={key:readFileSync(keyPath,"utf8"),certificate:readFileSync(certPath,"utf8"),ca:readFileSync(caPath,"utf8"),generation};const leaf=new X509Certificate(material.certificate),ca=new X509Certificate(material.ca);if(!leaf.verify(ca.publicKey)||leaf.checkIP(address)!==address||!(leaf.subjectAltName??"").includes("URI:spiffe://lanmodelmanager/host/controller")||Date.parse(leaf.validTo)<=now)return null;return Object.freeze(material)}catch{return null}}
function syncPath(path:string):void{const fd=openSync(path,"r");try{fsyncSync(fd)}finally{closeSync(fd)}}
function syncDirectory(path:string):void{if(process.platform!=="win32")syncPath(path)}
function atomicPointer(directory:string,generation:string):void{const temp=join(directory,`.agent-plane-current-${generation}`),target=join(directory,"agent-plane-current");const fd=openSync(temp,"wx",0o600);try{writeFileSync(fd,`${generation}\n`);fsyncSync(fd)}finally{closeSync(fd)}renameSync(temp,target);syncDirectory(directory)}

// Material is generated in an isolated directory, fully validated, and made
// active by one atomic pointer rename. Existing generations are never modified
// or deleted, so an interrupted or failed rotation leaves the old identity live.
export function ensureAgentPlaneMaterial(directory:string,address:string,options:{readonly now?:number;readonly run?:OpenSslRunner;readonly random?:()=>Buffer}={}):AgentPlaneMaterial{
 const now=options.now??Date.now(),run=options.run??openssl,random=options.random??(()=>randomBytes(16));
 secureDirectory(directory,true);const caKey=join(directory,"ca-key.pem"),caCert=join(directory,"ca-cert.pem");regular(caKey);regular(caCert);
 const generations=join(directory,"agent-plane-generations");secureDirectory(generations,true);
 const current=readGeneration(directory);if(current){const active=readMaterial(directory,current,address,now);if(active&&Date.parse(new X509Certificate(active.certificate).validTo)>now+RENEW_BEFORE_MS)return active}
 const raw=random();if(!Buffer.isBuffer(raw)||raw.length!==16)throw new Error("ERR_AGENT_PLANE_CERTIFICATE");const generation=raw.toString("hex");if(!GENERATION.test(generation)||existsSync(join(generations,generation)))throw new Error("ERR_AGENT_PLANE_CERTIFICATE");
 const stage=mkdtempSync(join(generations,".staging-"));chmodSync(stage,0o700);const key="key.pem",csr="request.pem",cert="cert.pem",ext="extensions.cnf";
 try{
  run(stage,["ecparam","-name","prime256v1","-genkey","-noout","-out",key]);chmodSync(join(stage,key),0o600);
  run(stage,["req","-new","-sha256","-key",key,"-subj","/CN=controller","-out",csr]);
  writeFileSync(join(stage,ext),`basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,serverAuth\nsubjectAltName=IP:${address},URI:spiffe://lanmodelmanager/host/controller\n`,{mode:0o600});
  run(stage,["x509","-req","-sha256","-in",csr,"-CA",caCert,"-CAkey",caKey,"-set_serial",`0x${generation.slice(0,32)}`,"-days","30","-extfile",ext,"-out",cert]);chmodSync(join(stage,cert),0o600);
  regular(join(stage,key));regular(join(stage,cert));syncPath(join(stage,key));syncPath(join(stage,cert));syncDirectory(stage);const staged={key:readFileSync(join(stage,key),"utf8"),certificate:readFileSync(join(stage,cert),"utf8"),ca:readFileSync(caCert,"utf8"),generation};const leaf=new X509Certificate(staged.certificate),ca=new X509Certificate(staged.ca);if(!leaf.verify(ca.publicKey)||leaf.checkIP(address)!==address||!(leaf.subjectAltName??"").includes("URI:spiffe://lanmodelmanager/host/controller"))throw new Error("ERR_AGENT_PLANE_CERTIFICATE");
  renameSync(stage,join(generations,generation));syncDirectory(generations);const replacement=readMaterial(directory,generation,address,now);if(!replacement)throw new Error("ERR_AGENT_PLANE_CERTIFICATE");atomicPointer(directory,generation);return replacement;
 }catch{try{if(existsSync(stage))rmSync(stage,{recursive:true,force:true})}catch{}throw new Error("ERR_AGENT_PLANE_CERTIFICATE")}
}

export function scheduleAgentPlaneRotation(server:Server,directory:string,address:string,options:{readonly intervalMs?:number;readonly onError?:(error:Error)=>void}={}):()=>void{const interval=options.intervalMs??12*60*60*1000;if(!Number.isSafeInteger(interval)||interval<1000)throw new Error("ERR_AGENT_PLANE_CERTIFICATE");let active=readGeneration(directory),failures=0;const timer=setInterval(()=>{try{const next=ensureAgentPlaneMaterial(directory,address);if(next.generation!==active){const rotate=serverRotators.get(server);if(!rotate)throw new Error("ERR_AGENT_PLANE_CERTIFICATE");rotate(next);active=next.generation}failures=0}catch{failures++;options.onError?.(new Error("ERR_AGENT_PLANE_CERTIFICATE"));if(failures>=3){clearInterval(timer);server.close();}}},interval);timer.unref();return()=>clearInterval(timer)}

export function createProductionAgentPlane(runtime:ControllerRuntimeHandle,material:AgentPlaneMaterial,enrollment:RequestListener,clock:()=>string=()=>new Date().toISOString()):Server{
 const certificates=new CertificateRepository(runtime.repositories.db),ca=runtime.services.certificates.getCa();if(!ca)throw new Error("ERR_AGENT_PLANE_CA");
 const transport=new ControllerTransport({certificateRepository:certificates,replayStore:runtime.services.replay,clock,verifier:pem=>{const parsed=parseTransportParsedLeaf(pem,material.ca);if(!parsed.ok)return null;const built=buildTransportNativeVerifier(createPublicKey(pem).export({type:"spki",format:"pem"}) as string,parsed.value);return built.ok?built.value:null;}});
 const fleet=new FleetService(runtime.repositories.db,transport,certificates,runtime.repositories,{clock});
 const parsed=parseTransportParsedLeaf(material.certificate,material.ca);if(!parsed.ok)throw new Error("ERR_AGENT_PLANE_CERTIFICATE");const signer=buildTransportNativeSigner(material.key,parsed.value);if(!signer.ok)throw new Error("ERR_AGENT_PLANE_CERTIFICATE");const signers=new Map<string,TransportSigner>([[parsed.value.fingerprint,signer.value]]);
 const commands=new AgentCommandService(transport,certificates,new AgentCommandStore(runtime.repositories.db,clock,30_000,runtime.jobStores),runtime.jobStores,signer.value,{clock});
 const commandSigner=(request:Parameters<RequestListener>[0])=>{const socket=request.socket as TLSSocket,local=(typeof socket.getCertificate==="function"?socket.getCertificate():null) as {raw?:Buffer}|null;if(!local?.raw)return null;return signers.get(createHash("sha256").update(local.raw).digest("hex"))??null};
 const fleetHandler=createFleetAgentHttpHandler({fleet,certificates,commands,rotation:runtime.services.certificates,commandSigner});
 const handler:RequestListener=(request,response)=>{const path=request.url?.split("?",1)[0]??"";if(path.startsWith("/agent/v1/enrollment/")){enrollment(request,response);return;}fleetHandler(request,response);};
 const server=createServer({key:material.key,cert:material.certificate,ca:material.ca,minVersion:"TLSv1.3",maxVersion:"TLSv1.3",requestCert:true,rejectUnauthorized:false,honorCipherOrder:true,maxHeaderSize:8192,requestTimeout:35_000,headersTimeout:5_000},handler);
 serverRotators.set(server,next=>{const nextParsed=parseTransportParsedLeaf(next.certificate,next.ca);if(!nextParsed.ok)throw new Error("ERR_AGENT_PLANE_CERTIFICATE");const nextSigner=buildTransportNativeSigner(next.key,nextParsed.value);if(!nextSigner.ok)throw new Error("ERR_AGENT_PLANE_CERTIFICATE");signers.set(nextParsed.value.fingerprint,nextSigner.value);server.setSecureContext({key:next.key,cert:next.certificate,ca:next.ca,minVersion:"TLSv1.3",maxVersion:"TLSv1.3"});});return server;
}
