import {canonicalCertificateSerial,sameCertificateSerial} from "@lan-model-manager/core";
import { createHash, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { TransportSigner } from "@lan-model-manager/core";
import type { TLSSocket } from "node:tls";
import type { CertificateRepository } from "./certificate-repository.js";
import type { FleetService } from "./fleet-service.js";
import type { AgentCommandService } from "./agent-command-channel.js";

export const FLEET_AGENT_BODY_LIMIT = 65_536;
export const AGENT_COMMAND_RESULT_BODY_LIMIT = 786_432;
export const FLEET_AGENT_RATE_LIMIT = 120;
export const FLEET_AGENT_RATE_WINDOW_MS = 60_000;
const MAX_RATE_KEYS = 2_048;
const PATHS = new Map([
  ["/agent/v1/fleet/hello", "transport.hello"],
  ["/agent/v1/fleet/heartbeat", "transport.heartbeat"],
  ["/agent/v1/commands/poll", "agent.command.poll"],
  ["/agent/v1/commands/result", "agent.command.result"],
  ["/agent/v1/certificate/rotate", "certificate.rotate"],
]);

type Rate = { count: number; resetAt: number };
export interface FleetAgentHttpDependencies { readonly fleet: FleetService; readonly certificates: CertificateRepository; readonly commands?: AgentCommandService; readonly streams?:(request:IncomingMessage,response:ServerResponse)=>boolean; readonly artifacts?: { handle(request:IncomingMessage,response:ServerResponse):Promise<boolean> }; readonly rotation?: { rotate(serial:string,fingerprint:string,csrPem:string):{certificate:{certificatePem:string;fingerprint:string;serial:string;notBefore:string;notAfter:string};caCertificatePem:string}|null }; readonly commandSigner?: (request:IncomingMessage)=>TransportSigner|null }
export interface FleetAgentHttpOptions { readonly clock?: () => number; readonly bodyLimit?: number; readonly rateLimit?: number; readonly rateWindowMs?: number; readonly bodyTimeoutMs?: number }

function send(response: ServerResponse, status: number, body: unknown): void {
  if (response.headersSent || response.destroyed || response.writableEnded) return;
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.setHeader("cache-control", "no-store");
  response.setHeader("x-content-type-options", "nosniff");
  response.writeHead(status);
  response.end(JSON.stringify(body));
}
function fail(response: ServerResponse, status: number, error = "ERR_FLEET_INPUT"): void { send(response, status, { ok: false, error }); }
function exactEnvelope(input: unknown, messageType: string): { certFingerprint: string; certSerial: string } | null {
  if (typeof input !== "object" || input === null || Array.isArray(input)) return null;
  const value = input as Record<string, unknown>;
  return value.messageType === messageType && typeof value.certFingerprint === "string" && /^[a-f0-9]{64}$/.test(value.certFingerprint) && typeof value.certSerial === "string" && /^[A-F0-9]{1,64}$/.test(value.certSerial)
    ? { certFingerprint: value.certFingerprint, certSerial: value.certSerial } : null;
}
function peer(request: IncomingMessage): { fingerprint: string; serial: string } | null {
  const socket = request.socket as TLSSocket;
  if (socket.authorized !== true || typeof socket.getPeerCertificate !== "function") return null;
  const certificate = socket.getPeerCertificate(true);
  if (!certificate || !certificate.raw || typeof certificate.serialNumber !== "string") return null;
  const serial=canonicalCertificateSerial(certificate.serialNumber.toUpperCase());
  return serial===null?null:{ fingerprint: createHash("sha256").update(certificate.raw).digest("hex"), serial };
}
function equal(left: string, right: string): boolean { const a = Buffer.from(left), b = Buffer.from(right); return a.length === b.length && timingSafeEqual(a, b); }

/** Closed-by-default adapter. Own at most 16 accepted uploads/processing waits,
 * four per certificate (including long polls), with a 10s upload deadline.
 * shutdown synchronously fences the generation and aborts sockets, then joins
 * every async end continuation before the runtime may close its database. */
export type FleetAgentHttpHandler = ((request: IncomingMessage, response: ServerResponse) => void) & { shutdown():Promise<void>; stats():{inflight:number;retainedBytes:number;processing:number} };
export function createFleetAgentHttpHandler(deps: FleetAgentHttpDependencies, options: FleetAgentHttpOptions = {}): FleetAgentHttpHandler {
  const clock = options.clock ?? Date.now, bodyLimit = options.bodyLimit ?? FLEET_AGENT_BODY_LIMIT, rateLimit = options.rateLimit ?? FLEET_AGENT_RATE_LIMIT, windowMs = options.rateWindowMs ?? FLEET_AGENT_RATE_WINDOW_MS;
  if (![bodyLimit, rateLimit, windowMs].every(v => Number.isSafeInteger(v) && v > 0) || bodyLimit > FLEET_AGENT_BODY_LIMIT || rateLimit > FLEET_AGENT_RATE_LIMIT || windowMs > FLEET_AGENT_RATE_WINDOW_MS) throw new Error("ERR_FLEET_HTTP_OPTIONS");
  const bodyTimeoutMs=options.bodyTimeoutMs??10_000;
  if(!Number.isSafeInteger(bodyTimeoutMs)||bodyTimeoutMs<1||bodyTimeoutMs>10_000)throw new Error("ERR_FLEET_HTTP_OPTIONS");
  const rates = new Map<string, Rate>(), active=new Map<string,number>();
  const owners=new Set<()=>void>(),joins=new Set<Promise<void>>();let closed=false,inflight=0,retainedBytes=0;
  const handler: (request:IncomingMessage,response:ServerResponse)=>void = (request, response) => {
    // Fence the old generation synchronously, including requests on reused sockets.
    if(closed){request.destroy();response.destroy();return;}
    if(deps.streams?.(request,response))return;
    if(request.method==="GET"&&request.url?.startsWith("/agent/v1/artifacts/")){if(!deps.artifacts){request.resume();fail(response,404);return;}void deps.artifacts.handle(request,response).catch(()=>fail(response,500));return;}
    const expectedType = request.url ? PATHS.get(request.url) : undefined;
    if (request.method !== "POST" || !expectedType) { request.resume(); fail(response, 404); return; }
    if ((request.headers["content-type"] ?? "").toString().toLowerCase() !== "application/json") { request.resume(); fail(response, 415); return; }
    const certificate = peer(request);
    if (!certificate) { request.resume(); fail(response, 401, "ERR_HOST_REVOKED"); return; }
    const now = clock(); if (!Number.isSafeInteger(now) || now < 0) { request.resume(); fail(response, 500); return; }
    const rateKey = certificate.fingerprint;
    let rate = rates.get(rateKey); if (!rate || now >= rate.resetAt) { rate = { count: 0, resetAt: now + windowMs }; rates.set(rateKey, rate); }
    if (rate.count >= rateLimit) { request.resume(); fail(response, 429); return; } rate.count++;
    if (rates.size > MAX_RATE_KEYS) rates.delete(rates.keys().next().value!);
    if(inflight>=16||(active.get(rateKey)??0)>=4){request.resume();fail(response,429);return;}
    const requestBodyLimit=expectedType==="agent.command.result"?AGENT_COMMAND_RESULT_BODY_LIMIT:bodyLimit;
    const declared = request.headers["content-length"];
    if (Array.isArray(declared) || declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > requestBodyLimit)) { request.resume(); fail(response, 413); return; }
    const chunks: Buffer[] = []; let length = 0, done = false, processing=false, released=false;
    const controller=new AbortController();let destroyTimer:ReturnType<typeof setTimeout>|undefined;let joined!:()=>void;
    const join=new Promise<void>(resolve=>{joined=resolve;});joins.add(join);
    inflight++;active.set(rateKey,(active.get(rateKey)??0)+1);
    const clearBody=()=>{retainedBytes-=length;length=0;chunks.length=0;};
    const detachUpload=()=>{request.off("data",data);request.off("end",end);};
    const release=()=>{if(released)return;released=true;done=true;clearTimeout(timer);if(destroyTimer)clearTimeout(destroyTimer);clearBody();detachUpload();response.off?.("finish",abort);request.off("error",error);request.off("aborted",abort);response.off?.("close",abort);owners.delete(abort);inflight--;const n=(active.get(rateKey)??1)-1;if(n)active.set(rateKey,n);else active.delete(rateKey);if(!processing){joins.delete(join);joined();}};
    const abort=()=>{controller.abort();request.destroy();response.destroy();release();};
    const terminate=(status:number)=>{if(released)return;done=true;clearTimeout(timer);clearBody();detachUpload();response.setHeader("connection","close");response.once?.("finish",abort);destroyTimer=setTimeout(abort,100);destroyTimer.unref();fail(response,status);};
    const error=()=>abort();
    const timer=setTimeout(()=>terminate(408),bodyTimeoutMs);timer.unref();
    const data=(chunk:unknown)=>{if(done||closed)return;if(!(typeof chunk==="string"||chunk instanceof Uint8Array)){terminate(400);return;}const value=Buffer.from(chunk);if(length+value.byteLength>requestBodyLimit){terminate(413);return;}chunks.push(value);length+=value.byteLength;retainedBytes+=value.byteLength;};
    const end=()=>{
      if(done||closed)return;done=true;processing=true;clearTimeout(timer);detachUpload();
      // EventEmitter does not consume rejected async listeners. Own and join the
      // complete continuation, including signed long-poll processing.
      void (async()=>{try{
      if(closed||controller.signal.aborted)return;
      const body=Buffer.concat(chunks,length).toString("utf8");clearBody();
      let input: unknown; try { input = JSON.parse(body); } catch { fail(response, 400); return; }
      if(expectedType==="certificate.rotate"){
        const current=deps.certificates.getBySerial(certificate.serial,certificate.fingerprint),value=input as Record<string,unknown>;
        if(!deps.rotation||!current||typeof value!=="object"||value===null||Array.isArray(value)||Reflect.ownKeys(value).length!==1||typeof value.csrPem!=="string"||value.csrPem.length<64||value.csrPem.length>16384){fail(response,current?400:401,current?"ERR_CERTIFICATE_INPUT":"ERR_HOST_REVOKED");return;}
        try{const rotated=deps.rotation.rotate(certificate.serial,certificate.fingerprint,value.csrPem);if(!rotated){fail(response,409,"ERR_CERTIFICATE_ROTATION");return;}send(response,200,{ok:true,result:{certificatePem:rotated.certificate.certificatePem,caPem:rotated.caCertificatePem,fingerprint:rotated.certificate.fingerprint,serial:rotated.certificate.serial,notBefore:rotated.certificate.notBefore,notAfter:rotated.certificate.notAfter}});}catch{fail(response,400,"ERR_CERTIFICATE_ROTATION");}return;
      }
      const envelope = exactEnvelope(input, expectedType);
      if (!envelope || !equal(envelope.certFingerprint, certificate.fingerprint) || !sameCertificateSerial(envelope.certSerial,certificate.serial)) { fail(response, 401, "ERR_HOST_REVOKED"); return; }
      const record = deps.certificates.getBySerial(envelope.certSerial, envelope.certFingerprint);
      if (!record || record.status !== "active") { fail(response, 401, "ERR_HOST_REVOKED"); return; }
      if (expectedType.startsWith("agent.command.")) {
        if (!deps.commands) { fail(response, 404); return; }
        const result = deps.commands.ingest(input, record.binding.address);
        if (!result.ok) { fail(response, result.error === "ERR_COMMAND_AUTH" || result.error === "ERR_COMMAND_BINDING" ? 401 : 400, result.error); return; }
        if (expectedType === "agent.command.poll") {

          try { const waitMs=(input as {payload:{waitMs:number}}).payload.waitMs,signer=deps.commandSigner?.(request);if(deps.commandSigner&&!signer){fail(response,500,"ERR_COMMAND_SIGN");return;}const polled=await deps.commands.wait(record.binding.candidateId,result.result,waitMs,controller.signal);if(closed||controller.signal.aborted)return;send(response, 200, deps.commands.signed(record.binding.candidateId, (input as {requestId:string}).requestId, (input as {sequence:number}).sequence, polled,signer??undefined)); }
          catch(error) { if(!controller.signal.aborted){if(error instanceof Error&&error.message==="ERR_COMMAND_CLOSED")fail(response,503,"ERR_COMMAND_CLOSED");else fail(response,500,"ERR_COMMAND_SIGN");} }

        } else send(response, 200, { ok: true });
        return;
      }
      const result = deps.fleet.ingest(input, record.binding.address);
      send(response, 200, result);
      }catch{if(!closed&&!controller.signal.aborted)fail(response,500);}finally{release();joins.delete(join);joined();}})();
    };
    owners.add(abort);request.once("error",error);request.once("aborted",abort);response.once?.("close",abort);request.on("data",data);request.once("end",end);
  };
  return Object.assign(handler,{stats:()=>({inflight,retainedBytes,processing:joins.size}),shutdown:async()=>{closed=true;const pending=[...joins];for(const abort of [...owners])abort();rates.clear();await Promise.allSettled(pending);}});
}
