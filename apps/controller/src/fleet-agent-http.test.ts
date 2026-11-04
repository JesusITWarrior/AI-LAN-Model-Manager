import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import test from "node:test";
import { createFleetAgentHttpHandler } from "./fleet-agent-http.js";

const raw = Buffer.from("peer-certificate");
const fingerprint = createHash("sha256").update(raw).digest("hex");
function invoke(options: { path?: string; type?: string; active?: boolean; authorized?: boolean; authorization?: string; bodyFingerprint?: string } = {}) {
  let ingested = 0;
  const body = JSON.stringify({ messageType: options.type ?? "transport.hello", certFingerprint: options.bodyFingerprint ?? fingerprint, certSerial: "ABCD" });
  const request = Object.assign(new EventEmitter(), {
    method: "POST", url: options.path ?? "/agent/v1/fleet/hello",
    headers: { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)), ...(options.authorization ? { authorization: options.authorization } : {}) },
    socket: { authorized: options.authorized ?? true, getPeerCertificate: () => ({ raw, serialNumber: "ABCD" }) }, resume() {},
  });
  let status = 0, responseBody = "";
  const response = { headersSent: false, setHeader() {}, writeHead(value: number) { status = value; }, end(value = "") { responseBody = value; } };
  const certificates = { getBySerial: () => options.active === false ? { status: "revoked", binding: { address: "192.168.1.20" } } : { status: "active", binding: { address: "192.168.1.20" } } };
  const fleet = { ingest(_input: unknown, address: string) { ingested++; assert.equal(address, "192.168.1.20"); return { ok: true, result: { accepted: true, sequence: 1, nextHeartbeatIntervalMs: 30_000, nextHeartbeatIntervalJitterMs: 2_000, nextHeartbeatWindowMs: 60_000 } }; } };
  const handler = createFleetAgentHttpHandler({ fleet: fleet as never, certificates: certificates as never });
  handler(request as never, response as never); request.emit("data", Buffer.from(body)); request.emit("end");
  return { status, parsed: JSON.parse(responseBody), ingested };
}

test("dedicated fleet adapter accepts only exact mTLS route and message contract", () => {
  assert.deepEqual(invoke(), { status: 200, parsed: { ok: true, result: { accepted: true, sequence: 1, nextHeartbeatIntervalMs: 30_000, nextHeartbeatIntervalJitterMs: 2_000, nextHeartbeatWindowMs: 60_000 } }, ingested: 1 });
  assert.equal(invoke({ path: "/agent/v1/fleet/heartbeat", type: "transport.hello" }).status, 401);
  assert.equal(invoke({ path: "/management/v1/fleet/hello" }).status, 404);
});

test("management or inference credentials cannot replace an active client certificate", () => {
  const bearer = invoke({ authorized: false, authorization: "Bearer management-or-inference-secret" });
  assert.equal(bearer.status, 401); assert.equal(bearer.ingested, 0);
  const revoked = invoke({ active: false }); assert.equal(revoked.status, 401); assert.equal(revoked.ingested, 0);
  const commandCredentialConfusion=invoke({path:"/agent/v1/commands/poll",type:"agent.command.poll",authorized:false,authorization:"Bearer inference-token"});assert.equal(commandCredentialConfusion.status,401);
});

test("command routes reject wrong and revoked client certificates before dispatch",()=>{
  const wrong=invoke({path:"/agent/v1/commands/poll",type:"agent.command.poll",bodyFingerprint:"0".repeat(64)});assert.equal(wrong.status,401);assert.equal(wrong.ingested,0);
  const revoked=invoke({path:"/agent/v1/commands/result",type:"agent.command.result",active:false});assert.equal(revoked.status,401);assert.equal(revoked.ingested,0);
});

test("certificate rotation is mTLS-only and supports idempotent revoked-predecessor recovery",()=>{for(const statusValue of ["active","revoked"]){const body=JSON.stringify({csrPem:"-----BEGIN CERTIFICATE REQUEST-----\n"+"A".repeat(96)+"\n-----END CERTIFICATE REQUEST-----\n"}),request=Object.assign(new EventEmitter(),{method:"POST",url:"/agent/v1/certificate/rotate",headers:{"content-type":"application/json","content-length":String(Buffer.byteLength(body))},socket:{authorized:true,getPeerCertificate:()=>({raw,serialNumber:"ABCD"})},resume(){}});let status=0,responseBody="",calls=0;const response={headersSent:false,setHeader(){},writeHead(value:number){status=value},end(value=""){responseBody=value}},certificates={getBySerial:()=>({status:statusValue,binding:{address:"192.168.1.20"}})},rotation={rotate(serial:string,fp:string,csr:string){calls++;assert.equal(serial,"ABCD");assert.equal(fp,fingerprint);assert.match(csr,/BEGIN CERTIFICATE REQUEST/);return{certificate:{certificatePem:"cert",fingerprint:"f".repeat(64),serial:"EF",notBefore:"2026-01-01T00:00:00.000Z",notAfter:"2027-01-01T00:00:00.000Z"},caCertificatePem:"ca"}}};createFleetAgentHttpHandler({fleet:{} as never,certificates:certificates as never,rotation})(request as never,response as never);request.emit("data",Buffer.from(body));request.emit("end");assert.equal(status,200,responseBody);assert.equal(calls,1);assert.equal(JSON.parse(responseBody).result.fingerprint,"f".repeat(64));}}
);

function uploadFixture(handler:ReturnType<typeof createFleetAgentHttpHandler>,serial="ABCD",fpRaw=raw){
 const request=Object.assign(new EventEmitter(),{method:"POST",url:"/agent/v1/fleet/heartbeat",headers:{"content-type":"application/json"},complete:false,destroyed:false,socket:{authorized:true,getPeerCertificate:()=>({raw:fpRaw,serialNumber:serial})},resume(){},destroy(){this.destroyed=true;}});
 const response=Object.assign(new EventEmitter(),{headersSent:false,destroyed:false,writableEnded:false,status:0,setHeader(){},writeHead(status:number){this.status=status;this.headersSent=true;},end(){this.writableEnded=true;(this as typeof this & EventEmitter).emit("finish");},destroy(){this.destroyed=true;}});
 handler(request as never,response as never);return{request,response};
}

test("fleet uploads are globally/per-certificate bounded, detached and freed on shutdown; old generation never reaches DB",async()=>{
 let lookups=0;const handler=createFleetAgentHttpHandler({fleet:{} as never,certificates:{getBySerial(){lookups++;throw Error("DB_CLOSED");}} as never});
 const uploads=Array.from({length:4},()=>uploadFixture(handler));for(const{request}of uploads)request.emit("data",Buffer.alloc(100));
 assert.equal(uploadFixture(handler).response.status,429);
 for(let i=0;i<12;i++)uploads.push(uploadFixture(handler,"ABCD",Buffer.from(`peer-${i}`)));
 assert.equal(uploadFixture(handler,"ABCD",Buffer.from("global-overflow")).response.status,429);
 assert.deepEqual(handler.stats(),{inflight:16,retainedBytes:400,processing:16});
 const closing=handler.shutdown();assert.equal(handler.stats().inflight,0);await closing;
 assert.deepEqual(handler.stats(),{inflight:0,retainedBytes:0,processing:0});
 for(const{request,response}of uploads){assert.equal(request.destroyed,true);assert.equal(response.destroyed,true);for(const event of ["data","end","error","aborted"])assert.equal(request.listenerCount(event),0);assert.equal(response.listenerCount("close"),0);request.emit("end");}
 assert.equal(uploadFixture(handler).request.destroyed,true);assert.equal(lookups,0);
});

test("fleet body deadline and overflow abort owned uploads without processing",async()=>{
 const handler=createFleetAgentHttpHandler({fleet:{} as never,certificates:{} as never},{bodyTimeoutMs:20});
 const slow=uploadFixture(handler);slow.request.emit("data",Buffer.from("{"));
 await new Promise(resolve=>setTimeout(resolve,35));assert.equal(slow.response.status,408);assert.equal(slow.request.destroyed,true);
 const large=uploadFixture(handler);large.request.emit("data",Buffer.alloc(65_537));assert.equal(large.response.status,413);assert.equal(large.request.destroyed,true);
 assert.deepEqual(handler.stats(),{inflight:0,retainedBytes:0,processing:0});await handler.shutdown();
});

test("fleet shutdown joins processing, catches failures and fences late signed responses",async()=>{
 let finish!:(value:unknown)=>void,signed=0;const handler=createFleetAgentHttpHandler({fleet:{} as never,certificates:{getBySerial:()=>({status:"active",binding:{address:"127.0.0.1",candidateId:"agent-1"}})} as never,commands:{ingest:()=>({ok:true,result:{}}),wait:()=>new Promise(resolve=>{finish=resolve;}),signed(){signed++;throw Error("late DB");}} as never});
 const fixture=uploadFixture(handler); // Switch route before constructing the second fixture.
 fixture.request.emit("end"); // malformed JSON is safely caught, and owned listeners released.
 const request=Object.assign(new EventEmitter(),{method:"POST",url:"/agent/v1/commands/poll",headers:{"content-type":"application/json"},socket:{authorized:true,getPeerCertificate:()=>({raw,serialNumber:"ABCD"})},resume(){},destroy(){}});
 const response=Object.assign(new EventEmitter(),{headersSent:false,destroyed:false,setHeader(){},writeHead(){},end(){},destroy(){this.destroyed=true;}});
 handler(request as never,response as never);request.emit("data",Buffer.from(JSON.stringify({messageType:"agent.command.poll",certFingerprint:fingerprint,certSerial:"ABCD",payload:{waitMs:30000}})));request.emit("end");
 let settled=false;const closing=handler.shutdown().then(()=>{settled=true;});await Promise.resolve();assert.equal(settled,false);finish({});await closing;assert.equal(signed,0);assert.deepEqual(handler.stats(),{inflight:0,retainedBytes:0,processing:0});
});
