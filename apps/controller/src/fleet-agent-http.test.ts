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
