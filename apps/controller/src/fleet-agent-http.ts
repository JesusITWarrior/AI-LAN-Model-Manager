import { createHash, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { TLSSocket } from "node:tls";
import type { CertificateRepository } from "./certificate-repository.js";
import type { FleetService } from "./fleet-service.js";
import type { AgentCommandService } from "./agent-command-channel.js";

export const FLEET_AGENT_BODY_LIMIT = 65_536;
export const FLEET_AGENT_RATE_LIMIT = 120;
export const FLEET_AGENT_RATE_WINDOW_MS = 60_000;
const MAX_RATE_KEYS = 2_048;
const PATHS = new Map([
  ["/agent/v1/fleet/hello", "transport.hello"],
  ["/agent/v1/fleet/heartbeat", "transport.heartbeat"],
  ["/agent/v1/commands/poll", "agent.command.poll"],
  ["/agent/v1/commands/result", "agent.command.result"],
]);

type Rate = { count: number; resetAt: number };
export interface FleetAgentHttpDependencies { readonly fleet: FleetService; readonly certificates: CertificateRepository; readonly commands?: AgentCommandService }
export interface FleetAgentHttpOptions { readonly clock?: () => number; readonly bodyLimit?: number; readonly rateLimit?: number; readonly rateWindowMs?: number }

function send(response: ServerResponse, status: number, body: unknown): void {
  if (response.headersSent) return;
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
  return { fingerprint: createHash("sha256").update(certificate.raw).digest("hex"), serial: certificate.serialNumber.toUpperCase().replace(/^0+/, "") || "0" };
}
function equal(left: string, right: string): boolean { const a = Buffer.from(left), b = Buffer.from(right); return a.length === b.length && timingSafeEqual(a, b); }

/** Closed-by-default fleet adapter: construction never opens or attaches a listener. */
export function createFleetAgentHttpHandler(deps: FleetAgentHttpDependencies, options: FleetAgentHttpOptions = {}): (request: IncomingMessage, response: ServerResponse) => void {
  const clock = options.clock ?? Date.now, bodyLimit = options.bodyLimit ?? FLEET_AGENT_BODY_LIMIT, rateLimit = options.rateLimit ?? FLEET_AGENT_RATE_LIMIT, windowMs = options.rateWindowMs ?? FLEET_AGENT_RATE_WINDOW_MS;
  if (![bodyLimit, rateLimit, windowMs].every(v => Number.isSafeInteger(v) && v > 0) || bodyLimit > FLEET_AGENT_BODY_LIMIT || rateLimit > FLEET_AGENT_RATE_LIMIT || windowMs > FLEET_AGENT_RATE_WINDOW_MS) throw new Error("ERR_FLEET_HTTP_OPTIONS");
  const rates = new Map<string, Rate>();
  return (request, response) => {
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
    const declared = request.headers["content-length"];
    if (Array.isArray(declared) || declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > bodyLimit)) { request.resume(); fail(response, 413); return; }
    const chunks: Buffer[] = []; let length = 0, done = false, overflow = false;
    request.on("data", chunk => { if (done || overflow) return; if (!(typeof chunk === "string" || chunk instanceof Uint8Array)) { overflow = true; return; } const value = Buffer.from(chunk); length += value.byteLength; if (length > bodyLimit) { overflow = true; return; } chunks.push(value); });
    request.on("error", () => { if (!done) { done = true; fail(response, 400); } });
    request.on("end", async () => {
      if (done) return; done = true; if (overflow) { fail(response, 413); return; }
      let input: unknown; try { input = JSON.parse(Buffer.concat(chunks, length).toString("utf8")); } catch { fail(response, 400); return; }
      const envelope = exactEnvelope(input, expectedType);
      if (!envelope || !equal(envelope.certFingerprint, certificate.fingerprint) || BigInt(`0x${envelope.certSerial}`) !== BigInt(`0x${certificate.serial}`)) { fail(response, 401, "ERR_HOST_REVOKED"); return; }
      const record = deps.certificates.getBySerial(envelope.certSerial, envelope.certFingerprint);
      if (!record || record.status !== "active") { fail(response, 401, "ERR_HOST_REVOKED"); return; }
      if (expectedType.startsWith("agent.command.")) {
        if (!deps.commands) { fail(response, 404); return; }
        const result = deps.commands.ingest(input, record.binding.address);
        if (!result.ok) { fail(response, result.error === "ERR_COMMAND_AUTH" || result.error === "ERR_COMMAND_BINDING" ? 401 : 400, result.error); return; }
        if (expectedType === "agent.command.poll") {
          try { const waitMs=(input as {payload:{waitMs:number}}).payload.waitMs;const polled=await deps.commands.wait(record.binding.candidateId,result.result,waitMs);send(response, 200, deps.commands.signed(record.binding.candidateId, (input as {requestId:string}).requestId, (input as {sequence:number}).sequence, polled)); }
          catch { fail(response, 500, "ERR_COMMAND_SIGN"); }
        } else send(response, 200, { ok: true });
        return;
      }
      const result = deps.fleet.ingest(input, record.binding.address);
      send(response, 200, result);
    });
  };
}
