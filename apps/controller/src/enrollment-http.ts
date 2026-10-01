import type { IncomingMessage, ServerResponse } from "node:http";
import { routeEnrollmentRequest, type EnrollmentApiDependencies, type EnrollmentApiResponse } from "./enrollment-api.js";

export const ENROLLMENT_BODY_LIMIT = 24_576;
// A pending enrollment polls once per second for up to two minutes. Keep the
// per-address window bounded while allowing that documented client cadence.
export const ENROLLMENT_RATE_LIMIT = 120;
export const ENROLLMENT_RATE_WINDOW_MS = 60_000;
const MAX_RATE_KEYS = 1_024;

export interface EnrollmentHttpOptions {
  readonly clock?: () => number;
  readonly bodyLimit?: number;
  readonly rateLimit?: number;
  readonly rateWindowMs?: number;
}
type RateEntry = { count: number; resetAt: number };

function envelope(status: number, code: string, message: string): EnrollmentApiResponse {
  return { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }, body: { ok: false, error: { code, message } } };
}
function send(response: ServerResponse, result: EnrollmentApiResponse): void {
  if (response.headersSent) return;
  for (const [key, value] of Object.entries(result.headers)) response.setHeader(key, value);
  response.writeHead(result.status);
  response.end(JSON.stringify(result.body));
}
function publicHeaders(request: IncomingMessage): Record<string, string> | null {
  const output = Object.create(null) as Record<string, string>;
  for (const [key, value] of Object.entries(request.headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) return null;
    output[key] = value;
  }
  return output;
}

/** Dedicated injected adapter; constructing it never creates or opens a listener. */
export function createEnrollmentHttpHandler(deps: EnrollmentApiDependencies, options: EnrollmentHttpOptions = {}): (request: IncomingMessage, response: ServerResponse) => void {
  const clock = options.clock ?? Date.now;
  const bodyLimit = options.bodyLimit ?? ENROLLMENT_BODY_LIMIT;
  const rateLimit = options.rateLimit ?? ENROLLMENT_RATE_LIMIT;
  const windowMs = options.rateWindowMs ?? ENROLLMENT_RATE_WINDOW_MS;
  if (![bodyLimit, rateLimit, windowMs].every(value => Number.isSafeInteger(value) && value > 0) || bodyLimit > ENROLLMENT_BODY_LIMIT || rateLimit > ENROLLMENT_RATE_LIMIT || windowMs > ENROLLMENT_RATE_WINDOW_MS) throw new Error("ERR_ENROLLMENT_OPTIONS");
  const rates = new Map<string, RateEntry>();
  return (request, response) => {
    const now = clock();
    if (!Number.isSafeInteger(now) || now < 0) { send(response, envelope(500, "INTERNAL_ERROR", "Request failed.")); return; }
    const key = request.socket.remoteAddress ?? "unknown";
    let rate = rates.get(key);
    if (!rate || now >= rate.resetAt) { rate = { count: 0, resetAt: now + windowMs }; rates.delete(key); rates.set(key, rate); }
    if (rate.count >= rateLimit) { send(response, envelope(429, "RATE_LIMITED", "Too many requests.")); request.resume(); return; }
    rate.count++;
    if (rates.size > MAX_RATE_KEYS) rates.delete(rates.keys().next().value!);
    const declared = request.headers["content-length"];
    if (Array.isArray(declared) || declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > bodyLimit)) { send(response, envelope(413, "PAYLOAD_TOO_LARGE", "Request body too large.")); request.resume(); return; }
    const chunks: Buffer[] = [];
    let length = 0, settled = false, overflow = false;
    request.on("data", chunk => {
      if (settled || overflow) return;
      if (!(typeof chunk === "string" || chunk instanceof Uint8Array)) { overflow = true; return; }
      const value = Buffer.from(chunk);
      length += value.byteLength;
      if (length > bodyLimit) { overflow = true; return; }
      chunks.push(value);
    });
    request.on("error", () => { if (!settled) { settled = true; send(response, envelope(400, "INVALID_REQUEST", "Invalid request.")); } });
    request.on("end", () => {
      if (settled) return;
      settled = true;
      if (overflow) { send(response, envelope(413, "PAYLOAD_TOO_LARGE", "Request body too large.")); return; }
      const headers = publicHeaders(request);
      if (!headers) { send(response, envelope(400, "INVALID_REQUEST", "Invalid request.")); return; }
      void routeEnrollmentRequest(deps, { method: request.method ?? "", url: request.url ?? "", headers, body: Buffer.concat(chunks, length).toString("utf8") }).then(result => send(response, result), () => send(response, envelope(500, "INTERNAL_ERROR", "Request failed.")));
    });
  };
}
