import type { IncomingMessage, ServerResponse } from "node:http";
import { AUTH_BODY_LIMIT, routeAuthRequest, type AuthApiDependencies, type AuthHttpResponse } from "./owner-auth.js";

function publicHeaders(input: IncomingMessage["headers"]): Record<string, string> | null {
  const out = Object.create(null) as Record<string, string>;
  for (const [key, value] of Object.entries(input)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) return null;
    out[key] = value;
  }
  return out;
}
function send(response: ServerResponse, result: AuthHttpResponse): void {
  if (response.headersSent) return;
  const cookie = (result.headers["set-cookie"] ?? undefined) as string[] | string | undefined;
  if (Array.isArray(cookie)) { for (const c of cookie) response.setHeader("set-cookie", c); } else if (typeof cookie === "string") { response.setHeader("set-cookie", cookie); }
  for (const [key, value] of Object.entries(result.headers)) { if (key === "set-cookie") continue; response.setHeader(key, value); }
  response.writeHead(result.status);
  response.end(JSON.stringify(result.body));
}
function envelope(status: number, code: string, message: string): AuthHttpResponse { return Object.freeze({ status, headers: Object.freeze({ "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }), body: Object.freeze({ ok: false, error: Object.freeze({ code, message }) }) }); }

/** Adapt the pure auth router to Node HTTP without opening a listener. */
export function createAuthHttpHandler(deps: AuthApiDependencies): (request: IncomingMessage, response: ServerResponse) => void {
  return (request, response) => {
    const declared = request.headers["content-length"];
    if (typeof declared === "string" && (/^\d+$/.test(declared) === false || Number(declared) > AUTH_BODY_LIMIT)) { request.resume(); send(response, envelope(413, "PAYLOAD_TOO_LARGE", "Request body too large.")); return; }
    const chunks: Buffer[] = []; let bytes = 0, overflow = false, settled = false;
    const fail = () => { if (settled) return; settled = true; send(response, envelope(400, "INVALID_REQUEST", "Invalid request.")); };
    request.on("error", fail);
    request.on("data", (chunk: unknown) => { if (overflow) return; if (typeof chunk !== "string" && !Buffer.isBuffer(chunk)) { overflow = true; return; } const part = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); bytes += part.length; if (bytes > AUTH_BODY_LIMIT) { overflow = true; chunks.length = 0; return; } chunks.push(part); });
    request.on("end", () => { if (settled) return; settled = true; if (overflow) { send(response, envelope(413, "PAYLOAD_TOO_LARGE", "Request body too large.")); return; } const normalized = publicHeaders(request.headers); if (!normalized) { send(response, envelope(400, "INVALID_REQUEST", "Invalid request.")); return; } void routeAuthRequest(deps, { method: request.method ?? "", url: request.url ?? "", headers: normalized, body: Buffer.concat(chunks).toString("utf8") }).then(value => send(response, value), () => send(response, envelope(500, "INTERNAL_ERROR", "Request failed."))); });
  };
}
