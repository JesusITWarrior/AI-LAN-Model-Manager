import { readFile, realpathSync, statSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { dirname, extname, isAbsolute, join, normalize, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export type ConsoleStaticHandler = (request: IncomingMessage, response: ServerResponse) => void;
export interface ConsoleStaticOptions { readonly root?: string; readonly maxFileBytes?: number }
export const DEFAULT_MAX_FILE_BYTES = 33_554_432;
export const DEFAULT_WEB_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../web/dist");

const MIME = new Map<string, string>([
  [".html", "text/html; charset=utf-8"], [".js", "application/javascript; charset=utf-8"],
  [".mjs", "application/javascript; charset=utf-8"], [".css", "text/css; charset=utf-8"],
  [".json", "application/json; charset=utf-8"], [".map", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"], [".ico", "image/x-icon"], [".png", "image/png"],
  [".webp", "image/webp"], [".woff", "font/woff"], [".woff2", "font/woff2"],
]);
const SECURITY = {
  "content-security-policy": "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; connect-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
} as const;
const RESERVED = /^(?:\/auth(?:\/|$)|\/api(?:\/|$)|\/agent(?:\/|$)|\/v1(?:\/|$)|\/health(?:\/|$))/;
const HASHED = /(?:^|\/)[^/]+-[A-Za-z0-9_-]{6,}\.[A-Za-z0-9]+$/;

type ErrorCode = "INVALID_REQUEST" | "METHOD_NOT_ALLOWED" | "NOT_FOUND" | "PAYLOAD_TOO_LARGE" | "INTERNAL_ERROR";
function sendError(response: ServerResponse, status: number, code: ErrorCode, allow?: string): void {
  if (response.headersSent) { response.destroy(); return; }
  response.writeHead(status, { ...SECURITY, "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...(allow ? { allow } : {}) });
  response.end(JSON.stringify({ ok: false, error: { code, message: "Request failed." } }));
}
function contained(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}
/** Reject a symlink escape even when the final navigation target does not exist. */
function nearestExistingAncestorIsContained(root: string, candidate: string): boolean {
  let current = candidate;
  for (;;) {
    try { return contained(root, realpathSync(current)); } catch { /* inspect parent */ }
    if (current === root) return false;
    const parent = dirname(current);
    if (parent === current || !contained(root, parent)) return false;
    current = parent;
  }
}
function decodePath(raw: string): string | null {
  if (raw.length === 0 || raw.length > 4096 || raw.includes("#") || raw.includes("\\") || raw.includes("\0")) return null;
  const query = raw.indexOf("?");
  if (query >= 0 && raw.length - query - 1 > 2048) return null;
  const encoded = query < 0 ? raw : raw.slice(0, query);
  if (/%(?![0-9A-Fa-f]{2})/.test(encoded) || /%25[0-9A-Fa-f]{2}/i.test(encoded)) return null;
  let decoded: string;
  try { decoded = decodeURIComponent(encoded); } catch { return null; }
  if (/[%\\\u0000-\u001f\u007f]/.test(decoded)) return null;
  if (!decoded.startsWith("/") || decoded.includes("//")) return null;
  const segments = decoded.split("/");
  if (segments.some(part => part === "." || part === "..")) return null;
  return decoded;
}

/** Create a final, catch-all same-origin handler for the built console. */
export function createConsoleStaticHandler(options: ConsoleStaticOptions = {}): ConsoleStaticHandler {
  const configured = options.root ?? DEFAULT_WEB_ROOT;
  const max = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  let root: string | null = null;
  try {
    if (typeof configured === "string" && isAbsolute(configured) && normalize(configured) === configured && !configured.endsWith(sep) && Number.isSafeInteger(max) && max > 0) {
      const canonical = realpathSync(configured);
      if (statSync(canonical).isDirectory()) root = canonical;
    }
  } catch { root = null; }

  return (request, response) => {
    const method = request.method ?? "";
    if (method !== "GET" && method !== "HEAD") { request.resume(); sendError(response, 405, "METHOD_NOT_ALLOWED", "GET, HEAD"); return; }
    const pathname = decodePath(request.url ?? "");
    if (!root || pathname === null) { sendError(response, pathname === null ? 400 : 404, pathname === null ? "INVALID_REQUEST" : "NOT_FOUND"); return; }
    if (RESERVED.test(pathname)) { sendError(response, 404, "NOT_FOUND"); return; }

    const requested = resolve(root, `.${pathname}`);
    if (!contained(root, requested) || !nearestExistingAncestorIsContained(root, requested)) { sendError(response, 404, "NOT_FOUND"); return; }
    const extension = extname(pathname).toLowerCase();
    if (extension && !MIME.has(extension)) { sendError(response, 404, "NOT_FOUND"); return; }

    let target = requested;
    let index = pathname === "/" || pathname === "/index.html";
    try {
      const stats = statSync(target);
      if (stats.isDirectory()) throw new Error("directory");
    } catch {
      if (extension || pathname.startsWith("/assets/")) { sendError(response, 404, "NOT_FOUND"); return; }
      target = join(root, "index.html");
      index = true;
    }

    let canonical: string;
    let size: number;
    try {
      canonical = realpathSync(target);
      if (!contained(root, canonical)) { sendError(response, 404, "NOT_FOUND"); return; }
      const stats = statSync(canonical);
      if (!stats.isFile()) { sendError(response, 404, "NOT_FOUND"); return; }
      size = stats.size;
    } catch { sendError(response, 404, "NOT_FOUND"); return; }
    const finalExtension = extname(canonical).toLowerCase();
    const mime = MIME.get(finalExtension);
    if (!mime) { sendError(response, 404, "NOT_FOUND"); return; }
    if (!Number.isSafeInteger(size) || size < 0 || size > max) { sendError(response, 413, "PAYLOAD_TOO_LARGE"); return; }

    const headers = { ...SECURITY, "content-type": mime, "content-length": String(size), "cache-control": index ? "no-store" : HASHED.test(pathname) ? "public, max-age=31536000, immutable" : "no-cache" };
    if (method === "HEAD") { response.writeHead(200, headers); response.end(); return; }
    readFile(canonical, (error, body) => {
      if (error || body.length !== size || body.length > max) { sendError(response, 500, "INTERNAL_ERROR"); return; }
      response.writeHead(200, headers);
      response.end(body);
    });
  };
}
