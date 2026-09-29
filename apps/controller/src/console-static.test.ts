import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { request, createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createControllerServer } from "./app.js";
import { createConsoleStaticHandler } from "./console-static.js";

type Result = { status: number; headers: Record<string, string | string[] | undefined>; body: string };
function rootFixture(): string {
  const root = mkdtempSync(join(tmpdir(), "lanmm-web-"));
  mkdirSync(join(root, "assets"));
  writeFileSync(join(root, "index.html"), "<!doctype html><div id=\"root\"></div><script type=\"module\" src=\"/assets/index-AbCd1234.js\"></script>");
  writeFileSync(join(root, "assets/index-AbCd1234.js"), "fetch('/auth/v1/status');");
  writeFileSync(join(root, "plain.css"), "body{}");
  return root;
}
async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address(); if (!address || typeof address === "string") throw new Error("listen"); return address.port;
}
async function close(server: Server): Promise<void> { await new Promise<void>(resolve => server.close(() => resolve())); }
async function get(port: number, path: string, method = "GET"): Promise<Result> {
  return await new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port, path, method }, response => { const chunks: Buffer[] = []; response.on("data", chunk => chunks.push(Buffer.from(chunk))); response.on("end", () => resolve({ status: response.statusCode ?? 0, headers: response.headers, body: Buffer.concat(chunks).toString() })); });
    req.on("error", reject); req.end();
  });
}

test("serves root index and safe SPA navigation with strict headers", async t => {
  const root = rootFixture(); const server = createServer(createConsoleStaticHandler({ root })); const port = await listen(server);
  t.after(async () => { await close(server); rmSync(root, { recursive: true }); });
  for (const path of ["/", "/fleet/hosts"]) {
    const result = await get(port, path); assert.equal(result.status, 200); assert.match(result.body, /id="root"/);
    assert.equal(result.headers["cache-control"], "no-store"); assert.equal(result.headers["x-frame-options"], "DENY");
    assert.equal(result.headers["x-content-type-options"], "nosniff"); assert.equal(result.headers["referrer-policy"], "no-referrer");
    assert.match(String(result.headers["content-security-policy"]), /frame-ancestors 'none'/);
  }
});

test("serves allowlisted assets with correct cache and HEAD behavior", async t => {
  const root = rootFixture(); const server = createServer(createConsoleStaticHandler({ root })); const port = await listen(server);
  t.after(async () => { await close(server); rmSync(root, { recursive: true }); });
  const hashed = await get(port, "/assets/index-AbCd1234.js"); assert.equal(hashed.status, 200); assert.match(String(hashed.headers["content-type"]), /javascript/); assert.equal(hashed.headers["cache-control"], "public, max-age=31536000, immutable");
  const plain = await get(port, "/plain.css", "HEAD"); assert.equal(plain.status, 200); assert.equal(plain.body, ""); assert.equal(plain.headers["cache-control"], "no-cache");
});

test("rejects traversal, malformed/double encoding, NUL, backslash and query abuse", async t => {
  const root = rootFixture(); const server = createServer(createConsoleStaticHandler({ root })); const port = await listen(server);
  t.after(async () => { await close(server); rmSync(root, { recursive: true }); });
  for (const path of ["/../secret", "/%2e%2e/secret", "/%252e%252e%252fsecret", "/%GG", "/%00x", "/a%5cb", `/?${"x".repeat(2049)}`]) {
    const result = await get(port, path); assert.ok(result.status === 400 || result.status === 404, `${path}: ${result.status}`); assert.doesNotMatch(result.body, /lanmm-web|secret/);
  }
});

test("does not SPA-fallback for reserved planes, directories, or missing/unknown assets", async t => {
  const root = rootFixture(); mkdirSync(join(root, "folder")); const server = createServer(createConsoleStaticHandler({ root })); const port = await listen(server);
  t.after(async () => { await close(server); rmSync(root, { recursive: true }); });
  for (const path of ["/health/other", "/auth/x", "/api/v1/missing", "/agent/v1/enrollment/begin", "/v1/models", "/assets/", "/missing.js", "/secret.txt"]) assert.equal((await get(port, path)).status, 404, path);
});

test("rejects symlink escapes, oversized files and non-GET methods", async t => {
  const root = rootFixture(), outside = mkdtempSync(join(tmpdir(), "lanmm-out-")); writeFileSync(join(outside, "escape.js"), "secret"); symlinkSync(outside, join(root, "escape"));
  const server = createServer(createConsoleStaticHandler({ root, maxFileBytes: 8 })); const port = await listen(server);
  t.after(async () => { await close(server); rmSync(root, { recursive: true }); rmSync(outside, { recursive: true }); });
  assert.equal((await get(port, "/escape/escape.js")).status, 404);
  assert.equal((await get(port, "/escape/missing-navigation")).status, 404);
  assert.equal((await get(port, "/assets/index-AbCd1234.js")).status, 413);
  const post = await get(port, "/", "POST"); assert.equal(post.status, 405); assert.equal(post.headers.allow, "GET, HEAD");
});

test("controller route ordering preserves health/auth/api/v1 before final static handler", async t => {
  const root = rootFixture(); const marker = (name: string) => (_request: unknown, response: any) => { response.writeHead(200); response.end(name); };
  const server = createControllerServer(marker("api"), marker("inference"), marker("auth"), createConsoleStaticHandler({ root })); const port = await listen(server);
  t.after(async () => { await close(server); rmSync(root, { recursive: true }); });
  assert.match((await get(port, "/health")).body, /"status":"ok"/); assert.equal((await get(port, "/auth/v1/status")).body, "auth"); assert.equal((await get(port, "/api/v1/fleet")).body, "api"); assert.equal((await get(port, "/v1/models")).body, "inference"); assert.match((await get(port, "/settings")).body, /id="root"/);
});
