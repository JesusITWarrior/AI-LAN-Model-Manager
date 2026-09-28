import assert from "node:assert/strict";
import test from "node:test";
import { once } from "node:events";
import { createControllerServer } from "./app.js";

test("health reports a loopback-only development surface", async (context) => {
  const server = createControllerServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => server.close());
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const response = await fetch(`http://127.0.0.1:${address.port}/health`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    status: "ok", exposure: "development-loopback-only"
  });
});

test("controller delegates only versioned management paths to an injected handler", async (context) => {
  let calls=0;
  const server=createControllerServer((_request,response)=>{calls++;response.writeHead(204);response.end();});
  server.listen(0,"127.0.0.1");await once(server,"listening");context.after(()=>server.close());
  const address=server.address();assert.ok(address&&typeof address==="object");const base=`http://127.0.0.1:${address.port}`;
  assert.equal((await fetch(`${base}/api/v1/fleet/summary`)).status,204);
  assert.equal((await fetch(`${base}/health`)).status,200);
  assert.equal(calls,1);
});

test("controller keeps inference and management handlers on separate namespaces",async context=>{let management=0,inference=0;const server=createControllerServer((_request,response)=>{management++;response.writeHead(204);response.end();},(_request,response)=>{inference++;response.writeHead(200,{"content-type":"application/json"});response.end("{}");});server.listen(0,"127.0.0.1");await once(server,"listening");context.after(()=>server.close());const address=server.address();assert.ok(address&&typeof address==="object");const base=`http://127.0.0.1:${address.port}`;assert.equal((await fetch(`${base}/v1/models`)).status,200);assert.equal((await fetch(`${base}/api/v1/fleet/summary`)).status,204);assert.equal((await fetch(`${base}/v1x/models`)).status,404);assert.equal(management,1);assert.equal(inference,1);});
