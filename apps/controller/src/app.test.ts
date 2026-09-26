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
