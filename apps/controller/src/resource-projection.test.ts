import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import test from "node:test";
import { parseHeartbeatPayload } from "@lan-model-manager/core";

test("synthetic Go collector resources satisfy the authenticated heartbeat schema", () => {
  const output = execFileSync("go", ["test", "./cmd/lan-model-agent", "-run", "^TestCollectorResourceProjection$/^valid$", "-count=1", "-v"], {
    cwd: resolve(import.meta.dirname, "../../../agents/host-agent"), encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  });
  const match = /^SYNTHETIC_RESOURCE=(.+)$/m.exec(output);
  assert.ok(match);
  const payload = JSON.parse(match[1]!);
  const parsed = parseHeartbeatPayload(payload);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;
  assert.equal(parsed.value.resource?.hostId, "synthetic-host");
  assert.equal(parsed.value.resource?.platform, parsed.value.platform);
  assert.equal(parsed.value.resource?.observedAt, payload.observedAt);
  assert.deepEqual({ ...parsed.value.resource?.memory }, { totalBytes: 100, usedBytes: 20, availableBytes: 80 });
  assert.deepEqual(parsed.value.resource?.accelerators, []);
});
