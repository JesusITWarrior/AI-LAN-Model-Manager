import assert from "node:assert/strict";
import test from "node:test";
import { planPlacement } from "./placement.js";
import type { HostSnapshot, PlacementRequest } from "./types.js";

const gib = 1024 ** 3;
const request: PlacementRequest = {
  modelId: "example/model",
  requirements: { runtime: "example-runtime", memoryBytes: 8*gib, vramBytes: 6*gib, diskBytes: 12*gib }
};

function host(overrides: Partial<HostSnapshot>): HostSnapshot {
  return {
    hostId: "host-a", authorized: true, online: true, observationFresh: true,
    runtimes: ["example-runtime"],
    available: { memoryBytes: 32*gib, vramBytes: 16*gib, diskBytes: 100*gib },
    reserve: { memoryBytes: 4*gib, vramBytes: 2*gib, diskBytes: 20*gib },
    models: [], ...overrides
  };
}

test("rejects stale and under-resourced hosts before ranking", () => {
  const plan = planPlacement(request, [
    host({ hostId: "stale", observationFresh: false }),
    host({ hostId: "small", available: { memoryBytes: 10*gib, vramBytes: 7*gib, diskBytes: 25*gib } })
  ]);
  assert.equal(plan.selected, null);
  assert.equal(plan.rejected.length, 2);
  assert.match(plan.rejected[0]?.reasons.join(" ") ?? "", /stale/);
  assert.match(plan.rejected[1]?.reasons.join(" ") ?? "", /memory|VRAM|storage/);
});

test("prefers a loaded model over a host requiring acquisition", () => {
  const plan = planPlacement(request, [
    host({ hostId: "install-target" }),
    host({ hostId: "ready-target", models: [{ modelId: request.modelId, state: "loaded_idle",
      activeRequests: 0, installed: true, managedTemporary: false, pinned: true }] })
  ]);
  assert.equal(plan.selected?.hostId, "ready-target");
  assert.equal(plan.selected?.acquisition, "none");
});

test("does not require installation disk space for an installed model", () => {
  const plan = planPlacement(request, [host({
    hostId: "installed-target",
    available: { memoryBytes: 32*gib, vramBytes: 16*gib, diskBytes: 20*gib },
    models: [{ modelId: request.modelId, state: "installed", activeRequests: 0,
      installed: true, managedTemporary: false, pinned: false }]
  })]);
  assert.equal(plan.selected?.hostId, "installed-target");
});
