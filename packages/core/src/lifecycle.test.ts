import assert from "node:assert/strict";
import test from "node:test";
import { canEvict, canTransition, canUnload } from "./lifecycle.js";
import type { HostModelObservation } from "./types.js";

const model: HostModelObservation = {
  modelId: "example/model", state: "loaded_idle", activeRequests: 0,
  installed: true, managedTemporary: true, pinned: false
};

test("serving models must drain before becoming idle", () => {
  assert.equal(canTransition("serving", "loaded_idle"), false);
  assert.equal(canTransition("serving", "draining"), true);
  assert.equal(canTransition("draining", "loaded_idle"), true);
});

test("only an idle model without active requests can unload", () => {
  assert.equal(canUnload(model), true);
  assert.equal(canUnload({ ...model, state: "serving", activeRequests: 1 }), false);
  assert.equal(canUnload({ ...model, activeRequests: 1 }), false);
});

test("eviction is limited to inactive manager-owned unpinned cache entries", () => {
  assert.equal(canEvict({ ...model, state: "installed" }), true);
  assert.equal(canEvict({ ...model, state: "installed", pinned: true }), false);
  assert.equal(canEvict({ ...model, state: "installed", managedTemporary: false }), false);
  assert.equal(canEvict({ ...model, state: "installed", activeRequests: 1 }), false);
});
