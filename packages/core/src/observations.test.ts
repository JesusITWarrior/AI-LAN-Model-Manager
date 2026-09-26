import assert from "node:assert/strict";
import test from "node:test";
import {
  parseAcceleratorObservation,
  parseByteAmount,
  parseHostResourceObservation,
  parseResourceQuantity,
} from "./observations.js";

const quantity = (overrides: Record<string, unknown> = {}) => ({ totalBytes: 100, usedBytes: 40, availableBytes: 50, ...overrides });
const accelerator = (overrides: Record<string, unknown> = {}) => ({
  id: "gpu-0", name: "Example GPU", kind: "nvidia", memory: quantity(), utilizationPercent: 25, ...overrides,
});
const host = (overrides: Record<string, unknown> = {}) => ({
  hostId: "host-1", observedAt: "2026-09-26T09:00:00.000Z", platform: "linux",
  cpuLogicalCores: 16, cpuUtilizationPercent: 20, memory: quantity(), storage: quantity(),
  accelerators: [accelerator()], ...overrides,
});

test("parses byte boundaries", () => {
  assert.equal(parseByteAmount(0).ok, true);
  assert.equal(parseByteAmount(Number.MAX_SAFE_INTEGER).ok, true);
  for (const value of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1, "1", null]) assert.equal(parseByteAmount(value).ok, false);
});

test("enforces resource invariants while allowing unaccounted bytes", () => {
  assert.equal(parseResourceQuantity(quantity()).ok, true);
  assert.equal(parseResourceQuantity(quantity({ usedBytes: 40, availableBytes: 60 })).ok, true);
  for (const value of [quantity({ usedBytes: 101 }), quantity({ availableBytes: 101 }), quantity({ usedBytes: 60, availableBytes: 50 })])
    assert.deepStrictEqual(parseResourceQuantity(value), { ok: false, error: "ERR_RESOURCE_INVARIANT" });
});

test("parses accelerator kinds and utilization boundaries", () => {
  for (const kind of ["nvidia", "amd", "intel", "apple", "other"])
    assert.equal(parseAcceleratorObservation(accelerator({ kind })).ok, true);
  for (const utilizationPercent of [null, 0, 100])
    assert.equal(parseAcceleratorObservation(accelerator({ utilizationPercent })).ok, true);
  for (const utilizationPercent of [-1, 101, 1.5, "1"])
    assert.equal(parseAcceleratorObservation(accelerator({ utilizationPercent })).ok, false);
});

test("rejects invalid accelerator identifiers, names, kinds, and memory", () => {
  for (const value of [
    accelerator({ id: "bad/id" }), accelerator({ id: "" }), accelerator({ name: "bad\nname" }),
    accelerator({ name: "" }), accelerator({ kind: "cuda" }), accelerator({ memory: quantity({ usedBytes: 101 }) }),
  ]) assert.equal(parseAcceleratorObservation(value).ok, false);
});

test("parses host platform, CPU, and accelerator count boundaries", () => {
  for (const platform of ["linux", "darwin", "windows"])
    assert.equal(parseHostResourceObservation(host({ platform })).ok, true);
  for (const cpuLogicalCores of [1, 4096]) assert.equal(parseHostResourceObservation(host({ cpuLogicalCores })).ok, true);
  for (const cpuLogicalCores of [0, 4097, 1.5]) assert.equal(parseHostResourceObservation(host({ cpuLogicalCores })).ok, false);
  assert.equal(parseHostResourceObservation(host({ accelerators: [] })).ok, true);
  assert.equal(parseHostResourceObservation(host({ accelerators: Array.from({ length: 32 }, (_, id) => accelerator({ id: `gpu-${id}` })) })).ok, true);
  assert.equal(parseHostResourceObservation(host({ accelerators: Array.from({ length: 33 }, (_, id) => accelerator({ id: `gpu-${id}` })) })).ok, false);
});

test("rejects duplicate accelerator ids and invalid nested fields", () => {
  assert.deepStrictEqual(parseHostResourceObservation(host({ accelerators: [accelerator(), accelerator()] })), {
    ok: false, error: "ERR_DUPLICATE_ACCELERATOR",
  });
  for (const value of [host({ hostId: "bad/id" }), host({ observedAt: "bad" }), host({ platform: "bsd" }), host({ memory: quantity({ usedBytes: 101 }) })])
    assert.equal(parseHostResourceObservation(value).ok, false);
});

test("rejects exact-key violations, custom roots, and accessors without invocation", () => {
  assert.equal(parseHostResourceObservation({ ...host(), extra: true }).ok, false);
  const custom = Object.assign(Object.create({ inherited: true }), host());
  assert.equal(parseHostResourceObservation(custom).ok, false);
  const symbolValue = host(); Object.defineProperty(symbolValue, Symbol("extra"), { value: true });
  assert.equal(parseHostResourceObservation(symbolValue).ok, false);
  let invoked = false;
  const accessor = host(); Object.defineProperty(accessor, "memory", { get() { invoked = true; throw new Error("no"); } });
  assert.equal(parseHostResourceObservation(accessor).ok, false);
  assert.equal(invoked, false);
});

test("rejects sparse and decorated accelerator arrays", () => {
  const sparse = new Array(2); sparse[0] = accelerator({ id: "gpu-0" });
  assert.equal(parseHostResourceObservation(host({ accelerators: sparse })).ok, false);
  const decorated = [accelerator()] as unknown[] & { note?: string }; decorated.note = "no";
  assert.equal(parseHostResourceObservation(host({ accelerators: decorated })).ok, false);
  const symbolic = [accelerator()]; Object.defineProperty(symbolic, Symbol("extra"), { value: true });
  assert.equal(parseHostResourceObservation(host({ accelerators: symbolic })).ok, false);
});

test("returns detached deeply frozen null-prototype observations", () => {
  const input = host();
  const result = parseHostResourceObservation(input);
  assert.equal(result.ok, true); if (!result.ok) return;
  assert.equal(Object.getPrototypeOf(result.value), null);
  assert.equal(Object.isFrozen(result.value), true);
  assert.equal(Object.isFrozen(result.value.memory), true);
  assert.equal(Object.isFrozen(result.value.accelerators), true);
  assert.equal(Object.isFrozen(result.value.accelerators[0]), true);
  input.memory.usedBytes = 99;
  input.accelerators[0]!.name = "Changed";
  assert.equal(result.value.memory.usedBytes, 40);
  assert.equal(result.value.accelerators[0]?.name, "Example GPU");
});

test("never throws for hostile or revoked roots and arrays", () => {
  const hostile = new Proxy({}, { ownKeys() { throw new Error("hostile"); } });
  assert.doesNotThrow(() => parseHostResourceObservation(hostile));
  const revoked = Proxy.revocable(host(), {}); revoked.revoke();
  assert.doesNotThrow(() => parseHostResourceObservation(revoked.proxy));
  const arrayProxy = new Proxy([], { ownKeys() { throw new Error("hostile"); } });
  assert.doesNotThrow(() => parseHostResourceObservation(host({ accelerators: arrayProxy })));
});
