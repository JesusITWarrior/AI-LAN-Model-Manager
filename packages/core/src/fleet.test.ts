import test from "node:test";
import assert from "node:assert/strict";
import {
  FLEET_MAX_HOST_MODELS,
  FLEET_MAX_HOST_PROVIDERS,
  FLEET_MIN_HEARTBEAT_INTERVAL_MS,
  FLEET_MAX_HEARTBEAT_INTERVAL_MS,
  FLEET_MAX_HEARTBEAT_INTERVAL_JITTER_MS,
  FLEET_MIN_HEARTBEAT_WINDOW_MS,
  parseHeartbeatInterval,
  parseHeartbeatJitter,
  parseHeartbeatWindow,
  parseHelloPayload,
  parseHeartbeatPayload,
  parseHelloResult,
  parseHeartbeatResult,
  parseFleetResult,
  parseFleetErrorCode,
} from "./fleet.js";

const NOW = "2026-09-27T20:00:00.000Z";
const PLATFORMS = ["linux", "darwin", "windows"] as const;

function hello(o: Record<string, unknown> = {}): unknown {
  return { platform: "linux", protocolMinor: 0, observedAt: NOW, ...o };
}
function heartbeat(o: Record<string, unknown> = {}): unknown {
  return { platform: "linux", protocolMinor: 0, idle: true, observedAt: NOW, sequence: 1, ...o };
}

test("hello payload parses exact keys and rejects extras", () => {
  const ok = parseHelloPayload(hello());
  assert.ok(ok.ok);
  const rejected = parseHelloPayload(hello({ extra: 1 }));
  assert.equal(rejected.ok, false);
  const missing = parseHelloPayload({ platform: "linux", protocolMinor: 0 });
  assert.equal(missing.ok, false);
});

test("hello platform is restricted and protocol minor bounded", () => {
  assert.equal(parseHelloPayload(hello({ platform: "freebsd" })).ok, false);
  assert.equal(parseHelloPayload(hello({ platform: "linux", protocolMinor: 65_536 })).ok, false);
  assert.equal(parseHelloPayload(hello({ platform: "linux", protocolMinor: -1 })).ok, false);
  assert.ok(parseHelloPayload(hello({ platform: "darwin" })).ok);
});

test("hello clamps interval/jitter/window ranges and rejects oob", () => {
  const min = FLEET_MIN_HEARTBEAT_INTERVAL_MS;
  const max = FLEET_MAX_HEARTBEAT_INTERVAL_MS;
  assert.equal(parseHelloPayload(hello({ preferredIntervalMs: min - 1 })).ok, false);
  assert.equal(parseHelloPayload(hello({ preferredIntervalMs: min })).ok, true);
  assert.equal(parseHelloPayload(hello({ preferredIntervalMs: max })).ok, true);
  assert.equal(parseHelloPayload(hello({ preferredIntervalMs: max + 1 })).ok, false);
  assert.equal(parseHelloPayload(hello({ preferredWindowMs: FLEET_MIN_HEARTBEAT_WINDOW_MS - 1 })).ok, false);
  // Optional model accepted; too long / bad id rejected.
  assert.ok(parseHelloPayload(hello({ model: "acme/model:latest" })).ok);
  assert.equal(parseHelloPayload(hello({ model: "bad model" })).ok, false);
});

test("heartbeat payload: no providers/models means optional inventory", () => {
  const base = parseHeartbeatPayload(heartbeat({ providers: undefined, models: undefined }));
  assert.ok(base.ok);
  const withProviders = parseHeartbeatPayload(
    heartbeat({ providers: [{ providerId: "p1", kind: "ollama", displayName: "P1", endpoint: "http://127.0.0.1:11434", health: "ready", version: "1.0.0", observedAt: NOW }] }),
  );
  assert.ok(withProviders.ok);
  assert.equal(withProviders.value!.providers!.length, 1);
});

test("heartbeat rejects provider/model cardinality, invalid ids, bad sequence", () => {
  const many = Array.from({ length: FLEET_MAX_HOST_PROVIDERS + 1 }, (_v, i) => ({ providerId: `p${i}`, kind: "ollama", displayName: "p", endpoint: "http://127.0.0.1:11434", health: "ready", version: "", versionKnown: false, observedAt: NOW }));
  const tooMany = parseHeartbeatPayload(heartbeat({ providers: many }));
  assert.equal(tooMany.ok, false);
  const oneOf = parseHeartbeatPayload(heartbeat({ providers: [{ providerId: "p1" }] }));
  // provider dto is strict: missing fields => invalid inventory
  assert.equal(oneOf.ok, false);
  const badSeq = parseHeartbeatPayload(heartbeat({ sequence: 0 }));
  assert.equal(badSeq.ok, false);
  const badIdle = parseHeartbeatPayload(heartbeat({ idle: "yes" }));
  assert.equal(badIdle.ok, false);
});

test("heartbeat platform and protocol are validated like hello", () => {
  assert.equal(parseHeartbeatPayload(heartbeat({ platform: "freebsd" })).ok, false);
  assert.equal(parseHeartbeatPayload(heartbeat({ protocolMinor: 70_000 })).ok, false);
});

test("hello / heartbeat result parsing honours accepted + interval/jitter/window", () => {
  const result = parseHelloResult({
    accepted: true,
    sequence: 7,
    nextHeartbeatIntervalMs: FLEET_MIN_HEARTBEAT_INTERVAL_MS,
    nextHeartbeatIntervalJitterMs: 0,
    nextHeartbeatWindowMs: FLEET_MIN_HEARTBEAT_WINDOW_MS,
  });
  assert.ok(result.ok);
  assert.equal(result.value!.sequence, 7);
  const jitterOut = parseHeartbeatJitter(FLEET_MAX_HEARTBEAT_INTERVAL_JITTER_MS + 1);
  assert.equal(jitterOut.ok, false);
  const intervalOut = parseHeartbeatInterval(FLEET_MIN_HEARTBEAT_INTERVAL_MS - 1);
  assert.equal(intervalOut.ok, false);
  const windowOut = parseHeartbeatWindow(FLEET_MIN_HEARTBEAT_WINDOW_MS);
  assert.ok(windowOut.ok);
});

test("fleet result discriminates ok:true/result and ok:false/error codes", () => {
  const okResult = parseFleetResult({ ok: true, result: { accepted: true, sequence: 1, nextHeartbeatIntervalMs: 1000, nextHeartbeatIntervalJitterMs: 0, nextHeartbeatWindowMs: 1000 } });
  assert.ok(okResult.ok);
  const errResult = parseFleetResult({ ok: false, error: "ERR_HOST_REVOKED" });
  assert.ok(errResult.ok);
  assert.equal(errResult.value!.ok, false);
  assert.equal((errResult.value as any).error, "ERR_HOST_REVOKED");
  const badCode = parseFleetResult({ ok: false, error: "lowercase" });
  assert.equal(badCode.ok, false);
  assert.equal(parseFleetErrorCode("ERR_HOST_REVOKED").ok, true);
  assert.equal(parseFleetErrorCode("bogus").ok, false);
});

test("cardinality constants are wired and reasonable", () => {
  assert.ok(FLEET_MAX_HOST_PROVIDERS > 0);
  assert.ok(FLEET_MAX_HOST_MODELS > 0);
});
