import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { commandAuthorizationDigest, parseCommandRequest, type CommandRequest } from "@lan-model-manager/core";
import { classifyNativeTerminal } from "./native-terminal-classification.js";
import { encodeNativeTerminalEvidence, decodeNativeTerminalEvidence, MAX_EVIDENCE_PAYLOAD_BYTES,
  MAX_EVIDENCE_RESPONSE_BYTES, type NativeEvidenceCodecResult } from "./native-terminal-evidence-codec.js";

const TIME = "2026-11-04T16:15:43.000Z";
const FULL_PAYLOAD_GOLDEN_BASE64 = "eyJkb21haW4iOiJsYW5tbS1uYXRpdmUtdGVybWluYWwtZXZpZGVuY2UtcGF5bG9hZC12MSIsImtpbmQiOiJhZ2VudC5jb21tYW5kLnRlcm1pbmFsLWV2aWRlbmNlIiwidmVyc2lvbiI6MSwiZGlzcG9zaXRpb24iOiJldmlkZW5jZS1vbmx5IiwidHVwbGUiOnsiZG9tYWluIjoibGFubW0tbmF0aXZlLXRlcm1pbmFsLWV2aWRlbmNlLXYxIiwiaG9zdElkIjoiaG9zdC0xIiwiam9iSWQiOiJqb2ItMSIsInJlcXVlc3RJZCI6InJlcXVlc3QtMSIsImNvbW1hbmRTZXF1ZW5jZSI6NywiaWRlbXBvdGVuY3lLZXkiOiJpZGVtLTEiLCJhdXRob3JpemF0aW9uUmVxdWVzdERpZ2VzdCI6ImQ3YzNhNGQ3NWRkM2M3N2JjN2M0YjJiMDJhOWE5NjY2MGFiYjYwY2IzOGMwYzE2MTg3ZjdmNTYzYzViN2I2OTUiLCJzdG9yZWRRdWV1ZURpZ2VzdCI6ImFiNmMyNDcwNDYzZmVmZmQ2NTQyYWEyNGY0YjdjZGNjMzk5ZDkyN2Q5MzM4MDU4Y2MyNGMwNzM2YjViMmJhZjUiLCJ0ZXJtaW5hbFN0YXRlIjoidGltZWQtb3V0IiwidGVybWluYWxSZXZpc2lvbiI6Imhpc3RvcnktMSIsInJlc3BvbnNlRGlnZXN0IjoiYmJkNTFjNmE0NDZkODZjZjZmOWQxNWI0YmY5ZGU5N2FhYWU3YmZkNWE0OTZmNDIxMmEyZmVmYzM2Y2M3ZmUxNyIsInJlc3BvbnNlQnl0ZUxlbmd0aCI6MjU0LCJldmlkZW5jZUtpbmQiOiJmYWlsZWQiLCJob2xkQ2xhc3MiOiJyZXRhaW5lZCJ9LCJyZXNwb25zZUJhc2U2NCI6ImV5SnlaWEYxWlhOMFNXUWlPaUp5WlhGMVpYTjBMVEVpTENKcWIySkpaQ0k2SW1wdllpMHhJaXdpYUc5emRFbGtJam9pYUc5emRDMHhJaXdpYzJWeGRXVnVZMlVpT2pjc0luTjBZWFIxY3lJNkltWmhhV3hsWkNJc0luQnliMmR5WlhOeklqcHVkV3hzTENKdlluTmxjblpsWkVGMElqb2lNakF5TmkweE1TMHdORlF4TmpveE5UbzBNeTR3TURCYUlpd2liMkp6WlhKMllYUnBiMjRpT25zaWRHVjRkQ0k2SXNPcEwrbWJxaUlzSW1OdmRXNTBJam94TENKdVpYTjBaV1FpT25zaVkyRnVZWEo1SWpvaVVGSkpWa0ZVUlY5RFFVNUJVbGtpZlgwc0ltVnljbTl5UTI5a1pTSTZJa0ZFUVZCVVJWSmZSa0ZKVEVWRUluMD0iLCJldmlkZW5jZVNvdXJjZSI6InN5bnRoZXRpYyJ9";
const FULL_PAYLOAD_GOLDEN_SHA256 = "45043ea7f2b2822284acf6f00140b7e4e1c818c1d4d09ed876e861118c980e3e";
const FULL_PAYLOAD_GOLDEN_TUPLE_DIGEST = "2b14043a942b44d41eafbb4562c94f533ef8225bdc36c3d9f56827b1f80a88d1";
function fixture() {
  const request: CommandRequest = { requestId: "request-1", jobId: "job-1", hostId: "host-1", operation: "load",
    idempotencyKey: "idem-1", sequence: 7, deadline: TIME,
    capability: { operation: "model-load", targetKind: "model", targetId: "model-1", hostId: "host-1", modelId: "model-1",
      requestDigest: "", expiresAt: TIME }, params: { modelId: "model-1", providerId: "ollama-1", model: "model:1" } };
  (request.capability as { requestDigest: string }).requestDigest = commandAuthorizationDigest(request);
  const parsed = parseCommandRequest(request); assert.ok(parsed.ok);
  const response = { requestId: "request-1", jobId: "job-1", hostId: "host-1", sequence: 7, status: "failed",
    progress: null, observedAt: TIME, observation: { text: "é/雪", count: 1, nested: { canary: "PRIVATE_CANARY" } }, errorCode: "ADAPTER_FAILED" };
  return { storedRequest: parsed.value, storedQueueDigest: createHash("sha256").update(JSON.stringify(parsed.value)).digest("hex"),
    terminal: { hostId: "host-1", jobId: "job-1", requestId: "request-1", state: "timed-out" as const, revision: "history-1", occurredAt: TIME },
    native: { kind: "response" as const, responseBytes: Buffer.from(JSON.stringify(response)),
      authorizationDigest: request.capability.requestDigest, source: "synthetic" as const }, runnerHold: "retained" as const,
    currentTrust: { provenance: "unverified" as const, hostId: "host-1", bindingRevision: "binding-1" } };
}
function good(result: NativeEvidenceCodecResult) {
  assert.ok(result.ok);
  assert.equal(result.releasePermitted, false); assert.equal(result.executionPermitted, false); assert.equal(result.receiptCommitted, false);
  assert.equal(result.payload.disposition, "evidence-only");
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.payload) && Object.isFrozen(result.payload.tuple));
  return result;
}
function bad(result: NativeEvidenceCodecResult) {
  assert.deepEqual(result, { ok: false, error: "ERR_NATIVE_EVIDENCE_CODEC" });
  assert.ok(Object.isFrozen(result));
  assert.equal(JSON.stringify(result).includes("PRIVATE_CANARY"), false);
}
function wire(result: NativeEvidenceCodecResult): Buffer { return Buffer.from(good(result).payloadBase64, "base64"); }
function mutatePayload(snapshot: ReturnType<typeof fixture>, change: (payload: any) => void) {
  const payload = JSON.parse(wire(encodeNativeTerminalEvidence(snapshot)).toString("utf8")); change(payload);
  return decodeNativeTerminalEvidence(Buffer.from(JSON.stringify(payload)), snapshot);
}

test("versioned unsigned evidence payload binds complete tuple and preserves immutable snapshots", () => {
  const snapshot = fixture(), before = structuredClone(snapshot);
  const encoded = good(encodeNativeTerminalEvidence(snapshot));
  const decoded = good(decodeNativeTerminalEvidence(wire(encoded), snapshot));
  assert.deepEqual(decoded, encoded);
  assert.deepEqual(encoded.payload.tuple, { domain: "lanmm-native-terminal-evidence-v1", hostId: "host-1", jobId: "job-1",
    requestId: "request-1", commandSequence: 7, idempotencyKey: "idem-1", authorizationRequestDigest: snapshot.native.authorizationDigest,
    storedQueueDigest: snapshot.storedQueueDigest, terminalState: "timed-out", terminalRevision: "history-1",
    responseDigest: createHash("sha256").update("lanmm-native-response-bytes-v1\0").update(snapshot.native.responseBytes).digest("hex"),
    responseByteLength: snapshot.native.responseBytes.length, evidenceKind: "failed", holdClass: "retained" });
  assert.equal(encoded.payload.domain, "lanmm-native-terminal-evidence-payload-v1");
  assert.equal(encoded.payload.kind, "agent.command.terminal-evidence"); assert.equal(encoded.payload.version, 1);
  assert.notEqual(encoded.payload.tuple.authorizationRequestDigest, encoded.payload.tuple.storedQueueDigest);
  assert.deepEqual(Buffer.from(encoded.payload.responseBase64, "base64"), snapshot.native.responseBytes);
  assert.deepEqual(structuredClone(snapshot), before);
  assert.equal(classifyNativeTerminal(snapshot).binding, "exact");
});

test("frozen language-neutral golden vectors bind complete bytes and explicit tuple encoding", () => {
  const vectors = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "testdata/native-terminal-evidence-codec-v1.json"), "utf8")) as {
    version: number; responseDigestPrefix: string; tupleDigestPrefix: string;
    authorizationRequestDigest: string; storedQueueDigest: string; storedQueueEncoding: string; storedRequest: CommandRequest;
    vectors: Array<{ name: string; responseBase64: string; responseByteLength: number; responseDigest: string; tupleEncoding: string; tupleDigest: string }>;
  };
  const snapshot = fixture();
  assert.equal(vectors.version, 1);
  assert.equal(vectors.responseDigestPrefix, "lanmm-native-response-bytes-v1\0");
  assert.equal(vectors.tupleDigestPrefix, "lanmm-native-terminal-evidence-tuple-digest-v1\0");
  assert.equal(JSON.stringify(vectors.storedRequest), JSON.stringify(snapshot.storedRequest));
  const parsedRequest = parseCommandRequest(vectors.storedRequest);
  assert.ok(parsedRequest.ok);
  assert.equal(vectors.storedQueueEncoding, JSON.stringify(parsedRequest.value));
  assert.equal(vectors.storedQueueEncoding, JSON.stringify(snapshot.storedRequest));
  assert.equal(Buffer.byteLength(vectors.storedQueueEncoding, "utf8"), 470);
  assert.equal(createHash("sha256").update(vectors.storedQueueEncoding, "utf8").digest("hex"), vectors.storedQueueDigest);
  assert.equal(vectors.authorizationRequestDigest, snapshot.native.authorizationDigest);
  assert.equal(vectors.storedQueueDigest, snapshot.storedQueueDigest);
  assert.equal(vectors.vectors.length, 4);
  for (const vector of vectors.vectors) {
    const input = { ...snapshot, native: { ...snapshot.native, responseBytes: Buffer.from(vector.responseBase64, "base64") } };
    const result = good(encodeNativeTerminalEvidence(input)); good(decodeNativeTerminalEvidence(wire(result), input));
    assert.equal(result.payload.responseBase64, vector.responseBase64, vector.name);
    assert.equal(result.payload.tuple.responseDigest, vector.responseDigest, vector.name);
    assert.equal(result.payload.tuple.responseByteLength, vector.responseByteLength, vector.name);
    assert.equal(JSON.stringify(Object.values(result.payload.tuple)), vector.tupleEncoding, vector.name);
    assert.equal(result.tupleDigest, vector.tupleDigest, vector.name);
  }
  const payloadGolden = good(encodeNativeTerminalEvidence(snapshot));
  assert.equal(payloadGolden.payloadBase64, FULL_PAYLOAD_GOLDEN_BASE64);
  assert.equal(payloadGolden.tupleDigest, FULL_PAYLOAD_GOLDEN_TUPLE_DIGEST);
  assert.equal(createHash("sha256").update(Buffer.from(FULL_PAYLOAD_GOLDEN_BASE64, "base64")).digest("hex"), FULL_PAYLOAD_GOLDEN_SHA256);
});

test("every tuple field and signed payload domain kind version disposition mismatch fails closed", () => {
  const snapshot = fixture(), payload = good(encodeNativeTerminalEvidence(snapshot)).payload;
  for (const [key, value] of Object.entries(payload.tuple)) {
    bad(mutatePayload(snapshot, p => { p.tuple[key] = typeof value === "number" ? value + 1 : "foreign"; }));
    bad(mutatePayload(snapshot, p => { delete p.tuple[key]; }));
  }
  for (const [key, value] of Object.entries(payload)) {
    if (key !== "tuple") bad(mutatePayload(snapshot, p => { p[key] = typeof value === "number" ? value + 1 : "foreign"; }));
    bad(mutatePayload(snapshot, p => { delete p[key]; }));
  }
  for (const change of [(p: any) => { p.extra = "PRIVATE_CANARY"; }, (p: any) => { p.tuple.extra = true; },
    (p: any) => { p.disposition = "release"; }, (p: any) => { p.kind = "controller.command.terminal-evidence-receipt"; },
    (p: any) => { p.version = "1"; }, (p: any) => { p.tuple.responseDigest = p.tuple.responseDigest.toUpperCase(); }])
    bad(mutatePayload(snapshot, change));
  for (const raw of ['{"ok":true}', '{}', 'null', '[]']) bad(decodeNativeTerminalEvidence(Buffer.from(raw), snapshot));
});

test("all independent request terminal native and queue bindings are revalidated not trusted", () => {
  const snapshot = fixture(), raw = wire(encodeNativeTerminalEvidence(snapshot));
  const denied = (changed: unknown) => { bad(encodeNativeTerminalEvidence(changed)); bad(decodeNativeTerminalEvidence(raw, changed)); };
  for (const key of ["hostId", "jobId", "requestId"]) denied({ ...snapshot, terminal: { ...snapshot.terminal, [key]: "foreign" } });
  for (const key of ["hostId", "jobId", "requestId", "idempotencyKey", "sequence", "deadline"])
    denied({ ...snapshot, storedRequest: { ...snapshot.storedRequest, [key]: key === "sequence" ? 8 : "foreign" } });
  for (const key of ["hostId", "jobId", "requestId", "sequence"]) {
    const response = JSON.parse(snapshot.native.responseBytes.toString("utf8")); response[key] = key === "sequence" ? 8 : "foreign";
    denied({ ...snapshot, native: { ...snapshot.native, responseBytes: Buffer.from(JSON.stringify(response)) } });
  }
  denied({ ...snapshot, storedQueueDigest: snapshot.native.authorizationDigest });
  denied({ ...snapshot, native: { ...snapshot.native, authorizationDigest: snapshot.storedQueueDigest } });
  denied({ ...snapshot, terminal: { ...snapshot.terminal, revision: "" } });
  denied({ ...snapshot, terminal: { ...snapshot.terminal, state: "running" } });
  denied({ ...snapshot, native: { kind: "absent" } });
  denied({ ...snapshot, currentTrust: { provenance: "verified_current", hostId: "foreign", bindingRevision: "binding" } });
  const reordered = { ...snapshot, storedRequest: { ...snapshot.storedRequest,
    params: { model: "model:1", providerId: "ollama-1", modelId: "model-1" } } };
  assert.equal(commandAuthorizationDigest(reordered.storedRequest), snapshot.native.authorizationDigest);
  denied(reordered); // Queue digest remains order-sensitive, never silently repaired.
  // Even a legitimately reauthorized/requeued change cannot reuse the old tuple.
  const changed = structuredClone(snapshot);
  (changed.storedRequest as { idempotencyKey: string }).idempotencyKey = "other-idem";
  const auth = commandAuthorizationDigest(changed.storedRequest);
  (changed.storedRequest.capability as { requestDigest: string }).requestDigest = auth;
  changed.native.authorizationDigest = auth;
  changed.storedQueueDigest = createHash("sha256").update(JSON.stringify(changed.storedRequest)).digest("hex");
  good(encodeNativeTerminalEvidence(changed)); bad(decodeNativeTerminalEvidence(raw, changed));
  for (const changed of [{ ...snapshot, terminal: { ...snapshot.terminal, revision: "new-revision" } },
    { ...snapshot, terminal: { ...snapshot.terminal, state: "succeeded" } }, { ...snapshot, runnerHold: "pending_uncertain" }]) {
    good(encodeNativeTerminalEvidence(changed)); bad(decodeNativeTerminalEvidence(raw, changed));
  }
});

test("entire original response byte digest distinguishes key order escaping whitespace and observation", () => {
  const snapshot = fixture(), original = good(encodeNativeTerminalEvidence(snapshot));
  const text = snapshot.native.responseBytes.toString("utf8"), object = JSON.parse(text);
  const representations = [text + "\n", text.replace("é/雪", "\\u00e9\\/\\u96ea"),
    JSON.stringify(Object.fromEntries(Object.entries(object).reverse())),
    text.replace('"count":1', '"count":2'), text.replace('"progress":null', '"progress":50'),
    text.replace(TIME, "2026-11-04T16:15:44.000Z"), text.replace("ADAPTER_FAILED", "OTHER_FAILURE")];
  for (const text of representations) {
    const changed = { ...snapshot, native: { ...snapshot.native, responseBytes: Buffer.from(text) } };
    const result = good(encodeNativeTerminalEvidence(changed));
    assert.notEqual(result.payload.tuple.responseDigest, original.payload.tuple.responseDigest);
    assert.notEqual(result.tupleDigest, original.tupleDigest);
    assert.deepEqual(Buffer.from(result.payload.responseBase64, "base64"), changed.native.responseBytes);
    bad(decodeNativeTerminalEvidence(wire(original), changed));
  }
  // Payload metadata may use different object order/spacing; original wire bytes
  // survive decode, while tuple digest has one explicit order-independent encoding.
  const reorderedWire = Buffer.from(JSON.stringify(Object.fromEntries(Object.entries(original.payload).reverse()), null, 2));
  const decoded = good(decodeNativeTerminalEvidence(reorderedWire, snapshot));
  assert.equal(decoded.tupleDigest, original.tupleDigest);
  assert.deepEqual(Buffer.from(decoded.payloadBase64, "base64"), reorderedWire);
});

test("malformed duplicate nonfinite unsafe UTF8 Unicode depth and nonterminal response representations deny", () => {
  const snapshot = fixture(), text = snapshot.native.responseBytes.toString("utf8");
  const negatives: Array<string | Uint8Array> = ["", "null", "{}", "[]", "NaN", "Infinity", text + "{}", text + "garbage",
    text.replace('"sequence":7', '"sequence":7,"sequen\\u0063e":7'),
    text.replace('"count":1', '"count":1,"count":1'), text.replace('"count":1', '"count":NaN'),
    ...["1e999", "1.0", "1e0", "0.5", "-0", "9007199254740993"].map(n => text.replace('"count":1', `"count":${n}`)),
    text.replace('"count":1', '"\\ud800":1'), text.replace("PRIVATE_CANARY", "\\ud800"),
    text.replace('"count":1', `"count":${"[".repeat(18)}1${"]".repeat(18)}`),
    text.replace('"status":"failed"', '"status":"running"'), text.replace('"status":"failed"', '"status":"accepted"'),
    text.replace('"errorCode":"ADAPTER_FAILED"', '"errorCode":null'), text.replace(TIME, "2026-02-30T00:00:00.000Z"),
    text.replace('"progress":null', '"progress":null,"extra":true'),
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text)]), Buffer.from([0xc3, 0x28]),
    Buffer.alloc(MAX_EVIDENCE_RESPONSE_BYTES + 1, 0x20)];
  for (const raw of negatives) bad(encodeNativeTerminalEvidence({ ...snapshot,
    native: { ...snapshot.native, responseBytes: typeof raw === "string" ? Buffer.from(raw) : raw } }));
  const payloadText = wire(encodeNativeTerminalEvidence(snapshot)).toString("utf8");
  for (const raw of [payloadText + " {}", payloadText.replace('"version":1', '"version":1,"version":1'),
    payloadText.replace('"version":1', '"version":1e0'), payloadText.replace('"commandSequence":7', '"commandSequence":9007199254740993'),
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(payloadText)]), Buffer.from([0xff])])
    bad(decodeNativeTerminalEvidence(typeof raw === "string" ? Buffer.from(raw) : raw, snapshot));
});

test("base64 grammar pad bits full-byte digest and exact byte caps are enforced before parsing", () => {
  const snapshot = fixture(), encoded = good(encodeNativeTerminalEvidence(snapshot));
  for (const value of ["", "@@@=", "e30", "e30=\n", "e30= ", "e31=", "____", "e30===", "a".repeat(699053)])
    bad(mutatePayload(snapshot, p => { p.responseBase64 = value; }));
  bad(mutatePayload(snapshot, p => { p.responseBase64 = Buffer.from("{}").toString("base64"); p.tuple.responseByteLength = 2; }));
  const text = snapshot.native.responseBytes.toString("utf8");
  const capBytes = Buffer.from(text + " ".repeat(MAX_EVIDENCE_RESPONSE_BYTES - Buffer.byteLength(text)));
  const capped = { ...snapshot, native: { ...snapshot.native, responseBytes: capBytes } };
  const result = good(encodeNativeTerminalEvidence(capped)); good(decodeNativeTerminalEvidence(wire(result), capped));
  assert.equal(result.payload.tuple.responseByteLength, MAX_EVIDENCE_RESPONSE_BYTES);
  assert.ok(wire(result).length < MAX_EVIDENCE_PAYLOAD_BYTES);
  bad(encodeNativeTerminalEvidence({ ...capped, native: { ...capped.native, responseBytes: Buffer.concat([capBytes, Buffer.from(" ")]) } }));
  const raw = wire(encoded), capWire = Buffer.concat([raw, Buffer.alloc(MAX_EVIDENCE_PAYLOAD_BYTES - raw.length, 0x20)]);
  good(decodeNativeTerminalEvidence(capWire, snapshot));
  bad(decodeNativeTerminalEvidence(Buffer.concat([capWire, Buffer.from(" ")]), snapshot));
});

test("caller trust expiry provenance and every hold state remain evidence-only assertions", () => {
  for (const runnerHold of ["unknown", "in_flight", "retained", "pending_uncertain"])
    for (const provenance of ["verified_current", "unverified", "unavailable"])
      for (const source of ["synthetic", "retained_same_process", "explicit_snapshot"])
        for (const status of ["failed", "succeeded", "cancelled"]) {
          const snapshot = fixture(), response = JSON.parse(snapshot.native.responseBytes.toString("utf8")); response.status = status;
          const input = { ...snapshot, runnerHold, native: { ...snapshot.native, source, responseBytes: Buffer.from(JSON.stringify(response)) },
            currentTrust: { provenance, hostId: provenance === "unavailable" ? null : "host-1", bindingRevision: provenance === "unavailable" ? null : "binding-1" },
            terminal: { ...snapshot.terminal, occurredAt: "2099-01-01T00:00:00.000Z" } };
          const encoded = good(encodeNativeTerminalEvidence(input)); good(decodeNativeTerminalEvidence(wire(encoded), input));
          assert.equal(encoded.callerTrustAssertion, provenance);
          assert.equal(encoded.payload.tuple.holdClass, runnerHold);
          assert.equal(encoded.payload.evidenceSource, source);
        }
});

test("hostile caller getters proxies serializers byte subclasses and shared buffers never invoke caller code", () => {
  const snapshot = fixture(), raw = wire(encodeNativeTerminalEvidence(snapshot)); let calls = 0;
  const hostile = () => { calls++; throw new Error("PRIVATE_CANARY"); };
  const proxy = new Proxy({}, { ownKeys: hostile, get: hostile, getPrototypeOf: hostile });
  const revoked = Proxy.revocable({}, {}); revoked.revoke();
  const cycle: Record<string, unknown> = {}; cycle.self = cycle;
  const params = [proxy, revoked.proxy, { toJSON: hostile }, cycle,
    Object.defineProperty({}, "x", { enumerable: true, get: hostile }), { unsafe: Infinity }, { unsafe: 9007199254740992 }];
  for (const value of params) bad(encodeNativeTerminalEvidence({ ...snapshot, storedRequest: { ...snapshot.storedRequest, params: value } }));
  for (const value of [null, undefined, {}, proxy, revoked.proxy, Object.defineProperty({ ...snapshot }, "native", { get: hostile }),
    { ...snapshot, terminal: Object.defineProperty({ ...snapshot.terminal }, "revision", { get: hostile }) },
    { ...snapshot, currentTrust: { ...snapshot.currentTrust, extra: true } },
    { ...snapshot, native: { ...snapshot.native, source: { toString: hostile } } }]) {
    bad(encodeNativeTerminalEvidence(value)); bad(decodeNativeTerminalEvidence(raw, value));
  }
  for (const value of [proxy, revoked.proxy, new Uint8Array(new SharedArrayBuffer(1)), new Proxy(raw, { get: hostile })]) {
    bad(decodeNativeTerminalEvidence(value, snapshot));
    bad(encodeNativeTerminalEvidence({ ...snapshot, native: { ...snapshot.native, responseBytes: value } }));
  }
  for (const key of ["buffer", "byteLength", "byteOffset"]) {
    const bytes = Buffer.from(snapshot.native.responseBytes); Object.defineProperty(bytes, key, { get: hostile });
    good(encodeNativeTerminalEvidence({ ...snapshot, native: { ...snapshot.native, responseBytes: bytes } }));
    const payload = Buffer.from(raw); Object.defineProperty(payload, key, { get: hostile });
    good(decodeNativeTerminalEvidence(payload, snapshot));
  }
  class HostileBytes extends Uint8Array {
    get buffer(): ArrayBuffer { return hostile(); }
    get byteLength(): number { return hostile(); }
    get byteOffset(): number { return hostile(); }
    [Symbol.iterator](): ReturnType<Uint8Array[typeof Symbol.iterator]> { return hostile(); }
  }
  good(encodeNativeTerminalEvidence({ ...snapshot, native: { ...snapshot.native, responseBytes: new HostileBytes(snapshot.native.responseBytes) } }));
  good(decodeNativeTerminalEvidence(new HostileBytes(raw), snapshot));
  const huge = new HostileBytes(MAX_EVIDENCE_PAYLOAD_BYTES + 1); bad(decodeNativeTerminalEvidence(huge, snapshot));
  const detached = new Uint8Array([1]); structuredClone(detached.buffer, { transfer: [detached.buffer] });
  bad(decodeNativeTerminalEvidence(detached, snapshot));
  assert.equal(calls, 0);
});

test("codec is unwired with only pure core dependencies and no runtime receipt release or signing seam", () => {
  const dir = dirname(fileURLToPath(import.meta.url)), source = readFileSync(join(dir, "native-terminal-evidence-codec.ts"), "utf8");
  assert.deepEqual([...source.matchAll(/from\s+["']([^"']+)["']/g)].map(m => m[1]), ["node:crypto", "node:util", "@lan-model-manager/core"]);
  assert.equal(/\b(?:fetch|readFile|writeFile|setTimeout|setInterval|Date\.now|execute|release|persist|sign)\s*\(/i.test(source), false);
  const files = (path: string): string[] => readdirSync(path, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? files(join(path, entry.name)) :
    entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts") ? [join(path, entry.name)] : []);
  for (const path of files(dir)) if (!path.endsWith("/native-terminal-evidence-codec.ts"))
    assert.equal(readFileSync(path, "utf8").includes("native-terminal-evidence-codec"), false, path);
  bad(encodeNativeTerminalEvidence({ ...fixture(), adapters: { execute() { throw new Error("must not execute"); } } }));
});
