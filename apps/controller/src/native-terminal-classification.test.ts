import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { commandAuthorizationDigest, parseCommandRequest, type CommandRequest, type CommandResponse } from "@lan-model-manager/core";
import {
  classifyNativeTerminal, MAX_NATIVE_TERMINAL_RESPONSE_BYTES,
  type ControllerTerminalState, type NativeTerminalClassificationInput, type NativeTerminalReport,
  type NativeEvidenceSource, type RunnerHold, type TrustProvenance,
} from "./native-terminal-classification.js";

const at = (ms: number) => new Date(Date.parse("2026-11-04T16:15:43.000Z") + ms).toISOString();
const CANARY = "CANARY_SECRET_99";
function frozen<T>(value: T): T {
  if (value && typeof value === "object" && !(value instanceof Uint8Array)) {
    for (const child of Object.values(value)) frozen(child);
    Object.freeze(value);
  }
  return value;
}
function fixture(options: {
  status?: "failed" | "succeeded" | "cancelled";
  hold?: RunnerHold;
  trust?: TrustProvenance;
  terminal?: ControllerTerminalState;
  source?: NativeEvidenceSource;
  observedAt?: string;
} = {}) {
  const capability = { operation: "model-load" as const, targetKind: "model", targetId: `model-${CANARY}`,
    hostId: `host-${CANARY}`, modelId: `model-${CANARY}`, requestDigest: "", expiresAt: at(60_000) };
  const raw: CommandRequest = { requestId: `request-${CANARY}`, jobId: `job-${CANARY}`, hostId: `host-${CANARY}`,
    operation: "load", idempotencyKey: `key-${CANARY}`, sequence: 7, deadline: at(30_000), capability,
    params: { modelId: `model-${CANARY}`, providerId: "ollama-1", model: `model:${CANARY}` } };
  capability.requestDigest = commandAuthorizationDigest(raw);
  const parsed = parseCommandRequest(raw);
  assert.ok(parsed.ok);
  const request = parsed.value;
  const response: CommandResponse = { requestId: request.requestId, jobId: request.jobId, hostId: request.hostId,
    sequence: request.sequence, status: options.status ?? "failed", progress: null, observedAt: options.observedAt ?? at(502),
    observation: { model: CANARY, path: `/private/${CANARY}`, nonce: CANARY, key: CANARY, response: CANARY },
    errorCode: (options.status ?? "failed") === "failed" ? "ADAPTER_FAILED" : null };
  const trust = options.trust ?? "unverified";
  const input: NativeTerminalClassificationInput = {
    storedRequest: request,
    storedQueueDigest: createHash("sha256").update(JSON.stringify(request)).digest("hex"),
    terminal: { hostId: request.hostId, jobId: request.jobId, requestId: request.requestId, state: options.terminal ?? "timed-out",
      revision: `terminal-${CANARY}`, occurredAt: at(40_000) },
    native: { kind: "response", responseBytes: Buffer.from(JSON.stringify(response)),
      authorizationDigest: request.capability.requestDigest, source: options.source ?? "synthetic" },
    runnerHold: options.hold ?? "retained",
    currentTrust: { provenance: trust, hostId: trust === "unavailable" ? null : request.hostId,
      bindingRevision: trust === "unavailable" ? null : `binding-${CANARY}` },
  };
  frozen(request); frozen(response); frozen(input);
  return { input, request, response };
}
function flags(report: NativeTerminalReport) {
  assert.equal(report.releasePermitted, false);
  assert.equal(report.executionPermitted, false);
  assert.equal(report.receiptCommitted, false);
  assert.ok(Object.isFrozen(report));
}
function responseInput(input: NativeTerminalClassificationInput, response: unknown): NativeTerminalClassificationInput {
  assert.equal(input.native.kind, "response");
  if (input.native.kind !== "response") throw new Error("fixture");
  return { ...input, native: { ...input.native, responseBytes: Buffer.from(JSON.stringify(response)) } };
}
function rawInput(input: NativeTerminalClassificationInput, raw: Uint8Array | string): NativeTerminalClassificationInput {
  assert.equal(input.native.kind, "response");
  if (input.native.kind !== "response") throw new Error("fixture");
  return { ...input, native: { ...input.native, responseBytes: typeof raw === "string" ? Buffer.from(raw) : raw } };
}
function denied(input: NativeTerminalClassificationInput) {
  let report!: NativeTerminalReport;
  assert.doesNotThrow(() => { report = classifyNativeTerminal(input); });
  flags(report);
  assert.notEqual(report.binding, "exact");
  assert.ok(!JSON.stringify(report).includes(CANARY));
  return report;
}

test("terminal timeout and retained native failure remain separate immutable observations", () => {
  const { input, response } = fixture({ source: "retained_same_process" });
  const before = structuredClone(input), responseBefore = structuredClone(response);
  const report = classifyNativeTerminal(input);
  assert.deepEqual(report, {
    originalControllerTerminal: "timed-out", nativeEvidence: "failed", nativeFailure: "adapter_failed",
    evidenceSource: "retained_same_process", runnerHold: "retained", binding: "exact", currentTrust: "unverified",
    releasePermitted: false, executionPermitted: false, receiptCommitted: false,
  });
  assert.deepEqual(classifyNativeTerminal(input), report);
  assert.deepEqual(structuredClone(input), before);
  assert.deepEqual(structuredClone(response), responseBefore);
  flags(report);
});

test("pending uncertainty and unknown runner state never become release authority", () => {
  for (const hold of ["unknown", "in_flight", "retained", "pending_uncertain"] as const)
    for (const trust of ["verified_current", "unverified", "unavailable"] as const)
      for (const status of ["failed", "succeeded", "cancelled"] as const)
        for (const terminal of ["timed-out", "failed", "succeeded", "cancelled"] as const)
          for (const source of ["retained_same_process", "explicit_snapshot", "synthetic"] as const) {
            const { input } = fixture({ hold, trust, status, terminal, source });
            const before = structuredClone(input), report = classifyNativeTerminal(input);
            flags(report);
            assert.equal(report.binding, "exact");
            assert.equal(report.runnerHold, hold);
            assert.equal(report.currentTrust, trust);
            assert.equal(report.originalControllerTerminal, terminal);
            assert.equal(report.nativeEvidence, status);
            assert.equal(report.evidenceSource, source);
            assert.deepEqual(structuredClone(input), before);
          }
});

test("exact binding rejects every host job request sequence authorization and queue digest mismatch", () => {
  const { input, response, request } = fixture();
  for (const key of ["hostId", "jobId", "requestId", "sequence"] as const) {
    const report = denied(responseInput(input, { ...response, [key]: key === "sequence" ? 8 : "foreign" }));
    assert.equal(report.binding, "mismatch", key);
    assert.equal(report.nativeEvidence, "invalid");
  }
  for (const key of ["hostId", "jobId", "requestId"] as const)
    assert.equal(denied({ ...input, terminal: { ...input.terminal, [key]: "foreign" } }).binding, "mismatch");
  if (input.native.kind !== "response") throw new Error("fixture");
  for (const authorizationDigest of ["0".repeat(64), input.storedQueueDigest, "bad", ""]) {
    assert.equal(denied({ ...input, native: { ...input.native, authorizationDigest } }).binding, "mismatch");
  }
  assert.notEqual(input.storedQueueDigest, request.capability.requestDigest);
  for (const storedQueueDigest of [request.capability.requestDigest, "0".repeat(64), "bad", ""])
    assert.equal(denied({ ...input, storedQueueDigest }).binding, "mismatch");
  for (const key of ["hostId", "jobId", "requestId", "idempotencyKey", "sequence", "deadline"] as const) {
    denied({ ...input, storedRequest: { ...request, [key]: key === "sequence" ? 8 : key === "deadline" ? at(20_000) : "foreign" } });
  }
  denied({ ...input, storedRequest: { ...request, params: { modelId: "foreign" } } });
  denied({ ...input, storedRequest: { ...request, capability: { ...request.capability, requestDigest: input.storedQueueDigest } } });
  // Reauthorized changed request still cannot match the OLD stored queue digest.
  const changed = { ...request, idempotencyKey: "foreign", capability: { ...request.capability } };
  changed.capability.requestDigest = commandAuthorizationDigest(changed);
  assert.equal(denied({ ...input, storedRequest: changed }).binding, "mismatch");
  // Authorization digest canonicalizes parameter order; queue digest does not.
  // Reordering a decoded stored request must not silently repair its queue hash.
  const reordered = { ...request, params: { model: `model:${CANARY}`, providerId: "ollama-1", modelId: `model-${CANARY}` } };
  assert.equal(commandAuthorizationDigest(reordered), request.capability.requestDigest);
  assert.equal(denied({ ...input, storedRequest: reordered }).binding, "mismatch");
  denied(rawInput(input, "not JSON"));
});

test("expired historical capability identifies evidence without granting fresh execution", () => {
  // No wall clock is read: both original deadline and capability are long expired
  // relative to this supplied terminal observation. Neither is renewed or rewritten.
  const { input, request } = fixture();
  const expired = frozen({ ...input, terminal: { ...input.terminal, occurredAt: "2099-01-01T00:00:00.000Z" } });
  const before = structuredClone(expired);
  const report = classifyNativeTerminal(expired);
  assert.equal(report.binding, "exact");
  assert.equal(report.nativeEvidence, "failed");
  assert.equal(request.deadline, at(30_000));
  assert.equal(request.capability.expiresAt, at(60_000));
  flags(report);
  assert.deepEqual(structuredClone(expired), before);
});

test("native observation time never revises controller terminal history", () => {
  for (const observedAt of [at(-60_000), at(40_000), at(60_000), "2099-01-01T00:00:00.000Z"]) {
    const { input } = fixture({ observedAt });
    const before = structuredClone(input);
    const report = classifyNativeTerminal(input);
    assert.equal(report.binding, "exact");
    assert.equal(report.originalControllerTerminal, "timed-out");
    flags(report);
    assert.deepEqual(structuredClone(input), before);
  }
});

test("missing corrupt oversized duplicate-key and nonfinite evidence fails closed", () => {
  const { input, response } = fixture();
  const absent = denied({ ...input, native: { kind: "absent" } });
  assert.equal(absent.binding, "insufficient");
  assert.equal(absent.nativeEvidence, "absent");
  assert.equal(absent.nativeFailure, "none");
  const raw = JSON.stringify(response);
  const negatives: Array<string | Uint8Array> = [
    "", "null", "{}", "[]", "{", "NaN", "Infinity", `${raw} {}`, `${raw}junk`,
    raw.replace('"sequence":7', '"sequence":7,"sequence":7'),
    raw.replace('"sequence":7', '"sequence":7,"sequen\\u0063e":7'),
    raw.replace('"sequence":7', '"sequence":1e999'),
    raw.replace('"sequence":7', '"sequence":9007199254740993'),
    raw.replace('"sequence":7', '"sequence":7.0'),
    raw.replace('"sequence":7', '"sequence":7e0'),
    raw.replace('"progress":null', '"progress":-0'),
    raw.replace('"progress":null', '"progress":NaN'),
    raw.replace('"observation":{', '"observation":{"dup":1,"dup":2,'),
    raw.replace('"observation":{', '"observation":{"unsafe":9007199254740993,'),
    raw.replace('"observation":{', '"observation":{"overflow":1e999,'),
    raw.replace('"observation":{', '"observation":{"fraction":0.5,'),
    raw.replace('"observation":{', '"observation":{"\\ud800":1,'),
    raw.replace('"observation":{', '"observation":{"bad":"\\ud800",'),
    raw.replace('"observation":{', `"observation":{"deep":${"[".repeat(20)}0${"]".repeat(20)},`),
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(raw)]),
    Buffer.concat([Buffer.from(raw.slice(0, -1)), Buffer.from([0xff]), Buffer.from("}")]),
    Buffer.alloc(MAX_NATIVE_TERMINAL_RESPONSE_BYTES + 1, 0x20),
  ];
  for (const bytes of negatives) {
    const report = denied(rawInput(input, bytes));
    assert.equal(report.nativeEvidence, "invalid");
    assert.equal(report.nativeFailure, "none");
  }
  for (const value of [
    { ...response, extra: CANARY }, { ...response, observedAt: "2026-99-99T99:99:99.000Z" },
    { ...response, observedAt: "2026-02-30T00:00:00.000Z" }, { ...response, status: "accepted" },
    { ...response, status: "running" }, { ...response, errorCode: null },
  ]) denied(responseInput(input, value));
  if (input.native.kind !== "response") throw new Error("fixture");
  denied({ ...input, native: { ...input.native, source: "diagnostic_status" as NativeEvidenceSource } });
  denied({ ...input, native: { ...input.native, responseBytes: new SharedArrayBuffer(1) as unknown as Uint8Array } });
  denied(rawInput(input, new Uint8Array(new SharedArrayBuffer(1))));
  // Evidence is never truncated: a complete valid body of exactly the cap works;
  // the same body plus a single whitespace byte fails before parsing.
  const exactCap = Buffer.from(raw + " ".repeat(MAX_NATIVE_TERMINAL_RESPONSE_BYTES - Buffer.byteLength(raw)));
  assert.equal(classifyNativeTerminal(rawInput(input, exactCap)).binding, "exact");
  denied(rawInput(input, Buffer.concat([exactCap, Buffer.from(" ")])));
});

test("diagnostic status alone is insufficient and reports redact canaries", () => {
  const { input, response, request } = fixture();
  const reports = [classifyNativeTerminal(input),
    denied({ ...input, native: { kind: "absent" } }),
    denied(responseInput(input, { retained: true, hostId: request.hostId, error: CANARY })),
    denied(responseInput(input, { ...response, errorCode: CANARY, extra: CANARY })),
    classifyNativeTerminal(responseInput(input, { ...response, errorCode: CANARY })),
    denied({ ...input, currentTrust: { provenance: "verified_current", hostId: "foreign", bindingRevision: "revision" } }),
    denied({ ...input, terminal: { ...input.terminal, revision: "" } }),
  ];
  const serialized = JSON.stringify(reports);
  for (const canary of [CANARY, request.hostId, request.jobId, request.requestId, request.idempotencyKey,
    request.capability.requestDigest, input.storedQueueDigest, input.terminal.revision, input.terminal.occurredAt,
    response.observedAt, `/private/${CANARY}`, "ADAPTER_FAILED"])
    assert.equal(serialized.includes(canary), false, canary);
  assert.equal(reports[4]!.nativeFailure, "other_failure");
  assert.equal(reports[5]!.currentTrust, "mismatch");
  assert.equal(reports[6]!.originalControllerTerminal, "invalid");
});

test("malformed snapshot metadata and hostile data never invoke accessors or produce authority", () => {
  const { input, request } = fixture();
  let calls = 0;
  const getter = Object.defineProperty({}, "modelId", { enumerable: true, get() { calls++; throw new Error(CANARY); } });
  const serializer = { toJSON() { calls++; throw new Error(CANARY); } };
  const cycle: Record<string, unknown> = {}; cycle.self = cycle;
  for (const params of [getter, serializer, cycle, { unsafe: Infinity }, { unsafe: 9007199254740992 }])
    denied({ ...input, storedRequest: { ...request, params } });
  assert.equal(calls, 0);
  const metadata = [
    { ...input, runnerHold: "clear" },
    { ...input, currentTrust: { provenance: "verified_current", hostId: input.terminal.hostId, bindingRevision: "" } },
    { ...input, currentTrust: { provenance: "unavailable", hostId: input.terminal.hostId, bindingRevision: null } },
    { ...input, currentTrust: { ...input.currentTrust, extra: CANARY } },
    { ...input, terminal: { ...input.terminal, state: "running" } },
    { ...input, terminal: { ...input.terminal, occurredAt: "2026-02-30T00:00:00.000Z" } },
    { ...input, terminal: { ...input.terminal, extra: CANARY } },
    { ...input, native: { kind: "absent", response: CANARY } },
    null, undefined, {}, new Date(),
  ];
  for (const value of metadata) denied(value as NativeTerminalClassificationInput);
  const revoked = Proxy.revocable({}, {}); revoked.revoke();
  denied(revoked.proxy as NativeTerminalClassificationInput);
  const topGetter = Object.defineProperty({ ...input }, "storedRequest", { get() { calls++; return request; } });
  denied(topGetter);
  assert.equal(calls, 0);
});

test("report-only module has no runtime entrypoint and no release execute or persistence dependency", () => {
  const sourceDir = dirname(fileURLToPath(import.meta.url));
  const source = readFileSync(join(sourceDir, "native-terminal-classification.ts"), "utf8");
  const imports = [...source.matchAll(/from\s+["']([^"']+)["']/g)].map(match => match[1]);
  assert.deepEqual(imports, ["node:crypto", "node:util", "@lan-model-manager/core"]);
  assert.equal(/\b(?:fetch|setTimeout|setInterval|Date\.now|readFile|writeFile|execute|release|persist)\s*\(/i.test(source), false);
  // Follow the exported core graph as well: no controller, transport runtime,
  // sqlite, file IO, process/network/service dependency can hide behind a barrel.
  const coreDir = join(sourceDir, "../../..", "packages/core/src");
  const visited = new Set<string>();
  function coreGraph(file: string) {
    if (visited.has(file)) return;
    visited.add(file);
    const text = readFileSync(file, "utf8");
    for (const match of text.matchAll(/(?:from\s*|import\s*\()["']([^"']+)["']/g)) {
      const specifier = match[1]!;
      if (specifier.startsWith(".")) coreGraph(join(dirname(file), specifier.replace(/\.js$/, ".ts")));
      else assert.ok(["node:crypto", "node:net", "node:path"].includes(specifier), specifier);
    }
  }
  coreGraph(join(coreDir, "index.ts"));
  assert.ok(visited.size > 10);
  function productionFiles(dir: string): string[] {
    return readdirSync(dir, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? productionFiles(join(dir, entry.name)) :
      entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts") ? [join(dir, entry.name)] : []);
  }
  for (const file of productionFiles(sourceDir)) {
    if (file.endsWith("/native-terminal-classification.ts")) continue;
    assert.equal(readFileSync(file, "utf8").includes("native-terminal-classification"), false, file);
  }
  const calls = { release: 0, execute: 0, persist: 0, read: 0, transport: 0 };
  const adapters = Object.fromEntries(Object.keys(calls).map(key => [key, () => { calls[key as keyof typeof calls]++; }]));
  // There is no adapter input seam. Extra adapter keys are rejected rather than
  // inspected/called; normal offline classification also leaves all spies zero.
  denied({ ...fixture().input, adapters } as NativeTerminalClassificationInput);
  flags(classifyNativeTerminal(fixture().input));
  assert.deepEqual(calls, { release: 0, execute: 0, persist: 0, read: 0, transport: 0 });
});


test("byte-view intrinsic bounds ignore hostile properties and subclasses without invoking caller code", () => {
  const { input, response } = fixture();
  let calls = 0;
  for (const key of ["buffer", "byteLength", "byteOffset"]) {
    const raw = Buffer.from(JSON.stringify(response));
    Object.defineProperty(raw, key, { get() { calls++; throw new Error("caller getter"); } });
    assert.equal(classifyNativeTerminal(rawInput(input, raw)).binding, "exact");
  }
  class HostileBytes extends Uint8Array {
    get buffer(): ArrayBuffer { calls++; throw new Error("subclass getter"); }
    get byteLength(): number { calls++; return 1; }
    get byteOffset(): number { calls++; return 0; }
  }
  const valid = new HostileBytes(Buffer.from(JSON.stringify(response)));
  assert.equal(classifyNativeTerminal(rawInput(input, valid)).binding, "exact");
  const oversized = Buffer.from(JSON.stringify(response) + " ".repeat(MAX_NATIVE_TERMINAL_RESPONSE_BYTES + 1));
  Object.defineProperty(oversized, "byteLength", { value: 1 });
  denied(rawInput(input, oversized));
  const oversizedGetter = new HostileBytes(MAX_NATIVE_TERMINAL_RESPONSE_BYTES + 1);
  denied(rawInput(input, oversizedGetter));
  const proxied = new Proxy(valid, { get() { calls++; throw new Error("proxy trap"); } });
  denied(rawInput(input, proxied));
  const top = new Proxy(input, { ownKeys() { calls++; throw new Error("snapshot trap"); } });
  denied(top);
  assert.equal(calls, 0);
});
