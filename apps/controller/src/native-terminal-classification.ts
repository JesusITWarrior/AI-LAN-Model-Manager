/** Offline, report-only snapshot classification. No live trust verification, lookup,
 * consent, receipt, dispatch, or hold transition occurs here. Caller assertions
 * (including verified_current) are not independently established by this module.
 * Historical capability expiry and native observation time never create authority.
 */
import { createHash } from "node:crypto";
import { types } from "node:util";
import {
  commandAuthorizationDigest, parseCommandRequest, parseCommandResponse,
  parseStreamWireJSON, responseMatches,
} from "@lan-model-manager/core";

export const MAX_NATIVE_TERMINAL_RESPONSE_BYTES = 512 * 1024;
export type ControllerTerminalState = "timed-out" | "failed" | "succeeded" | "cancelled";
export type RunnerHold = "unknown" | "in_flight" | "retained" | "pending_uncertain";
export type TrustProvenance = "verified_current" | "unverified" | "unavailable";
export type NativeEvidenceSource = "retained_same_process" | "explicit_snapshot" | "synthetic";
export interface TerminalSnapshot {
  readonly hostId: string;
  readonly jobId: string;
  readonly requestId: string;
  readonly state: ControllerTerminalState;
  /** Stable revision of the immutable terminal event, NOT a global audit head. */
  readonly revision: string;
  readonly occurredAt: string;
}
export interface CurrentTrustSnapshot {
  readonly provenance: TrustProvenance;
  readonly hostId: string | null;
  readonly bindingRevision: string | null;
}
export type NativeTerminalEvidence = Readonly<{ kind: "absent" }> | Readonly<{
  kind: "response";
  responseBytes: Uint8Array;
  authorizationDigest: string;
  source: NativeEvidenceSource;
}>;
export interface NativeTerminalClassificationInput {
  readonly storedRequest: unknown;
  readonly storedQueueDigest: string;
  readonly terminal: TerminalSnapshot;
  readonly native: NativeTerminalEvidence;
  readonly runnerHold: RunnerHold;
  readonly currentTrust: CurrentTrustSnapshot;
}
export interface NativeTerminalReport {
  readonly originalControllerTerminal: ControllerTerminalState | "invalid";
  readonly nativeEvidence: "absent" | "failed" | "succeeded" | "cancelled" | "invalid";
  /** Fixed classification, never arbitrary response error text. */
  readonly nativeFailure: "adapter_failed" | "other_failure" | "none";
  readonly evidenceSource: NativeEvidenceSource | "absent" | "invalid";
  readonly runnerHold: RunnerHold;
  readonly binding: "exact" | "mismatch" | "insufficient";
  readonly currentTrust: TrustProvenance | "mismatch" | "invalid";
  readonly releasePermitted: false;
  readonly executionPermitted: false;
  readonly receiptCommitted: false;
}
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const terminals: readonly string[] = ["timed-out", "failed", "succeeded", "cancelled"];
const holds: readonly string[] = ["unknown", "in_flight", "retained", "pending_uncertain"];
const sources: readonly string[] = ["retained_same_process", "explicit_snapshot", "synthetic"];
function exact(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || types.isProxy(value) || Array.isArray(value)) return null;
  const prototype = Object.getPrototypeOf(value), own = Reflect.ownKeys(value);
  if (prototype !== Object.prototype && prototype !== null || own.length !== keys.length) return null;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (own.some(key => typeof key !== "string" || !keys.includes(key)) ||
      keys.some(key => !descriptors[key] || !("value" in descriptors[key]!))) return null;
  return Object.fromEntries(keys.map(key => [key, descriptors[key]!.value]));
}
function stamp(value: unknown): boolean {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}
function id(value: unknown): value is string { return typeof value === "string" && ID.test(value); }
function digest(value: unknown): value is string { return typeof value === "string" && DIGEST.test(value); }
function wellFormed(value: string): boolean {
  return !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value);
}
/** Defensive, bounded data-only copy before core's JSON.stringify. Rejects
 * accessors/toJSON/cycles/unsafe numbers without invoking caller code. Also
 * closes the stream raw parser's safe-integer and object-key Unicode gaps.
 * Fractions/exponents and negative zero are unsupported evidence, not normalized.
 */
function dataSnapshot(input: unknown): unknown {
  let nodes = 0, bytes = 0;
  const walk = (value: unknown, depth: number): unknown => {
    if (++nodes > 65536 || depth > 16) throw new Error("UNSUPPORTED_SNAPSHOT");
    if (value === null || typeof value === "boolean") return value;
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new Error("UNSUPPORTED_SNAPSHOT");
      return value;
    }
    if (typeof value === "string") {
      bytes += Buffer.byteLength(value);
      if (bytes > 600 * 1024 || !wellFormed(value)) throw new Error("UNSUPPORTED_SNAPSHOT");
      return value;
    }
    if (typeof value !== "object") throw new Error("UNSUPPORTED_SNAPSHOT");
    if (types.isProxy(value)) throw new Error("UNSUPPORTED_SNAPSHOT");
    const array = Array.isArray(value), prototype = Object.getPrototypeOf(value);
    if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null)
      throw new Error("UNSUPPORTED_SNAPSHOT");
    const descriptors = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(value);
    if (array) {
      const length = descriptors.length?.value;
      if (!Number.isSafeInteger(length) || length > 65536 || keys.length !== length + 1)
        throw new Error("UNSUPPORTED_SNAPSHOT");
      const result: unknown[] = [];
      for (let i = 0; i < length; i++) {
        const descriptor = descriptors[String(i)];
        if (!descriptor || !("value" in descriptor)) throw new Error("UNSUPPORTED_SNAPSHOT");
        result.push(walk(descriptor.value, depth + 1));
      }
      return result;
    }
    const result = Object.create(null) as Record<string, unknown>;
    for (const key of keys) {
      if (typeof key !== "string" || !wellFormed(key)) throw new Error("UNSUPPORTED_SNAPSHOT");
      bytes += Buffer.byteLength(key);
      const descriptor = descriptors[key]!;
      if (!("value" in descriptor) || bytes > 600 * 1024) throw new Error("UNSUPPORTED_SNAPSHOT");
      result[key] = walk(descriptor.value, depth + 1);
    }
    return result;
  };
  return walk(input, 0);
}

/** A pure redacted report. No candidate/IDs/digests/bytes escape this boundary.
 * Native success is only a reported outcome, not adapter/durability certification.
 * The raw parser is reused solely as a strict bounded JSON grammar, not a stream
 * admission path. No response digest or receipt is fabricated by reserialization.
 */
export function classifyNativeTerminal(input: NativeTerminalClassificationInput): NativeTerminalReport {
  let originalControllerTerminal: NativeTerminalReport["originalControllerTerminal"] = "invalid";
  let nativeEvidence: NativeTerminalReport["nativeEvidence"] = "invalid";
  let nativeFailure: NativeTerminalReport["nativeFailure"] = "none";
  let evidenceSource: NativeTerminalReport["evidenceSource"] = "invalid";
  let runnerHold: RunnerHold = "unknown";
  let binding: NativeTerminalReport["binding"] = "insufficient";
  let currentTrust: NativeTerminalReport["currentTrust"] = "invalid";
  const report = (): NativeTerminalReport => Object.freeze({ originalControllerTerminal, nativeEvidence,
    nativeFailure, evidenceSource, runnerHold, binding, currentTrust,
    releasePermitted: false, executionPermitted: false, receiptCommitted: false });
  try {
    const top = exact(input, ["storedRequest", "storedQueueDigest", "terminal", "native", "runnerHold", "currentTrust"]);
    if (!top) return report();
    const holdValid = typeof top.runnerHold === "string" && holds.includes(top.runnerHold);
    if (holdValid) runnerHold = top.runnerHold as RunnerHold;
    const terminal = exact(top.terminal, ["hostId", "jobId", "requestId", "state", "revision", "occurredAt"]);
    const terminalValid = !!terminal && id(terminal.hostId) && id(terminal.jobId) && id(terminal.requestId) &&
      typeof terminal.state === "string" && terminals.includes(terminal.state) && id(terminal.revision) && stamp(terminal.occurredAt);
    if (terminalValid) originalControllerTerminal = terminal.state as ControllerTerminalState;
    const trust = exact(top.currentTrust, ["provenance", "hostId", "bindingRevision"]);
    if (trust?.provenance === "unavailable" && trust.hostId === null && trust.bindingRevision === null) currentTrust = "unavailable";
    if (trust?.provenance === "unverified" && (trust.hostId === null || id(trust.hostId)) &&
        (trust.bindingRevision === null || id(trust.bindingRevision))) currentTrust = "unverified";
    if (trust?.provenance === "verified_current" && id(trust.hostId) && id(trust.bindingRevision)) currentTrust = "verified_current";
    const absent = exact(top.native, ["kind"]);
    if (absent?.kind === "absent") { nativeEvidence = "absent"; evidenceSource = "absent"; }
    const native = exact(top.native, ["kind", "responseBytes", "authorizationDigest", "source"]);
    if (!terminalValid || !holdValid || currentTrust === "invalid") return report();
    const request = parseCommandRequest(dataSnapshot(top.storedRequest));
    if (!request.ok || !stamp(request.value.deadline) || !stamp(request.value.capability.expiresAt)) return report();
    const queueDigest = createHash("sha256").update(JSON.stringify(request.value)).digest("hex");
    if (!digest(top.storedQueueDigest) || queueDigest !== top.storedQueueDigest ||
        terminal.hostId !== request.value.hostId || terminal.jobId !== request.value.jobId || terminal.requestId !== request.value.requestId) {
      binding = "mismatch"; return report();
    }
    if (currentTrust === "verified_current" && trust!.hostId !== request.value.hostId) {
      currentTrust = "mismatch"; binding = "mismatch"; return report();
    }
    if (nativeEvidence === "absent") return report();
    if (!native || native.kind !== "response" || typeof native.source !== "string" || !sources.includes(native.source)) return report();
    evidenceSource = native.source as NativeEvidenceSource;
    if (!digest(native.authorizationDigest) || native.authorizationDigest !== commandAuthorizationDigest(request.value)) {
      binding = "mismatch"; return report();
    }
    const view = native.responseBytes;
    if (types.isProxy(view) || !types.isUint8Array(view)) return report();
    // Use intrinsic internal-slot getters, never shadowable view properties or
    // caller methods/iterators. Check actual size before allocating an owned copy.
    const proto = Object.getPrototypeOf(Uint8Array.prototype);
    const slot = (key: string) => Object.getOwnPropertyDescriptor(proto, key)!.get!.call(view);
    const backing = slot("buffer"), length = slot("byteLength"), offset = slot("byteOffset");
    if (!types.isArrayBuffer(backing) || length === 0 || length > MAX_NATIVE_TERMINAL_RESPONSE_BYTES) return report();
    const bytes = new Uint8Array(length);
    bytes.set(new Uint8Array(backing, offset, length));
    const response = parseCommandResponse(dataSnapshot(parseStreamWireJSON(bytes, MAX_NATIVE_TERMINAL_RESPONSE_BYTES)));
    if (!response.ok || !stamp(response.value.observedAt) || !terminals.includes(response.value.status)) return report();
    if (!responseMatches(request.value, response.value)) { binding = "mismatch"; return report(); }
    nativeEvidence = response.value.status as "failed" | "succeeded" | "cancelled";
    nativeFailure = nativeEvidence === "failed" ? response.value.errorCode === "ADAPTER_FAILED" ? "adapter_failed" : "other_failure" : "none";
    binding = "exact";
  } catch { /* Fixed classifications only; never return parser errors or inputs. */ }
  return report();
}
