import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { commandAuthorizationDigest, CURRENT_PROTOCOL_VERSION, signTransportSignedEnvelope, type JsonValue, type TransportParsedCertificate } from "@lan-model-manager/core";
import { decodeNativeTerminalEvidence, encodeNativeTerminalEvidence, MAX_EVIDENCE_PAYLOAD_BYTES, MAX_EVIDENCE_RESPONSE_BYTES } from "./native-terminal-evidence-codec.js";
import { ControllerTransport } from "./transport/controller-transport.js";

const NOW = "2026-11-11T20:00:00.000Z";
const RESULT_BODY_LIMIT = 512 * 1024;
const WHOLE_REQUEST_LIMIT = 768 * 1024;
const RESPONSE_CANDIDATE = 256 * 1024;
const PAYLOAD_CANDIDATE = 360 * 1024;

function fakeTransport() {
  const certificate: TransportParsedCertificate = { fingerprint: "a".repeat(64), serial: "ABCD", commonName: "host-1", address: "127.0.0.1",
    spiffe: "spiffe://lanmodelmanager/host/host-1", notBefore: "2026-11-11T00:00:00.000Z", notAfter: "2026-11-12T00:00:00.000Z",
    issuerFingerprint: "b".repeat(64), isCa: false };
  const signer = { algorithm: "ecdsa-p256-sha256" as const, certificate, sign: (_message: string) => "a".repeat(64) };
  const service = new ControllerTransport({
    certificateRepository: { getBySerial: () => ({ status: "active", serial: "ABCD", fingerprint: certificate.fingerprint,
      binding: { candidateId: "host-1" } }) } as never,
    replayStore: { check: () => "accepted" } as never,
    verifier: () => ({ algorithm: "ecdsa-p256-sha256" as const, certificate, verify: () => true }),
    clock: () => NOW,
  });
  return (payload: JsonValue) => {
    const env = signTransportSignedEnvelope({ protocolVersion: CURRENT_PROTOCOL_VERSION, messageType: "agent.command.result",
      hostId: "host-1", requestId: "request-1", sequence: 1, sentAt: NOW, nonce: "bm9uY2UtMQ",
      certFingerprint: certificate.fingerprint, certSerial: certificate.serial, bodyDigest: "0".repeat(64), signature: "a".repeat(64), payload }, signer);
    assert.equal(env.ok, true);
    if (!env.ok) throw new Error("synthetic fake-signed envelope construction failed");
    return service.accept(env.value);
  };
}
function syntheticSnapshot(responseBytes: Uint8Array) {
  const file = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "testdata/native-terminal-evidence-codec-v1.json"), "utf8"));
  const request = file.storedRequest;
  return { storedRequest: request, storedQueueDigest: file.storedQueueDigest,
    terminal: { hostId: "host-1", jobId: "job-1", requestId: "request-1", state: "timed-out", revision: "history-1", occurredAt: "2026-11-04T16:15:43.000Z" },
    native: { kind: "response", responseBytes, authorizationDigest: file.authorizationRequestDigest, source: "synthetic" },
    runnerHold: "retained", currentTrust: { provenance: "unverified", hostId: "host-1", bindingRevision: "binding-1" } };
}
function maxMetadataSnapshot(responseLength: number, evidenceSource = "retained_same_process", revisionLength = 128) {
  const id = "A" + "x".repeat(127), maxModel = "m".repeat(256);
  const capability = { operation: "model-load", targetKind: "model", targetId: id, hostId: id, modelId: id,
    requestDigest: "0".repeat(64), expiresAt: "2026-11-04T16:15:43.000Z" };
  const request = { requestId: id, jobId: id, hostId: id, operation: "load", idempotencyKey: id, sequence: 7,
    deadline: "2026-11-04T16:15:43.000Z", params: { modelId: id, providerId: id, model: maxModel }, capability };
  capability.requestDigest = commandAuthorizationDigest(request as never);
  const storedQueueDigest = createHash("sha256").update(JSON.stringify(request), "utf8").digest("hex");
  const response = Buffer.from(JSON.stringify({ requestId: id, jobId: id, hostId: id, sequence: 7, status: "failed",
    progress: null, observedAt: "2026-11-04T16:15:43.000Z", observation: null, errorCode: "ADAPTER_FAILED" }), "utf8");
  assert.ok(response.length < responseLength);
  const responseBytes = Buffer.concat([response, Buffer.alloc(responseLength - response.length, 0x20)]);
  return { storedRequest: request, storedQueueDigest,
    terminal: { hostId: id, jobId: id, requestId: id, state: "timed-out", revision: id.slice(0, revisionLength), occurredAt: "2026-11-04T16:15:43.000Z" },
    native: { kind: "response", responseBytes, authorizationDigest: capability.requestDigest, source: evidenceSource },
    runnerHold: "retained", currentTrust: { provenance: "unverified", hostId: id, bindingRevision: id } };
}
function fixtureResponse(): Buffer {
  const file = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "testdata/native-terminal-evidence-codec-v1.json"), "utf8"));
  return Buffer.from(file.vectors[0].responseBase64, "base64");
}
function paddedResponse(length: number): Buffer {
  const raw = fixtureResponse(); assert.ok(raw.length < length);
  return Buffer.concat([raw, Buffer.alloc(length - raw.length, 0x20)]);
}
function transportPayload(payload: JsonValue) {
  const accept = fakeTransport();
  return accept(payload);
}
function candidateEnvelope(snapshot: ReturnType<typeof maxMetadataSnapshot>, counter: { value: number }) {
  const encoded = encodeNativeTerminalEvidence(snapshot);
  if (!encoded.ok) return { reason: "codec", accepted: false };
  const raw = Buffer.from(encoded.payloadBase64, "base64");
  if (raw.length > PAYLOAD_CANDIDATE) return { reason: "payload-candidate", accepted: false };
  if (snapshot.native.responseBytes.length > RESPONSE_CANDIDATE) return { reason: "response-candidate", accepted: false };
  counter.value++;
  return { reason: "", accepted: transportPayload(raw.toString("base64")).ok };
}

test("real ControllerTransport accepts/rejects exact synthetic result-body byte limits", () => {
  const exact = transportPayload("x".repeat(RESULT_BODY_LIMIT - 2));
  assert.equal(exact.ok, true, JSON.stringify(exact));
  assert.equal(transportPayload("x".repeat(RESULT_BODY_LIMIT - 1)).ok, false);
});

test("current codec maximum response is valid offline but its responseBase64 cannot fit result body", () => {
  const response = paddedResponse(MAX_EVIDENCE_RESPONSE_BYTES);
  assert.equal(response.length, 524288);
  assert.equal(4 * Math.ceil(response.length / 3), 699052);
  const snapshot = syntheticSnapshot(response), encoded = encodeNativeTerminalEvidence(snapshot);
  assert.equal(encoded.ok, true);
  if (!encoded.ok) return;
  const rawPayload = Buffer.from(encoded.payloadBase64, "base64");
  assert.equal(decodeNativeTerminalEvidence(rawPayload, snapshot).ok, true);
  assert.equal(rawPayload.length, 699798);
  assert.equal(createHash("sha256").update(rawPayload).digest("hex"), "e1973574b4082ac653609bfa8c6eb1607c84a21783cb5eeb58b6ac8a96686658");
  assert.equal(rawPayload.toString("base64").length, 933064);
  assert.ok(encoded.payload.responseBase64.length > RESULT_BODY_LIMIT);
  assert.equal(transportPayload(encoded.payload.responseBase64).ok, false);
});

test("proposed future 256-KiB evidence response vector round-trips and fits synthetic transport size only", () => {
  const response = paddedResponse(RESPONSE_CANDIDATE);
  assert.equal(4 * Math.ceil(response.length / 3), 349528);
  const snapshot = syntheticSnapshot(response), encoded = encodeNativeTerminalEvidence(snapshot);
  assert.equal(encoded.ok, true);
  if (!encoded.ok) return;
  const rawPayload = Buffer.from(encoded.payloadBase64, "base64");
  assert.equal(decodeNativeTerminalEvidence(rawPayload, snapshot).ok, true);
  assert.equal(rawPayload.length, 350274);
  assert.equal(createHash("sha256").update(rawPayload).digest("hex"), "580abfc50192432ec31d30b8d7e30258c80f58560001fd962926ec5ff44c4a82");
  assert.ok(rawPayload.length <= PAYLOAD_CANDIDATE);
  const outerBase64 = rawPayload.toString("base64");
  assert.equal(outerBase64.length, 4 * Math.ceil(rawPayload.length / 3));
  // The payload is a raw base64 string solely to test bytes accepted by the
  // existing generic transport boundary; it is NOT an application result DTO.
  const payloadJson = JSON.stringify(outerBase64);
  assert.equal(outerBase64.length, 467032);
  assert.equal(Buffer.byteLength(payloadJson, "utf8"), 467034);
  assert.ok(Buffer.byteLength(payloadJson, "utf8") <= RESULT_BODY_LIMIT);
  const accepted = transportPayload(outerBase64);
  assert.equal(accepted.ok, true, JSON.stringify(accepted));
  const syntheticSignedEnvelopeBytes = Buffer.byteLength(JSON.stringify((accepted as { ok: true; envelope: unknown }).envelope), "utf8");
  assert.ok(syntheticSignedEnvelopeBytes < WHOLE_REQUEST_LIMIT);
  assert.equal(PAYLOAD_CANDIDATE - rawPayload.length > 0, true);
});

test("maximum legal metadata proposal vector is frozen and round-trips", () => {
  const snapshot = maxMetadataSnapshot(RESPONSE_CANDIDATE);
  const encoded = encodeNativeTerminalEvidence(snapshot);
  assert.equal(encoded.ok, true);
  if (!encoded.ok) return;
  const raw = Buffer.from(encoded.payloadBase64, "base64");
  assert.equal(decodeNativeTerminalEvidence(raw, snapshot).ok, true);
  const outer = raw.toString("base64"), wrapped = JSON.stringify(outer);
  const accepted = transportPayload(outer);
  assert.equal(accepted.ok, true, JSON.stringify(accepted));
  const fullEnvelopeBytes = Buffer.byteLength(JSON.stringify((accepted as { ok: true; envelope: unknown }).envelope), "utf8");
  assert.equal(raw.length, 350891);
  assert.equal(createHash("sha256").update(raw).digest("hex"), "ddfa7d7692a7e6f18cedef72386b6507c07133867550edb927d46b123d63e674");
  assert.equal(outer.length, 467856);
  assert.equal(Buffer.byteLength(wrapped, "utf8"), 467858);
  assert.equal(fullEnvelopeBytes, 468323);
  assert.ok(fullEnvelopeBytes < WHOLE_REQUEST_LIMIT);
});

test("future local response/payload candidate +1 rejects before envelope construction", () => {
  const counter = { value: 0 };
  assert.equal(candidateEnvelope(maxMetadataSnapshot(RESPONSE_CANDIDATE + 1), counter).reason, "response-candidate");
  const payloadOverCandidate = maxMetadataSnapshot(275461, "explicit_snapshot", 126);
  const encodedOver = encodeNativeTerminalEvidence(payloadOverCandidate);
  assert.equal(encodedOver.ok, true);
  if (!encodedOver.ok) return;
  assert.equal(Buffer.from(encodedOver.payloadBase64, "base64").length, PAYLOAD_CANDIDATE + 1);
  assert.equal(candidateEnvelope(payloadOverCandidate, counter).reason, "payload-candidate");
  assert.equal(counter.value, 0);
  assert.equal(candidateEnvelope(maxMetadataSnapshot(RESPONSE_CANDIDATE), counter).accepted, true);
  assert.equal(counter.value, 1);
});

test("raw codec payload cap accepts padded valid JSON and rejects cap plus one before transport", () => {
  const snapshot = maxMetadataSnapshot(RESPONSE_CANDIDATE);
  const encoded = encodeNativeTerminalEvidence(snapshot);
  assert.equal(encoded.ok, true);
  if (!encoded.ok) return;
  const raw = Buffer.from(encoded.payloadBase64, "base64");
  const cap = MAX_EVIDENCE_PAYLOAD_BYTES;
  assert.ok(raw.length < cap);
  const atCap = Buffer.concat([raw, Buffer.alloc(cap - raw.length, 0x20)]);
  assert.equal(decodeNativeTerminalEvidence(atCap, snapshot).ok, true);
  const envelopeConstructionCount = { value: 0 };
  assert.equal(decodeNativeTerminalEvidence(Buffer.concat([atCap, Buffer.from(" ")]), snapshot).ok, false);
  assert.equal(envelopeConstructionCount.value, 0);
  envelopeConstructionCount.value++;
  assert.equal(transportPayload(atCap.toString("base64")).ok, false);
  assert.equal(envelopeConstructionCount.value, 1);
});

test("UTF-8 transport body uses byte measurement distinct from JavaScript string length", () => {
  const payload = { evidence: "雪" }, serialized = JSON.stringify(payload);
  assert.equal(serialized.length, 16, "JS string length");
  assert.equal(Buffer.byteLength(serialized, "utf8"), 18, "UTF-8 byte length passed by ControllerTransport");
  assert.equal(transportPayload(payload).ok, true);
});

test("outer encoding of current maximum codec payload exceeds existing result body arithmetic", () => {
  assert.equal(MAX_EVIDENCE_PAYLOAD_BYTES, 786432);
  assert.equal(4 * Math.ceil(MAX_EVIDENCE_PAYLOAD_BYTES / 3), 1048576);
  assert.equal(4 * Math.ceil(PAYLOAD_CANDIDATE / 3), 491520);
  assert.equal(RESULT_BODY_LIMIT - 491520, 32768);
  assert.equal(4 * Math.ceil(MAX_EVIDENCE_RESPONSE_BYTES / 3), 699052);
  assert.equal(JSON.stringify({ evidence: "雪" }).length, 16);
  assert.equal(Buffer.byteLength(JSON.stringify({ evidence: "雪" }), "utf8"), 18);
});
