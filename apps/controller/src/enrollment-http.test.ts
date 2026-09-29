import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { request as httpRequest } from "node:http";
import test from "node:test";
import { parseDiscoveryCandidate, type CertificateAuthorityMetadata, type PairingBinding } from "@lan-model-manager/core";
import { createControllerServer } from "./app.js";
import { CertificateError, type CertificateEngine } from "./certificate-types.js";
import { CertificateManager } from "./certificate-manager.js";
import { openControllerDatabase } from "./database.js";
import { createEnrollmentHttpHandler, ENROLLMENT_BODY_LIMIT } from "./enrollment-http.js";
import { routeEnrollmentRequest } from "./enrollment-api.js";
import type { PasswordCryptoEngine } from "./credentials.js";
import { createOwnerBootstrapService } from "./owner-service.js";
import { PairingManager, pairingProof } from "./pairing-manager.js";

const START = "2026-09-29T14:00:00.000Z", PIN = "a".repeat(64), CERT = "-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n";
const binding: PairingBinding = { candidateId: "agent-1", address: "192.168.1.20", port: 7443, protocolMajor: 1, protocolMinor: 0 };
const passwordCrypto = (): PasswordCryptoEngine => ({ random: size => Buffer.alloc(size, 3), async derive(password, salt, options) { const seed = createHash("sha256").update(password).update(salt).digest(); return Buffer.alloc(options.keyLength, seed[0]); }, equal: (a, b) => Buffer.from(a).equals(Buffer.from(b)) });
class Engine implements CertificateEngine {
  issues = 0;
  readonly ca: CertificateAuthorityMetadata = { caId: PIN, version: 1, serial: "10", fingerprint: PIN, certificatePem: CERT, notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2036-01-01T00:00:00.000Z", createdAt: "2026-01-01T00:00:00.000Z" };
  initializeCa() { return this.ca; } inspectCa() { return this.ca; }
  inspectCsr(input: { csrPem: string }) { if (input.csrPem !== "valid-csr") throw new CertificateError("ERR_CERTIFICATE_CSR"); return { csrPem: input.csrPem, candidateId: binding.candidateId, address: binding.address, spiffeUri: `spiffe://lanmodelmanager/host/${binding.candidateId}`, publicKeyFingerprint: "b".repeat(64) }; }
  issueHost(input: { csrPem: string; serial: string }) { this.inspectCsr(input); this.issues++; return { certificatePem: CERT, fingerprint: "b".repeat(64), serial: input.serial, notBefore: "2026-09-29T13:59:00.000Z", notAfter: "2026-10-29T14:00:00.000Z", caCertificatePem: CERT }; }
  verifyHost() { return true; }
}
async function fixture() {
  const db = openControllerDatabase(":memory:"); let now = START, random = 0;
  const owner = createOwnerBootstrapService(db, { now: () => now, ownerId: () => "d".repeat(32), crypto: passwordCrypto() });
  await owner.bootstrapOwner({ username: "admin", password: "owner-password-123" });
  const pairing = new PairingManager(db, async credential => credential === "owner", { clock: () => now, random: size => Buffer.alloc(size, ++random), ttlMs: 600_000 });
  const certificates = new CertificateManager(db, new Engine(), "/unused", { clock: () => now, random: size => Buffer.alloc(size, 42) });
  const parsed = parseDiscoveryCandidate({ id: binding.candidateId, displayName: "Agent", protocolVersion: { major: 1, minor: 0 }, agentPort: binding.port, platform: "linux", address: binding.address, observedAt: START, ttlSeconds: 600 });
  if (!parsed.ok) throw new Error("invalid test candidate");
  const candidate = parsed.value;
  const begin = async (requested: PairingBinding) => {
    if (JSON.stringify(requested) !== JSON.stringify(binding)) return null;
    const value = await pairing.create("owner", candidate);
    if (!value || !pairing.present(value.challengeId)) return null;
    return value;
  };
  const post = (path: string, body: unknown, headers: Record<string, string> = {}) => routeEnrollmentRequest({ begin, pairing, certificates }, { method: "POST", url: path, headers: { "content-type": "application/json", ...headers }, body: typeof body === "string" ? body : JSON.stringify(body) });
  return { db, pairing, certificates, begin, post, setNow: (value: string) => { now = value; } };
}
function proofFor(challenge: any) {
  const agentNonce = Buffer.alloc(32, 9).toString("base64url");
  return { challengeId: challenge.challengeId, controllerNonce: challenge.controllerNonce, agentNonce, proof: pairingProof(challenge.operatorCode, challenge.challengeId, challenge.controllerNonce, agentNonce, challenge.binding), binding: challenge.binding, caFingerprint: PIN, csrPem: "valid-csr" };
}

test("live enrollment begins from exact binding, presents one-time code, then proves and issues once", async () => {
  const x = await fixture(); try {
    const begun = await x.post("/agent/v1/enrollment/begin", { binding, caFingerprint: PIN });
    assert.equal(begun.status, 200); const challenge = (begun.body as any).value;
    assert.deepEqual(Object.keys(challenge).sort(), ["binding", "caFingerprint", "challengeId", "controllerNonce", "expiresAt", "operatorCode"]);
    assert.equal(x.pairing.get(challenge.challengeId)?.state, "presented");
    assert.ok(await x.pairing.confirm("owner", { challengeId: challenge.challengeId, code: challenge.operatorCode, binding: challenge.binding }));
    const completed = await x.post("/agent/v1/enrollment/complete", proofFor(challenge));
    assert.equal(completed.status, 200); assert.equal((completed.body as any).value.certificateFingerprint, "b".repeat(64)); assert.equal(x.pairing.get(challenge.challengeId)?.state, "consumed");
    assert.equal((await x.post("/agent/v1/enrollment/complete", proofFor(challenge))).status, 400);
  } finally { x.db.close(); }
});

test("wrong pin/binding/proof, expiry, replay, and malformed CSR fail generically", async () => {
  const x = await fixture(); try {
    const wrongPin = await x.post("/agent/v1/enrollment/begin", { binding, caFingerprint: "f".repeat(64) }); assert.equal(wrongPin.status, 400);
    const wrongBinding = await x.post("/agent/v1/enrollment/begin", { binding: { ...binding, port: 7444 }, caFingerprint: PIN }); assert.equal(wrongBinding.status, 400);
    let begun = await x.post("/agent/v1/enrollment/begin", { binding, caFingerprint: PIN }); const challenge = (begun.body as any).value;
    assert.ok(await x.pairing.confirm("owner", { challengeId: challenge.challengeId, code: challenge.operatorCode, binding: challenge.binding }));
    const wrongProof = await x.post("/agent/v1/enrollment/complete", { ...proofFor(challenge), proof: "0".repeat(64) }); assert.equal(wrongProof.status, 400); assert.equal(x.pairing.get(challenge.challengeId)?.state, "owner_confirmed");
    x.setNow(challenge.expiresAt); const expired = await x.post("/agent/v1/enrollment/complete", proofFor(challenge)); assert.equal(expired.status, 400); assert.equal(x.pairing.get(challenge.challengeId)?.state, "expired");
    x.db.prepare("DELETE FROM pairing_challenges").run(); x.setNow(START); begun = await x.post("/agent/v1/enrollment/begin", { binding, caFingerprint: PIN }); const malformedChallenge = (begun.body as any).value; assert.ok(await x.pairing.confirm("owner", { challengeId: malformedChallenge.challengeId, code: malformedChallenge.operatorCode, binding }));
    const malformed = await x.post("/agent/v1/enrollment/complete", { ...proofFor(malformedChallenge), csrPem: "not-a-csr" }); assert.equal(malformed.status, 400); assert.equal(x.pairing.get(malformedChallenge.challengeId)?.state, "consumed");
    for (const result of [wrongPin, wrongBinding, wrongProof, expired, malformed]) assert.deepEqual((result.body as any).error, { code: "ENROLLMENT_FAILED", message: "Enrollment failed." });
  } finally { x.db.close(); }
});

test("duplicate and oversized JSON are bounded, credentials are not confused, and wiring is closed by default", async context => {
  const calls = { begin: 0, proof: 0, consume: 0 };
  const deps: any = { begin() { calls.begin++; return null; }, pairing: { verifyAgentProof() { calls.proof++; return {}; }, consume() { calls.consume++; return null; } }, certificates: { initialize() { return { fingerprint: PIN, certificatePem: CERT }; }, enroll() { throw new Error("must not run"); } } };
  const closed = createControllerServer(); closed.listen(0, "127.0.0.1"); await once(closed, "listening"); context.after(() => closed.close()); const closedAddress = closed.address(); assert.ok(closedAddress && typeof closedAddress === "object"); assert.equal((await fetch(`http://127.0.0.1:${closedAddress.port}/agent/v1/enrollment/begin`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).status, 404);
  const handler = createEnrollmentHttpHandler(deps, { rateLimit: 6 }); const server = createControllerServer(undefined, undefined, undefined, undefined, handler); server.listen(0, "127.0.0.1"); await once(server, "listening"); context.after(() => server.close()); const address = server.address(); assert.ok(address && typeof address === "object"); const url = `http://127.0.0.1:${address.port}/agent/v1/enrollment/begin`;
  const duplicate = `{"binding":{},"binding":{},"caFingerprint":"${PIN}"}`; assert.equal((await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: duplicate })).status, 400);
  for (const headers of [{ authorization: "Bearer ***" }, { cookie: "__Host-lanmm_session=management" }, { "x-csrf-token": "management" }]) { const result = await fetch(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: "{}" }); assert.equal(result.status, 401); }
  assert.deepEqual(calls, { begin: 0, proof: 0, consume: 0 });
  const oversize = await new Promise<number>((resolve, reject) => { const request = httpRequest({ host: "127.0.0.1", port: address.port, path: "/agent/v1/enrollment/begin", method: "POST", headers: { "content-type": "application/json", "content-length": String(ENROLLMENT_BODY_LIMIT + 1) } }, response => { resolve(response.statusCode ?? 0); response.resume(); }); request.on("error", reject); request.end(); }); assert.equal(oversize, 413);
  assert.equal((await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).status, 400); assert.equal((await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).status, 429);
});
