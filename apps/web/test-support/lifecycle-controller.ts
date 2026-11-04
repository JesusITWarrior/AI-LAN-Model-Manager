// Offline synthetic inventory; real production application/auth/policy/proposals and full runtime restart.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";
import type { OperationPolicy } from "@lan-model-manager/core";
import { createControllerApplication, type ControllerApplicationOptions } from "../../controller/src/controller-application.js";
import { CertificateRepository } from "../../controller/src/certificate-repository.js";
const T0 = "2026-09-29T10:00:00.000Z";
const policy: OperationPolicy = { version: 1, allowedOperations: ["model-load", "model-drain", "model-unload"], approvalOperations: [], allowArtifactAcquisition: false, allowArtifactRemoval: false, allowSubstitution: false, allowPublicExposure: false, minimumMemoryHeadroomBytes: 1, minimumVramHeadroomBytes: 0, minimumStorageHeadroomBytes: 1, maxConcurrentOperations: 10, maxOperationsPerMinute: 100 };
export async function browserController(closeTimeoutMs = 5000) {
  const probe = createServer();
  await new Promise<void>(resolve => probe.listen(0, "127.0.0.1", resolve));
  const address = probe.address(); assert.ok(address && typeof address === "object");
  const port = address.port;
  await new Promise<void>(resolve => probe.close(() => resolve()));
  const root = mkdtempSync(join(tmpdir(), "lanmm-lifecycle-http-"));
  let now = T0, random = 1;
  const options: ControllerApplicationOptions = {
    closeTimeoutMs,
    config: { bindHost: "127.0.0.1", port, inferenceHost: "127.0.0.1", inferencePort: port + 1, dataDir: root, logLevel: "info", discoveryEnabled: false, publicInferenceEnabled: false, tlsRequired: true, mutualTlsRequired: true },
    plan: { rootDir: root, databasePath: join(root, "controller.sqlite3"), artifactDir: join(root, "artifacts"), cacheDir: join(root, "cache"), stagingDir: join(root, "staging"), quarantineDir: join(root, "quarantine"), auditDir: join(root, "audit"), certificateDir: join(root, "certificates") },
    runtimeDependencies: { now: () => now, random: n => Buffer.alloc(n, random++), ownerId: () => "a".repeat(32), passwordCrypto: { random: n => Buffer.alloc(n, 3), async derive(password, salt, parameters) { return Buffer.alloc(parameters.keyLength, createHash("sha256").update(password).update(salt).digest()[0]); }, equal: (a, b) => Buffer.from(a).equals(Buffer.from(b)) } },
  };
  const app = createControllerApplication(options);
  try {
  await app.start();
  const base = `http://127.0.0.1:${port}`;
  const post = (path: string, value: unknown, headers: Record<string, string> = {}) => fetch(base + path, { method: "POST", headers: { "content-type": "application/json", origin: base, connection: "close", ...headers }, body: JSON.stringify(value) });
  const credentials = { username: "Owner", password: "synthetic-password-for-http-tests" };
  assert.equal((await post("/auth/v1/bootstrap", credentials)).status, 200);
  const login = await post("/auth/v1/login", credentials); assert.equal(login.status, 200);
  const cookie = login.headers.get("set-cookie")!.split(";", 1)[0]!;
  const csrf = (await login.json() as any).value.csrfToken;
  const headers = { cookie, "x-csrf-token": csrf };
  const repos = app.runtime.repositories, pem = "-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n", fp = "b".repeat(64), certs = new CertificateRepository(repos.db);
  certs.insertCa({ caId: "c".repeat(64), version: 1, serial: "10", fingerprint: "c".repeat(64), certificatePem: pem, notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2036-01-01T00:00:00.000Z", createdAt: T0 });
  certs.insertHost({ certificateId: fp, serial: "ABCD", fingerprint: fp, certificatePem: pem, caId: "c".repeat(64), caVersion: 1, binding: { candidateId: "host-1", address: "192.0.2.10", port: 7443, protocolMajor: 1, protocolMinor: 0 }, spiffeUri: "spiffe://lanmodelmanager/host/host-1", challengeId: "d".repeat(64), transcriptDigest: "e".repeat(64), notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2027-01-01T00:00:00.000Z", status: "active", version: 1, issuedAt: T0, revokedAt: null });
  repos.hosts.upsert({ hostId: "host-1", displayName: "Synthetic host", platform: "linux", observedAt: T0, online: true, freshness: "fresh", snapshot: { resource: { hostId: "host-1", platform: "linux", observedAt: T0, cpuLogicalCores: 4, cpuUtilizationPercent: 0, memory: { totalBytes: 100, usedBytes: 10, availableBytes: 90 }, storage: { totalBytes: 100, usedBytes: 10, availableBytes: 90 }, accelerators: [] } } });
  repos.providers.upsert({ providerId: "provider-1", hostId: "host-1", kind: "ollama", endpoint: "http://127.0.0.1:11434", health: "ready", version: "", versionKnown: false, observedAt: T0, snapshot: {} });
  repos.models.upsert({ modelId: "model-1", providerId: "provider-1", hostId: "host-1", canonicalName: "example/model:latest", state: "installed", type: "llm", digest: "", digestKnown: false, observedAt: T0, snapshot: { runtimeState: "unloaded", activeRequests: 0 } });
  repos.db.prepare("INSERT INTO fleet_liveness(host_id,certificate_fingerprint,protocol_minor,last_sequence,last_observed_at,last_request_id,idle,updated_at) VALUES(?,?,?,?,?,?,?,?)").run("host-1", fp, 0, 1, T0, "heartbeat-1", 1, T0);
  let current=app;
  return { headers, base, post, async restart(){await current.close();current=createControllerApplication(options);await current.start();},
    async install(approval:boolean,version:number){const r=await post("/api/v1/policy/install",{...policy,version,approvalOperations:approval?["model-load"]:[]},headers);assert.equal(r.status,200);},
    jobs(){return (current.runtime.repositories.db.prepare("SELECT COUNT(*) n FROM jobs").get() as {n:number}).n;},
    async close(){try{await current.close();}finally{rmSync(root,{recursive:true,force:true});}}};
  } catch(error) {
    try{await app.close();}finally{rmSync(root,{recursive:true,force:true});}
    throw error;
  }
}
