import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { parseDiscoveryCandidate, type PairingBinding } from "@lan-model-manager/core";
import { OpenSslCertificateEngine } from "./certificate-adapter.js";
import { CertificateManager } from "./certificate-manager.js";
import type { PasswordCryptoEngine } from "./credentials.js";
import { openControllerDatabase } from "./database.js";
import { createEnrollmentHttpHandler } from "./enrollment-http.js";
import { createOwnerBootstrapService } from "./owner-service.js";
import { PairingManager } from "./pairing-manager.js";

const binding: PairingBinding = { candidateId: "agent-1", address: "192.168.1.20", port: 7443, protocolMajor: 1, protocolMinor: 0 };
const passwordCrypto = (): PasswordCryptoEngine => ({
  random: size => Buffer.alloc(size, 3),
  async derive(password, salt, options) { const seed = createHash("sha256").update(password).update(salt).digest(); return Buffer.alloc(options.keyLength, seed[0]); },
  equal: (left, right) => Buffer.from(left).equals(Buffer.from(right)),
});

function issueLoopbackServerCertificate(root: string, caDirectory: string): { key: string; cert: string } {
  const directory = join(root, "tls");
  mkdirSync(directory, { mode: 0o700 });
  chmodSync(directory, 0o700);
  execFileSync("openssl", ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "server-key.pem"], { cwd: directory, stdio: "ignore" });
  execFileSync("openssl", ["req", "-new", "-sha256", "-key", "server-key.pem", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1", "-out", "server.csr"], { cwd: directory, stdio: "ignore" });
  writeFileSync(join(directory, "server.ext"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=critical,serverAuth\nsubjectAltName=IP:127.0.0.1\n", { mode: 0o600 });
  execFileSync("openssl", ["x509", "-req", "-sha256", "-in", "server.csr", "-CA", join(caDirectory, "ca-cert.pem"), "-CAkey", join(caDirectory, "ca-key.pem"), "-set_serial", "0x2001", "-days", "1", "-extfile", "server.ext", "-out", "server-cert.pem"], { cwd: directory, stdio: "ignore" });
  return { key: readFileSync(join(directory, "server-key.pem"), "utf8"), cert: readFileSync(join(directory, "server-cert.pem"), "utf8") };
}

async function waitUntil(predicate: () => boolean, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for Go enrollment request");
    await new Promise(resolveDelay => setTimeout(resolveDelay, 10));
  }
}

test("real TypeScript TLS enrollment handler enrolls and restarts the Go client", { timeout: 30_000 }, async () => {
  execFileSync("go", ["version"], { stdio: "ignore" });
  execFileSync("openssl", ["version"], { stdio: "ignore" });
  const root = mkdtempSync(join(tmpdir(), "lanmm-cross-enrollment-"));
  const database = openControllerDatabase(":memory:");
  let server: ReturnType<typeof createServer> | undefined;
  try {
    const now = () => new Date().toISOString();
    const owner = createOwnerBootstrapService(database, { now, ownerId: () => "d".repeat(32), crypto: passwordCrypto() });
    await owner.bootstrapOwner({ username: "admin", password: "owner-password-123" });
    const pairing = new PairingManager(database, async credential => credential === "owner", { clock: now, ttlMs: 60_000 });
    const caDirectory = join(root, "controller-ca");
    const certificates = new CertificateManager(database, new OpenSslCertificateEngine(), caDirectory, { clock: now, random: size => Buffer.alloc(size, 0x2a) });
    const ca = certificates.initialize();
    const observedAt = now();
    const parsed = parseDiscoveryCandidate({ id: binding.candidateId, displayName: "Agent", protocolVersion: { major: 1, minor: 0 }, agentPort: binding.port, platform: "linux", address: binding.address, observedAt, ttlSeconds: 120 });
    assert.equal(parsed.ok, true);
    if (!parsed.ok) return;
    let presentation: Awaited<ReturnType<PairingManager["create"]>> = null;
    let pendingLookups = 0;
    const begin = async (requested: PairingBinding) => {
      if (JSON.stringify(requested) !== JSON.stringify(binding)) return null;
      const created = await pairing.create("owner", parsed.value);
      if (!created || !pairing.present(created.challengeId)) return null;
      presentation = created;
      return created;
    };
    const pairingForRoute = {
      pendingOwnerConfirmation(input: unknown) {
        const pending = pairing.pendingOwnerConfirmation(input);
        if (pending) pendingLookups++;
        return pending;
      },
      pendingAgentProof: (input: unknown) => pairing.pendingAgentProof(input),
      verifyAgentProof: (input: unknown) => pairing.verifyAgentProof(input),
      consume: (challengeId: unknown) => pairing.consume(challengeId),
    };
    const tls = issueLoopbackServerCertificate(root, caDirectory);
    const responses: Array<{ readonly path: string; readonly status: number }> = [];
    const enrollmentHandler = createEnrollmentHttpHandler({ begin, pairing: pairingForRoute, certificates });
    server = createServer({ key: tls.key, cert: tls.cert, minVersion: "TLSv1.3", maxVersion: "TLSv1.3" }, (request, response) => {
      response.once("finish", () => responses.push({ path: request.url ?? "", status: response.statusCode }));
      enrollmentHandler(request, response);
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    assert.ok(address && typeof address === "object");

    const agentDirectory = join(root, "agent-certificates");
    const repositoryRoot = resolve(import.meta.dirname, "../../..");
    const child = spawn("go", ["test", "./internal/enrollment", "-run", "^TestCrossLanguageEnrollmentHelper$", "-count=1", "-v"], {
      cwd: join(repositoryRoot, "agents/host-agent"),
      env: {
        ...process.env,
        LANMM_CROSS_LANGUAGE_CONTROLLER_URL: `https://127.0.0.1:${address.port}`,
        LANMM_CROSS_LANGUAGE_CA_PEM: ca.certificatePem,
        LANMM_CROSS_LANGUAGE_CA_PIN: ca.fingerprint,
        LANMM_CROSS_LANGUAGE_CERT_DIR: agentDirectory,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "", stderr = "", lines = "";
    let confirmation: Promise<void> | undefined;
    const consumeLines = () => {
      const complete = lines.split("\n");
      lines = complete.pop() ?? "";
      for (const line of complete) {
        const match = /LANMM_CROSS_LANGUAGE_OPERATOR_CODE=([23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{8})/.exec(line);
        if (!match || confirmation) continue;
        confirmation = (async () => {
          await waitUntil(() => pendingLookups > 0);
          assert.ok(presentation);
          assert.ok(await pairing.confirm("owner", { challengeId: presentation.challengeId, code: match[1], binding }));
        })();
      }
    };
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", chunk => { stdout += chunk; lines += chunk; consumeLines(); });
    child.stderr.on("data", chunk => { stderr += chunk; });
    const exitCode = await new Promise<number | null>((resolveExit, rejectExit) => { child.once("error", rejectExit); child.once("close", resolveExit); });
    consumeLines();
    await confirmation;
    assert.equal(exitCode, 0, `Go enrollment helper failed\nresponses: ${JSON.stringify(responses)}\nstdout:\n${stdout}\nstderr:\n${stderr}`);
    assert.ok(confirmation, `Go helper did not present an operator code\n${stdout}`);
    const resultMatch = /LANMM_CROSS_LANGUAGE_RESULT=(\{[^\n]+\})/.exec(stdout);
    assert.ok(resultMatch, stdout);
    const result = JSON.parse(resultMatch[1]!) as Record<string, unknown>;
    assert.deepEqual(result, { certificatePersisted: true, challengeId: presentation!.challengeId, privateKeyPersisted: true, restartStatus: "enrolled", restartTransport: "nil", status: "enrolled" });
    assert.ok(pendingLookups > 0, "Go client did not poll while owner confirmation was pending");
    assert.equal(pairing.get(presentation!.challengeId)?.state, "consumed");
    const issued = database.prepare("SELECT cert_id, certificate, challenge_id FROM host_certificates WHERE challenge_id=?").get(presentation!.challengeId) as Record<string, unknown> | undefined;
    assert.ok(issued && typeof issued.cert_id === "string" && String(issued.certificate).includes("BEGIN CERTIFICATE"));
    assert.equal(readFileSync(join(agentDirectory, "enrollment.json"), "utf8").includes("PRIVATE KEY"), false);
  } finally {
    if (server) await new Promise<void>(resolveClose => server!.close(() => resolveClose()));
    database.close();
    rmSync(root, { recursive: true, force: true });
  }
});
