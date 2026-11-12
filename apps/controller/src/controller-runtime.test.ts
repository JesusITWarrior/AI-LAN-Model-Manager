import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { CONTROLLER_MIGRATIONS, migrateControllerDatabase, openControllerDatabase } from "./database.js";
import type { DatabaseSync } from "node:sqlite";
import type { PasswordCryptoEngine } from "./credentials.js";
import { RemoteInferenceService } from "./remote-inference.js";
import { commandAuthorizationDigest, commandPolicyOperation, type CommandRequest, type CommandResponse } from "@lan-model-manager/core";
import { CertificateRepository } from "./certificate-repository.js";
import { OpenSslCertificateEngine } from "./certificate-adapter.js";
import { AgentCommandStore } from "./agent-command-channel.js";
import { CommandDispatcher } from "./command-dispatch.js";
import { buildOwnerNativeEvidenceSnapshot } from "./owner-native-evidence-snapshot.js";
import { encodeNativeTerminalEvidence } from "./native-terminal-evidence-codec.js";
import { OwnerNativeEvidenceCandidateRegistry } from "./owner-native-evidence-candidates.js";
import { SessionManager } from "./session-manager.js";
import {
  createControllerRuntime,
  ControllerRuntimeError,
  type RuntimeBuildOptions,
  type RuntimeLifecycleHooks,
  type RuntimeDependencies,
} from "./controller-runtime.js";

// ---------------------------------------------------------------------------
// Deterministic, injectable config + plan pair (synchronous, no I/O in build).

const t0 = "2026-09-27T05:00:00.000Z";

function makePlan(root: string): RuntimeBuildOptions["plan"] {
  return {
    rootDir: root,
    databasePath: join(root, "controller.sqlite3"),
    artifactDir: join(root, "artifacts"),
    cacheDir: join(root, "cache"),
    stagingDir: join(root, "staging"),
    quarantineDir: join(root, "quarantine"),
    auditDir: join(root, "audit"),
    certificateDir: join(root, "certificates"),
  };
}

function baseOptions(plan: RuntimeBuildOptions["plan"]): RuntimeBuildOptions {
  return {
    config: {
      bindHost: "127.0.0.1",
      port: 7340,
      inferenceHost: "127.0.0.1",
      inferencePort: 7341,
      dataDir: plan.rootDir,
      logLevel: "info",
      discoveryEnabled: false,
      publicInferenceEnabled: false,
      tlsRequired: true,
      mutualTlsRequired: false,
    },
    plan,
  };
}

function optionsWithDependencies(
  plan: RuntimeBuildOptions["plan"],
  deps: RuntimeDependencies,
  hooks?: RuntimeLifecycleHooks,
): RuntimeBuildOptions {
  if (hooks) {
    return { ...baseOptions(plan), dependencies: deps, hooks };
  }
  return { ...baseOptions(plan), dependencies: deps };
}

const CONTAINED_SUBDIRS = Object.freeze(["artifacts", "cache", "staging", "quarantine", "audit", "certificates"]);

function subdirs(root: string): string[] {
  const entries = readdirSync(root, { withFileTypes: true });
  return entries.filter((d) => d.isDirectory()).map((d) => d.name).sort();
}

function deterministicPasswordCrypto(): PasswordCryptoEngine {
  return {
    random: size => Buffer.alloc(size, 7),
    async derive(password, salt, parameters) {
      const seed = createHash("sha256").update(Buffer.from(password)).update(Buffer.from(salt)).digest();
      return Buffer.alloc(parameters.keyLength, seed[0]);
    },
    equal: (left, right) => Buffer.from(left).equals(Buffer.from(right)),
  };
}

function observeEvidenceClose(events: string[], afterClose?: () => void): () => void {
  const prototype = OwnerNativeEvidenceCandidateRegistry.prototype as unknown as { close: () => void };
  const original = prototype.close;
  prototype.close = function () {
    events.push("evidence-close");
    original.call(this);
    afterClose?.();
  };
  return () => { prototype.close = original; };
}

// ---------------------------------------------------------------------------
// NOTE ON SEMANTICS (kept coherent across these tests):
// The runtime composes eagerly and synchronously. Directory setup failures,
// database open failures, and composition (buildRepositories/buildJobStores)
// failures are all thrown synchronously from createControllerRuntime(). Only
// the injected lifecycle hooks (start/stop) fail from runtime.start()/stop().
// A successful handle exposes start/stop/close; use after close is rejected.

test("build creates exactly the declared directories and no extras", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-runtime-"));
  try {
    const plan = makePlan(dir);
    const runtime = createControllerRuntime(baseOptions(plan));
    try {
      assert.equal(runtime.rootDir, dir);
      assert.deepEqual(subdirs(dir), [...CONTAINED_SUBDIRS].sort());
      assert.equal(Object.keys(runtime.plan).length, 8);
      assert.equal(runtime.isActive, false);
      assert.equal(runtime.isClosed, false);
    } finally {
      runtime.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("created directories get mode 0700 where POSIX supports it", () => {
  if (process.platform === "win32") return;
  const dir = mkdtempSync(join(tmpdir(), "lanmm-mode-"));
  try {
    const plan = makePlan(dir);
    const runtime = createControllerRuntime(baseOptions(plan));
    try {
      const sub = subdirs(dir);
      assert.equal(sub.length, CONTAINED_SUBDIRS.length);
      for (const child of sub) {
        const mode = statSync(join(dir, child)).mode & 0o777;
        assert.equal(mode, 0o700, `expected 0700 for ${child}`);
      }
    } finally {
      runtime.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runtime persists job state across a simulated restart (close + reopen)", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-persist-"));
  const plan = makePlan(dir);
  const runtime = createControllerRuntime(baseOptions(plan));
  runtime.start();
  try {
    runtime.jobStores.jobs.create({
      operation: {
        jobId: "job-1",
        requestId: "request-1",
        action: "load",
        hostId: "host-1",
        submittedAt: "2026-09-26T12:00:00.000Z",
        manifestRevision: null,
        idempotencyKey: "idem-1",
        idempotent: true,
      },
      state: "submitted",
      updatedAt: "2026-09-26T12:00:01.000Z",
      progressPercent: null,
      attempt: 1,
      terminalCode: null,
      terminalMessage: null,
    });

    runtime.stop();
    runtime.close();
    const runtime2 = createControllerRuntime(baseOptions(plan));
    runtime2.start();
    try {
      const jobs = runtime2.jobStores.jobs.list("submitted");
      assert.equal(jobs.length, 1);
      assert.equal(jobs[0]?.jobId, "job-1");
    } finally {
      runtime2.stop();
      runtime2.close();
    }
  } finally {
    runtime.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runtime owns one immutable non-network service graph with shared deterministic authority", async () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-services-"));
  const plan = makePlan(dir);
  const options = {
    ...baseOptions(plan),
    dependencies: {
      now: () => t0,
      random: (size: number) => Buffer.alloc(size, 9),
      ownerId: () => "a".repeat(32),
      passwordCrypto: deterministicPasswordCrypto(),
    },
  };
  try {
    const runtime = createControllerRuntime(options);
    const services = runtime.services;
    assert.equal(Object.isFrozen(services), true);
    assert.equal(runtime.services, services);
    assert.equal(typeof (services as unknown as { listen?: unknown }).listen, "undefined");
    const owner = await services.owner.bootstrapOwner({ username: "admin", password: "owner-password-123" });
    assert.equal(owner.ownerId, "a".repeat(32));
    const session = await services.sessions.create({ username: "admin", password: "owner-password-123" });
    assert.ok(session);
    assert.equal(session.metadata.createdAt, t0);
    const token = await services.inferenceTokens.issue(session.sessionToken, { label: "alpha" });
    assert.ok(token);
    assert.equal(token.metadata.tokenId, "09".repeat(16));
    runtime.close();
    assert.throws(() => runtime.services, (error: unknown) => error instanceof ControllerRuntimeError && error.code === "ERR_RUNTIME_CLOSED");

    const reopened = createControllerRuntime(options);
    try {
      assert.equal(reopened.services.owner.isInitialized(), true);
      assert.equal(await reopened.services.owner.authenticate({ username: "admin", password: "owner-password-123" }), true);
    } finally {
      reopened.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("start/stop/close are idempotent; use after close is rejected with ERR_RUNTIME_CLOSED", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-idempotent-"));
  try {
    const plan = makePlan(dir);
    const runtime = createControllerRuntime(baseOptions(plan));
    try {
      runtime.start();
      assert.equal(runtime.isActive, true);
      runtime.start();
      assert.equal(runtime.isActive, true);
      runtime.stop();
      assert.equal(runtime.isActive, false);
      runtime.stop();
      runtime.close();
      runtime.close();
      assert.equal(runtime.isClosed, true);

      assert.throws(() => runtime.start(), (e: unknown) => e instanceof ControllerRuntimeError && (e as ControllerRuntimeError).code === "ERR_RUNTIME_CLOSED");
      assert.throws(() => runtime.stop(), (e: unknown) => e instanceof ControllerRuntimeError && (e as ControllerRuntimeError).code === "ERR_RUNTIME_CLOSED");
      assert.throws(() => runtime.repositories, (e: unknown) => e instanceof ControllerRuntimeError && (e as ControllerRuntimeError).code === "ERR_RUNTIME_CLOSED");
      assert.throws(() => runtime.jobStores, (e: unknown) => e instanceof ControllerRuntimeError && (e as ControllerRuntimeError).code === "ERR_RUNTIME_CLOSED");
    } finally {
      runtime.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("start hook failure rolls back only directories created this attempt", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-hook-"));
  try {
    const plan = makePlan(join(dir, "root"));
    // Pre-create the root and exactly one subdir ("artifacts") so they are NOT
    // "created by this attempt". The remaining declared subdirs will be created
    // by construction; a failed start must roll ONLY those back while leaving
    // the preexisting root + artifacts (with its seed file) untouched.
    mkdirSync(plan.rootDir);
    mkdirSync(join(plan.rootDir, "artifacts"));
    writeFileSync(join(plan.rootDir, "artifacts", "seed.txt"), "preexisting");

    const runtime = createControllerRuntime(optionsWithDependencies(plan, {}, {
      onStart: () => {
        throw new Error("hook boom");
      },
    }));
    try {
      runtime.start();
      throw new Error("should have failed");
    } catch (e) {
      assert.ok(e instanceof ControllerRuntimeError);
      assert.equal((e as ControllerRuntimeError).code, "ERR_RUNTIME_START_HOOK");
      // The handle still exists; close it to avoid a leaked db handle.
      runtime.close();
    }

    // Preexisting root and the preexisting artifacts subdir + content survive.
    assert.ok(existsSync(dir));
    assert.ok(existsSync(plan.rootDir), "preexisting root must survive");
    assert.ok(existsSync(join(plan.rootDir, "artifacts", "seed.txt")), "preexisting content survives");
    // The subdirs created by this attempt were rolled back.
    const remaining = subdirs(plan.rootDir);
    assert.deepEqual(remaining, ["artifacts"], "only the preexisting subdir remains");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("failed open via injected openDatabase is rejected at construction and preserves preexisting content", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-rollback-"));
  try {
    const plan = makePlan(join(dir, "root"));
    mkdirSync(plan.rootDir, { recursive: true });
    mkdirSync(join(plan.rootDir, "artifacts"));
    writeFileSync(join(plan.rootDir, "artifacts", "seed.txt"), "unchanged");
    // Pre-create the remaining declared subdirs so nothing else is created.
    for (const sub of ["cache", "staging", "quarantine", "audit", "certificates"]) {
      mkdirSync(join(plan.rootDir, sub));
    }

    // Injected openDatabase throws with a secret in its message. Because
    // composition is eager, createControllerRuntime() throws synchronously with
    // ERR_RUNTIME_DATABASE_OPEN and no leaked material.
    let err: ControllerRuntimeError | undefined;
    try {
      createControllerRuntime(optionsWithDependencies(plan, {
        openDatabase: () => {
          throw new Error("SUP3R-S3CRMJW leaked api key /secrets/api-key/xyz");
        },
      }));
    } catch (e) {
      err = e as ControllerRuntimeError;
    }
    assert.ok(err instanceof ControllerRuntimeError, "expected ERR_RUNTIME_DATABASE_OPEN at construction");
    assert.equal((err as ControllerRuntimeError).code, "ERR_RUNTIME_DATABASE_OPEN");
    const message = (err as ControllerRuntimeError).message;
    assert.ok(message.toLowerCase().indexOf("sup3r-s3secret") < 0, `message leaked: ${message}`);
    const detail = (err as ControllerRuntimeError).detail;
    assert.equal(Object.isFrozen(detail), true);
    assert.equal(detail.length, 0);

    // Preexisting root + seeded content preserved exactly.
    assert.ok(existsSync(join(dir, "root", "artifacts", "seed.txt")));
    assert.deepStrictEqual(subdirs(join(dir, "root")).sort(), [...CONTAINED_SUBDIRS].sort());
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("failed database open removes newly-created SQLite artifacts before directory rollback", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-open-artifact-"));
  try {
    const plan = makePlan(join(dir, "root"));
    mkdirSync(plan.rootDir);
    assert.throws(() => createControllerRuntime(optionsWithDependencies(plan, {
      openDatabase: path => {
        writeFileSync(path, "partial");
        writeFileSync(`${path}-wal`, "partial");
        throw new Error("private database detail");
      },
    })), (error: unknown) => error instanceof ControllerRuntimeError && error.code === "ERR_RUNTIME_DATABASE_OPEN");
    assert.equal(existsSync(plan.databasePath), false);
    assert.equal(existsSync(`${plan.databasePath}-wal`), false);
    assert.deepEqual(subdirs(plan.rootDir), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("lexical containment: plan root equal to config.dataDir is accepted", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-contain-"));
  try {
    const plan = makePlan(dir);
    const runtime = createControllerRuntime(baseOptions(plan));
    try {
      runtime.start();
      assert.equal(runtime.isActive, true);
      runtime.stop();
    } finally {
      runtime.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("pre-existing directory symlink pointing outside root is rejected at construction (ERR_RUNTIME_PATH_CONTAINMENT)", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-symlink-"));
  try {
    const plan = makePlan(join(dir, "root"));
    mkdirSync(plan.rootDir);
    const outsideRoot = join(dir, "outside");
    mkdirSync(outsideRoot);
    // Point a contained subdirectory at a path outside the root.
    symlinkSync(outsideRoot, join(plan.rootDir, "cache"));

    let err: ControllerRuntimeError | undefined;
    try {
      createControllerRuntime(baseOptions(plan));
    } catch (e) {
      err = e as ControllerRuntimeError;
    }
    assert.ok(err instanceof ControllerRuntimeError, "expected ERR_RUNTIME_PATH_CONTAINMENT at construction");
    assert.equal((err as ControllerRuntimeError).code, "ERR_RUNTIME_PATH_CONTAINMENT");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("database file symlink escaping root is rejected at construction (ERR_RUNTIME_PATH_CONTAINMENT)", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-db-symlink-"));
  try {
    const plan = makePlan(join(dir, "root"));
    mkdirSync(plan.rootDir);
    // Create an escaped DB file outside root, then replace the in-root db path
    // with a symlink to it.
    const escapedDir = join(dir, "escaped");
    mkdirSync(escapedDir);
    const escapedDb = join(escapedDir, "controller.sqlite3");
    writeFileSync(escapedDb, "outside-data");
    symlinkSync(escapedDb, plan.databasePath);

    let err: ControllerRuntimeError | undefined;
    try {
      createControllerRuntime(baseOptions(plan));
    } catch (e) {
      err = e as ControllerRuntimeError;
    }
    assert.ok(err instanceof ControllerRuntimeError, "expected ERR_RUNTIME_PATH_CONTAINMENT at construction");
    assert.equal((err as ControllerRuntimeError).code, "ERR_RUNTIME_PATH_CONTAINMENT");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("hostile injected fs.mkdir error is redacted at construction to ERR_RUNTIME_DIRECTORY (no secrets/stack)", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-redact-"));
  try {
    // A custom fs whose mkdir throws a secret-carrying message.
    const hostileFs = {
      existsSync: (_path: string) => false,
      realpathSync: (path: string) => path,
      lstatSync: () => ({ isSymbolicLink: () => false }),
      mkdirSync: () => {
        throw new Error("SUP3R-S3CRMJW leaked api key /secrets/api-key/xyz");
      },
      chmodSync: () => {},
      rmSync: () => {},
    };
    const plan = makePlan(dir);

    let err: ControllerRuntimeError | undefined;
    try {
      createControllerRuntime(optionsWithDependencies(plan, { fs: hostileFs }));
    } catch (e) {
      err = e as ControllerRuntimeError;
    }
    assert.ok(err instanceof ControllerRuntimeError, "expected ERR_RUNTIME_DIRECTORY at construction");
    assert.equal((err as ControllerRuntimeError).code, "ERR_RUNTIME_DIRECTORY");
    const message = (err as ControllerRuntimeError).message;
    assert.ok(message.toLowerCase().indexOf("sup3r-s3secret") < 0, `message leaked: ${message}`);
    const detail = (err as ControllerRuntimeError).detail;
    assert.equal(Object.isFrozen(detail), true);
    assert.equal(detail.length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("injected DB is closed exactly once after a downstream start-hook failure", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-close-once-"));
  try {
    const db = openControllerDatabase(":memory:");
    migrateControllerDatabase(db, CONTROLLER_MIGRATIONS);

    // Track how many times the runtime actually calls db.close().
    let closeCount = 0;
    const observedDb = new Proxy(db, {
      get(target, property) {
        if (property === "close") return () => { closeCount += 1; target.close(); };
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    }) as DatabaseSync;

    const plan = makePlan(join(dir, "root"));
    // Directory setup + db open use real internals; only the start hook fails.
    const runtime = createControllerRuntime(optionsWithDependencies(plan, {
      openDatabase: () => observedDb,
    }, {
      onStart: () => {
        throw new Error("hook boom");
      },
    }));

    try {
      runtime.start();
      throw new Error("should have failed");
    } catch (e) {
      assert.ok(e instanceof ControllerRuntimeError);
      assert.equal((e as ControllerRuntimeError).code, "ERR_RUNTIME_START_HOOK");
    } finally {
      // Calling close again must not double-close the underlying handle.
      runtime.close();
    }

    assert.equal(closeCount, 1, `db.close() called exactly once, got ${closeCount}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("post-close access to repositories/job-store is rejected; double close is a no-op", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-postclose-"));
  try {
    const plan = makePlan(join(dir, "root"));
    const runtime = createControllerRuntime(baseOptions(plan));
    try {
      runtime.close();
      runtime.close(); // second close is a no-op
      assert.equal(runtime.isClosed, true);
      assert.throws(() => runtime.repositories, (e: unknown) => e instanceof ControllerRuntimeError && (e as ControllerRuntimeError).code === "ERR_RUNTIME_CLOSED");
      assert.throws(() => runtime.jobStores, (e: unknown) => e instanceof ControllerRuntimeError && (e as ControllerRuntimeError).code === "ERR_RUNTIME_CLOSED");
    } finally {
      runtime.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runtime builds without an ambient network listener (no net/http)", () => {
  // The runtime composes only file-system + SQLite modules; there is no
  // `node:net` / `node:http` listener to open. Building + starting + closing a
  // runtime therefore cannot bind any port.
  const dir = mkdtempSync(join(tmpdir(), "lanmm-no-net-"));
  try {
    const plan = makePlan(dir);
    const runtime = createControllerRuntime(baseOptions(plan));
    runtime.start();
    runtime.stop();
    runtime.close();
    assert.equal(runtime.isClosed, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("failed composition (injected buildJobStores error) is redacted at construction to ERR_RUNTIME_COMPOSITION and rolls back", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-compose-"));
  try {
    const plan = makePlan(join(dir, "root"));
    mkdirSync(plan.rootDir);
    for (const sub of ["cache", "staging", "quarantine", "audit", "certificates"]) {
      mkdirSync(join(plan.rootDir, sub));
    }

    let err: ControllerRuntimeError | undefined;
    try {
      createControllerRuntime(optionsWithDependencies(plan, {
        buildJobStores: () => {
          throw new Error("SUP3R-S3CRMJW exploded during compose");
        },
      }));
    } catch (e) {
      err = e as ControllerRuntimeError;
    }
    assert.ok(err instanceof ControllerRuntimeError, "expected ERR_RUNTIME_COMPOSITION at construction");
    assert.equal((err as ControllerRuntimeError).code, "ERR_RUNTIME_COMPOSITION");
    const message = (err as ControllerRuntimeError).message;
    assert.ok(message.toLowerCase().indexOf("sup3r-s3secret") < 0, `message leaked: ${message}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("malformed or hostile opt-in evidence configuration fails with a redacted stable runtime code", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-runtime-evidence-config-")), plan = makePlan(join(dir, "root"));
  const hostileProxy = new Proxy({}, { ownKeys() { throw new Error("private proxy trap"); } });
  const accessor = Object.defineProperty({}, "allowedOrigins", { enumerable: true, get() { throw new Error("private getter"); } });
  const cases: unknown[] = [
    { allowedOrigins: [42] },
    { allowedOrigins: ["https://manager.example"], originOptions: { allowLoopbackHttpDevelopment: "private" } },
    hostileProxy,
    accessor,
  ];
  try {
    for (const ownerEvidence of cases) {
      assert.throws(() => createControllerRuntime({ ...baseOptions(plan), ownerEvidence: ownerEvidence as never }),
        (error: unknown) => error instanceof ControllerRuntimeError && error.code === "ERR_RUNTIME_CONFIG" && error.message === "ERR_RUNTIME_CONFIG" && !error.message.includes("private"));
    }
    const optionGetter = Object.defineProperty({ ...baseOptions(plan) }, "ownerEvidence", { get() { throw new Error("private outer getter"); } });
    assert.throws(() => createControllerRuntime(optionGetter as never),
      (error: unknown) => error instanceof ControllerRuntimeError && error.code === "ERR_RUNTIME_CONFIG" && error.message === "ERR_RUNTIME_CONFIG");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("owner evidence is opt-in, shares runtime authority, survives reusable stop, and is retired before database close", async () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-runtime-evidence-owner-"));
  let retained: NonNullable<ReturnType<typeof createControllerRuntime>["services"]["ownerEvidence"]> | undefined;
  const databases: DatabaseSync[] = [];
  const closed: number[] = [], events: string[] = [];
  let sqlCalls = 0;
  const restoreEvidenceClose = observeEvidenceClose(events);
  const openDatabase = (path: string) => {
    const raw = openControllerDatabase(path); databases.push(raw);
    const index = databases.length - 1;
    return new Proxy(raw, { get(target, property) {
      if (property === "close") return () => { events.push("db-close"); closed.push(index); target.close(); };
      if (property === "prepare") return (sql: string) => { sqlCalls++; return target.prepare(sql); };
      const value = Reflect.get(target, property, target); return typeof value === "function" ? value.bind(target) : value;
    } }) as DatabaseSync;
  };
  const plan = makePlan(join(dir, "root"));
  const options = { ...baseOptions(plan), ownerEvidence: { allowedOrigins: ["http://127.0.0.1:7340"], originOptions: { allowLoopbackHttpDevelopment: true } },
    dependencies: { now: () => t0, ownerId: () => "a".repeat(32), passwordCrypto: deterministicPasswordCrypto(), openDatabase } };
  try {
    const disabled = createControllerRuntime(baseOptions(makePlan(join(dir, "default"))));
    assert.equal("ownerEvidence" in disabled.services, false, "omission preserves default runtime composition"); disabled.close();
    const runtime = createControllerRuntime(options);
    retained = runtime.services.ownerEvidence;
    assert.ok(retained); assert.equal(Object.isFrozen(retained), true);
    assert.deepEqual(Object.keys(retained).sort(), ["close", "confirm", "prepare"]);
    assert.equal(runtime.services.ownerEvidence, retained);
    const owner = await runtime.services.owner.bootstrapOwner({ username: "admin", password: "owner-password-123" });
    const session = await runtime.services.sessions.create({ username: "admin", password: "owner-password-123" });
    assert.ok(session); assert.equal(session.metadata.ownerId, owner.ownerId);
    runtime.start(); runtime.stop();
    assert.equal(runtime.services.ownerEvidence, retained, "normal stop retains the same evidence registry");
    runtime.start(); runtime.close(); runtime.close();
    assert.equal(runtime.isClosed, true); assert.deepEqual(closed, [0]);
    assert.deepEqual(events, ["evidence-close", "db-close"], "the actual registry close precedes the DB close exactly once");
    const prototype = SessionManager.prototype as unknown as { authenticate: (...args: unknown[]) => unknown; authenticateCsrf: (...args: unknown[]) => unknown };
    const originalAuthenticate = prototype.authenticate, originalAuthenticateCsrf = prototype.authenticateCsrf;
    let sessionCalls = 0;
    prototype.authenticate = function (...args: unknown[]) { sessionCalls++; return originalAuthenticate.apply(this, args); };
    prototype.authenticateCsrf = function (...args: unknown[]) { sessionCalls++; return originalAuthenticateCsrf.apply(this, args); };
    sqlCalls = 0;
    try {
      assert.deepEqual(retained.prepare({ method: "POST", path: "/api/v1/native-evidence/prepare", cookieHeader: `__Host-lanmm_session=${session.sessionToken}`,
        originHeader: "http://127.0.0.1:7340", csrfHeader: session.csrfToken, jobSelector: "job-1", rawPayloadBytes: Uint8Array.of(1) }),
      { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" });
      assert.equal(sessionCalls, 0, "stale runtime facade denies before the runtime SessionManager");
      assert.equal(sqlCalls, 0, "stale runtime facade denies before the already-closed SQLite handle");
    } finally { prototype.authenticate = originalAuthenticate; prototype.authenticateCsrf = originalAuthenticateCsrf; }
    const replacement = createControllerRuntime(options);
    try { assert.notEqual(replacement.services.ownerEvidence, retained); assert.equal(Object.keys(replacement.services.ownerEvidence!).length, 3); }
    finally { replacement.close(); }
    assert.deepEqual(closed, [0, 1]);
    assert.deepEqual(events, ["evidence-close", "db-close", "evidence-close", "db-close"]);
  } finally { restoreEvidenceClose(); rmSync(dir, { recursive: true, force: true }); }
});

test("late runtime composition failure retires opt-in evidence before closing the obtained database", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-runtime-evidence-late-failure-")), plan = makePlan(join(dir, "root"));
  mkdirSync(plan.rootDir, { recursive: true });
  let dbClosed = 0, sawLateComposition = false;
  const events: string[] = [], restoreEvidenceClose = observeEvidenceClose(events);
  const raw = openControllerDatabase(plan.databasePath);
  const observed = new Proxy(raw, { get(target, property) {
    if (property === "close") return () => { events.push("db-close"); dbClosed++; target.close(); };
    if (property === "prepare") return (sql: string) => {
      if (sql.includes("SELECT job_id FROM agent_commands")) { sawLateComposition = true; throw new Error("late inference composition"); }
      return target.prepare(sql);
    };
    const value = Reflect.get(target, property, target); return typeof value === "function" ? value.bind(target) : value;
  } }) as DatabaseSync;
  try {
    assert.throws(() => createControllerRuntime({ ...baseOptions(plan), ownerEvidence: { allowedOrigins: ["https://manager.example"] }, dependencies: { openDatabase: () => observed } }),
      (error: unknown) => error instanceof ControllerRuntimeError && error.code === "ERR_RUNTIME_COMPOSITION");
    assert.equal(sawLateComposition, true, "failure occurs after evidence composition, in runtime inference composition");
    assert.equal(dbClosed, 1, "obtained database is closed despite late composition failure");
    assert.deepEqual(events, ["evidence-close", "db-close"], "the constructed registry is actually closed before the DB on late failure");
  } finally { restoreEvidenceClose(); try { raw.close(); } catch {} rmSync(dir, { recursive: true, force: true }); }
});

test("terminal runtime start/stop-hook failures close opt-in evidence before the database exactly once", () => {
  for (const phase of ["start", "stop"] as const) {
    const dir = mkdtempSync(join(tmpdir(), `lanmm-runtime-evidence-${phase}-failure-`)), plan = makePlan(join(dir, "root"));
    let evidence: NonNullable<ReturnType<typeof createControllerRuntime>["services"]["ownerEvidence"]> | undefined;
    let closeCount = 0;
    const events: string[] = [], restoreEvidenceClose = observeEvidenceClose(events);
    const openDatabase = (path: string) => {
      const raw = openControllerDatabase(path);
      return new Proxy(raw, { get(target, property) {
        if (property === "close") return () => { events.push("db-close"); closeCount++; target.close(); };
        const value = Reflect.get(target, property, target); return typeof value === "function" ? value.bind(target) : value;
      } }) as DatabaseSync;
    };
    const hooks = phase === "start" ? { onStart: () => { throw new Error("private"); } } : { onStop: () => { throw new Error("private"); } };
    try {
      const runtime = createControllerRuntime({ ...baseOptions(plan), ownerEvidence: { allowedOrigins: ["https://manager.example"] }, hooks,
        dependencies: { now: () => t0, openDatabase } });
      evidence = runtime.services.ownerEvidence; assert.ok(evidence);
      if (phase === "stop") runtime.start();
      assert.throws(() => phase === "start" ? runtime.start() : runtime.stop(), (error: unknown) => error instanceof ControllerRuntimeError && error.code === (phase === "start" ? "ERR_RUNTIME_START_HOOK" : "ERR_RUNTIME_STOP_HOOK"));
      runtime.close(); runtime.close();
      assert.equal(runtime.isClosed, true); assert.equal(closeCount, 1);
      assert.deepEqual(events, ["evidence-close", "db-close"], `${phase} failure closes actual evidence exactly once before DB`);
    } finally { restoreEvidenceClose(); rmSync(dir, { recursive: true, force: true }); }
  }
});

test("inference cleanup throw cannot skip evidence or database close", () => {
  const dir = mkdtempSync(join(tmpdir(), "lanmm-runtime-evidence-inference-cleanup-")), plan = makePlan(join(dir, "root"));
  const original = Object.getOwnPropertyDescriptor(RemoteInferenceService.prototype, "close")!;
  let closeCount = 0;
  const events: string[] = [];
  const restoreEvidenceClose = observeEvidenceClose(events, () => { events.push("evidence-close-throw"); throw new Error("private registry cleanup"); });
  const openDatabase = (path: string) => {
    const raw = openControllerDatabase(path);
    return new Proxy(raw, { get(target, property) {
      if (property === "close") return () => { events.push("db-close"); closeCount++; target.close(); };
      const value = Reflect.get(target, property, target); return typeof value === "function" ? value.bind(target) : value;
    } }) as DatabaseSync;
  };
  try {
    Object.defineProperty(RemoteInferenceService.prototype, "close", { ...original, value() { throw new Error("private inference cleanup"); } });
    const runtime = createControllerRuntime({ ...baseOptions(plan), ownerEvidence: { allowedOrigins: ["https://manager.example"] }, dependencies: { openDatabase } });
    runtime.close(); runtime.close();
    assert.equal(runtime.isClosed, true); assert.equal(closeCount, 1);
    assert.deepEqual(events, ["evidence-close", "evidence-close-throw", "db-close"], "registry cleanup throw is not retried and cannot prevent DB close");
  } finally {
    restoreEvidenceClose();
    Object.defineProperty(RemoteInferenceService.prototype, "close", original);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runtime-owned evidence previews and confirms a real candidate across reusable stop/start", async () => {
  const root = mkdtempSync(join(tmpdir(), "lanmm-runtime-evidence-authority-")), plan = makePlan(join(root, "controller"));
  let now = new Date(Date.now() - 10_000).toISOString(), db!: DatabaseSync;
  const events: string[] = [], restoreEvidenceClose = observeEvidenceClose(events);
  const openDatabase = (path: string) => {
    const raw = openControllerDatabase(path);
    db = new Proxy(raw, { get(target, property) {
      if (property === "close") return () => { events.push("db-close"); target.close(); };
      const value = Reflect.get(target, property, target); return typeof value === "function" ? value.bind(target) : value;
    } }) as DatabaseSync;
    return db;
  };
  try {
    const runtime = createControllerRuntime({ ...baseOptions(plan), ownerEvidence: { allowedOrigins: ["https://manager.example"] },
      dependencies: { now: () => now, ownerId: () => "a".repeat(32), passwordCrypto: deterministicPasswordCrypto(), openDatabase } });
    const evidence = runtime.services.ownerEvidence; assert.ok(evidence);
    const owner = await runtime.services.owner.bootstrapOwner({ username: "Owner", password: "owner-password-123" });
    const session = await runtime.services.sessions.create({ username: "owner", password: "owner-password-123" });
    assert.ok(session); assert.equal(session.metadata.ownerId, owner.ownerId);

    const caDir = join(plan.certificateDir, "ca"), hostDir = join(plan.certificateDir, "host");
    mkdirSync(hostDir, { recursive: true, mode: 0o700 });
    const engine = new OpenSslCertificateEngine(), ca = engine.initializeCa({ directory: caDir, now: new Date(Date.now() - 2_000).toISOString() });
    execFileSync("openssl", ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", join(hostDir, "key.pem")], { stdio: "ignore" });
    execFileSync("openssl", ["req", "-new", "-key", join(hostDir, "key.pem"), "-subj", "/CN=host-1", "-addext",
      "subjectAltName=IP:192.0.2.10,URI:spiffe://lanmodelmanager/host/host-1", "-out", join(hostDir, "request.pem")], { stdio: "ignore" });
    const certNow = new Date().toISOString(), binding = { candidateId: "host-1", address: "192.0.2.10", port: 7443, protocolMajor: 1, protocolMinor: 0 };
    const issued = engine.issueHost({ directory: caDir, csrPem: readFileSync(join(hostDir, "request.pem"), "utf8"), binding, serial: "ABCDEF1234", now: certNow });
    const certs = new CertificateRepository(db); certs.insertCa(ca);
    certs.insertHost({ certificateId: issued.fingerprint, serial: issued.serial, fingerprint: issued.fingerprint, certificatePem: issued.certificatePem,
      caId: ca.caId, caVersion: ca.version, binding, spiffeUri: "spiffe://lanmodelmanager/host/host-1", challengeId: "e".repeat(64),
      transcriptDigest: "f".repeat(64), notBefore: issued.notBefore, notAfter: issued.notAfter, status: "active", version: 1,
      issuedAt: certNow, revokedAt: null });

    now = new Date().toISOString();
    const operation = "probe", jobId = "job-1", hostId = "host-1";
    const request: CommandRequest = { requestId: "request-1", jobId, hostId, operation, idempotencyKey: "idem-1", sequence: 1,
      deadline: new Date(Date.parse(now) + 300_000).toISOString(), capability: { operation: commandPolicyOperation(operation),
        targetKind: "host", targetId: hostId, hostId, modelId: null, requestDigest: "", expiresAt: new Date(Date.parse(now) + 300_000).toISOString() },
      params: { providerId: "provider-1", model: "model:latest" } };
    (request.capability as { requestDigest: string }).requestDigest = commandAuthorizationDigest(request);
    const commands = runtime.services.commands as AgentCommandStore;
    assert.equal(new CommandDispatcher(runtime.jobStores, commands, () => now).dispatch(request).ok, true);
    assert.ok(commands.poll(hostId).command);
    const response: CommandResponse = { requestId: request.requestId, jobId, hostId, sequence: 1, status: "failed", progress: null,
      observedAt: new Date(Date.parse(now) + 1_000).toISOString(), observation: null, errorCode: "ADAPTER_FAILED" };
    now = response.observedAt; assert.ok(commands.complete(hostId, response));
    const builtResult: { value: ReturnType<typeof buildOwnerNativeEvidenceSnapshot> } = { value: null };
    runtime.jobStores.withAuditTransaction(tx => { builtResult.value = buildOwnerNativeEvidenceSnapshot(db, tx, jobId, Buffer.from(JSON.stringify(response)), "synthetic", now); });
    assert.ok(builtResult.value);
    const encoded = encodeNativeTerminalEvidence(builtResult.value.snapshot); assert.ok(encoded.ok);
    const callerBytes = Uint8Array.from(Buffer.from(encoded.payloadBase64, "base64")), originalBytes = callerBytes.slice();
    const prepared = evidence.prepare({ method: "POST", path: "/api/v1/native-evidence/prepare", cookieHeader: `__Host-lanmm_session=${session.sessionToken}`,
      originHeader: "https://manager.example", csrfHeader: session.csrfToken, jobSelector: jobId, rawPayloadBytes: callerBytes });
    assert.equal(prepared.ok, true, "the runtime's real SessionManager, DB, and clock must authorize and preview the payload");
    if (!prepared.ok) return;
    assert.equal(prepared.preview.jobId, jobId); assert.equal(prepared.preview.hostId, hostId); assert.deepEqual(callerBytes, originalBytes);
    const candidate = prepared.preview;
    runtime.start(); runtime.stop();
    assert.equal(runtime.services.ownerEvidence, evidence, "normal stop retains the same evidence registry and candidate");
    runtime.start();
    const protectedState = () => JSON.stringify({
      jobs: db.prepare("SELECT * FROM jobs ORDER BY job_id").all(), histories: db.prepare("SELECT * FROM job_history ORDER BY history_id").all(),
      commands: db.prepare("SELECT * FROM agent_commands ORDER BY job_id").all(), owners: db.prepare("SELECT * FROM owners").all(),
      sessions: db.prepare("SELECT * FROM sessions").all(), hosts: db.prepare("SELECT * FROM host_certificates").all(),
      authorities: db.prepare("SELECT * FROM certificate_authorities").all(), replay: db.prepare("SELECT * FROM transport_replay_state").all(),
    });
    const beforeProtected = protectedState(), auditBefore = Number((db.prepare("SELECT COUNT(*) AS n FROM audit_events").get() as { n: number }).n);
    const evidenceBefore = Number((db.prepare("SELECT COUNT(*) AS n FROM supplemental_native_evidence").get() as { n: number }).n);
    const confirmed = evidence.confirm({ method: "POST", path: "/api/v1/native-evidence/confirm", cookieHeader: `__Host-lanmm_session=${session.sessionToken}`,
      originHeader: "https://manager.example", csrfHeader: session.csrfToken,
      body: JSON.stringify({ candidateHandle: candidate.candidateHandle, expectedTupleDigest: candidate.expectedTupleDigest,
        action: "append-supplemental-native-evidence", disposition: "evidence-only" }) });
    assert.equal(confirmed.outcome, "stored", "the same retained candidate is confirmable after stop/start");
    assert.deepEqual(callerBytes, originalBytes);
    assert.equal(Number((db.prepare("SELECT COUNT(*) AS n FROM supplemental_native_evidence").get() as { n: number }).n), evidenceBefore + 1);
    assert.equal(Number((db.prepare("SELECT COUNT(*) AS n FROM audit_events").get() as { n: number }).n), auditBefore + 1);
    assert.equal(protectedState(), beforeProtected, "confirm changes only supplemental evidence and its append audit");
    runtime.close();
    assert.deepEqual(events, ["evidence-close", "db-close"], "the actual registry closes exactly once before the actual DB");
    assert.deepEqual(evidence.prepare({}), { ok: false, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" });
  } finally {
    restoreEvidenceClose();
    try { db?.close(); } catch { /* runtime already closed it */ }
    rmSync(root, { recursive: true, force: true });
  }
});
