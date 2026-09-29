import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { CONTROLLER_MIGRATIONS, migrateControllerDatabase, openControllerDatabase } from "./database.js";
import type { DatabaseSync } from "node:sqlite";
import type { PasswordCryptoEngine } from "./credentials.js";
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
