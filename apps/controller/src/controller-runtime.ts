import * as fs from "node:fs";
import { randomBytes } from "node:crypto";
import { resolve, sep } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import type { PasswordCryptoEngine } from "./credentials.js";
import { createOwnerBootstrapService, type OwnerBootstrapService } from "./owner-service.js";
import { SessionManager } from "./session-manager.js";
import { createInferenceTokenManager, type InferenceTokenManager } from "./inference-manager.js";
import { PairingManager } from "./pairing-manager.js";
import { FleetQueryService } from "./fleet-queries.js";
import { PolicyService } from "./policy-service.js";
import { PersistentReplayStore } from "./transport/replay-store.js";
import { CertificateManager } from "./certificate-manager.js";
import { OpenSslCertificateEngine } from "./certificate-adapter.js";
import type { CertificateEngine } from "./certificate-types.js";

import { openControllerDatabase } from "./database.js";
import type { ControllerRepositories } from "./repositories.js";
import { createControllerRepositories } from "./repositories.js";
import { createJobStores as jobsStoreFactory, type JobStores } from "./jobs-store.js";
import {
  type ControllerConfig,
  type ControllerPathPlan,
  CONTROLLER_CONFIG_KEYS,
} from "./config.js";

/**
 * Bounded controller-runtime composition.
 *
 * This module composes the already-validated {@link ControllerConfig} and
 * {@link ControllerPathPlan} into a small, immutable runtime handle. It
 * deliberately wires no ambient network listener: no `node:net`, `node:http`,
 * or `node:tls` is imported. Any lifecycle behaviour is supplied by the caller
 * through {@link RuntimeLifecycleHooks} injected at build time.
 *
 * Responsibilities (all synchronous, all fail-closed):
 *   - Enforce lexical path containment plus practical symlink-escape rejection
 *     (existing directory symlinks and the database file included).
 *   - Create only the declared root/contained directories, with 0700
 *     permissions where the platform supports them.
 *   - Open/migrate the SQLite database through {@link openControllerDatabase}
 *     and compose repositories + job store through their existing factories.
 *   - Roll back only the directories created by a failed attempt and close an
 *     obtained database at most once.
 *   - Redact every hostile/leaky dependency error into a stable runtime error
 *     code whose message is the code itself (no value or stack material leaks).
 *
 * The returned handle is frozen (immutable) only as an outer view; the mutable
 * runtime internals it delegates to are intentionally left mutable so start/
 * stop/close and DB lifecycle keep working.
 */


export interface ControllerCoreServices {
  readonly owner: OwnerBootstrapService;
  readonly sessions: SessionManager;
  readonly inferenceTokens: InferenceTokenManager;
  readonly pairing: PairingManager;
  readonly certificates: CertificateManager;
  readonly fleet: FleetQueryService;
  readonly policy: PolicyService;
  readonly replay: PersistentReplayStore;
}

export interface CoreServiceDependencies {
  readonly now?: () => string;
  readonly random?: (size: number) => Uint8Array;
  readonly ownerId?: () => string;
  readonly passwordCrypto?: PasswordCryptoEngine;
  readonly certificateEngine?: CertificateEngine;
}

/** Stable, redacted runtime error-code namespace. Message === code. */
export type ControllerRuntimeErrorCode =
  | "ERR_RUNTIME_CONFIG"
  | "ERR_RUNTIME_PATH_PLAN"
  | "ERR_RUNTIME_PATH_CONTAINMENT"
  | "ERR_RUNTIME_DIRECTORY"
  | "ERR_RUNTIME_DATABASE_OPEN"
  | "ERR_RUNTIME_COMPOSITION"
  | "ERR_RUNTIME_START_HOOK"
  | "ERR_RUNTIME_STOP_HOOK"
  | "ERR_RUNTIME_CLOSED";

/**
 * A runtime error carries only its stable code. The message is intentionally
 * equal to the code so that no leaked secret, path, SQLite internals, or stack
 * material can ever surface to a caller.
 */
export class ControllerRuntimeError extends Error {
  readonly code: ControllerRuntimeErrorCode;
  readonly detail: readonly string[];
  constructor(code: ControllerRuntimeErrorCode) {
    super(code);
    this.name = "ControllerRuntimeError";
    this.code = code;
    // Fully redacted: the message is the stable code, never the underlying
    // error. detail is frozen and empty by construction.
    this.detail = Object.freeze<readonly string[]>([]);
  }
}

/** Subset of `node:fs` actually used by the runtime (injectable for tests). */
export interface ControllerFs {
  readonly existsSync: (path: string) => boolean;
  readonly realpathSync: (path: string) => string;
  readonly lstatSync: (path: string) => { readonly isSymbolicLink: () => boolean };
  readonly mkdirSync: (
    path: string,
    options?: { readonly recursive?: boolean; readonly mode?: number },
  ) => void;
  readonly chmodSync: (path: string, mode: number) => void;
  readonly rmSync: (path: string, options?: { readonly recursive?: boolean; readonly force?: boolean }) => void;
}

/** Open a SQLite database file (migrating it through `openControllerDatabase`). */
export type OpenDatabaseFn = (databasePath: string) => DatabaseSync;
/** Compose repositories against an already-open database. */
export type BuildRepositoriesFn = (
  db: DatabaseSync,
  now: () => string,
) => ControllerRepositories;
/** Compose the job/audit store against an already-open database. */
export type BuildJobStoresFn = (db: DatabaseSync, now: () => string) => JobStores;

/**
 * All cross-cutting dependencies the runtime may need, fully injectable so that
 * rollback / close-once / redaction can be proved without ambient mutation.
 * Every field is optional and defaults to the real implementation.
 */
export interface RuntimeDependencies extends CoreServiceDependencies {
  readonly fs?: ControllerFs;
  readonly openDatabase?: OpenDatabaseFn;
  readonly buildRepositories?: BuildRepositoriesFn;
  readonly buildJobStores?: BuildJobStoresFn;
}

/** Caller-supplied lifecycle hooks. Invoked only by explicit start/stop. */
export interface RuntimeLifecycleHooks {
  /** Run after a successful start. May throw to abort the start. */
  readonly onStart?: (context: RuntimeHookContext) => void;
  /** Run when a running runtime is stopped. May throw to abort the stop. */
  readonly onStop?: (context: RuntimeHookContext) => void;
}

/** Context passed to lifecycle hooks (immutable view). */
export interface RuntimeHookContext {
  readonly plan: ControllerPathPlan;
  /** Directories created by this build attempt (possibly empty). */
  readonly directories: readonly string[];
}

/** A frozen, immutable runtime handle. See {@link createControllerRuntime}. */
export interface ControllerRuntimeHandle {
  /** The root directory for this runtime (from the plan). */
  readonly rootDir: string;
  /** The validated path plan this runtime was composed from. */
  readonly plan: ControllerPathPlan;
  /** Repositories composed against the runtime database (rejected after close). */
  readonly repositories: ControllerRepositories;
  /** The job/audit store composed against the runtime database. */
  readonly jobStores: JobStores;
  /** Runtime-owned non-network authoritative services. */
  readonly services: ControllerCoreServices;
  /** True while the runtime has been started and not stopped/closed. */
  readonly isActive: boolean;
  /** True once {@link ControllerRuntimeHandle.close} has run (exactly once). */
  readonly isClosed: boolean;
  /** Start the runtime (idempotent; runnable after each other). */
  readonly start: () => void;
  /** Stop the runtime (idempotent). */
  readonly stop: () => void;
  /** Close the runtime, closing the database at most once. */
  readonly close: () => void;
}

/** Runtime state machine (internal). */
type RuntimeLifecycleState = "created" | "active" | "stopped" | "closed";

/** Options for {@link createControllerRuntime}. */
export interface RuntimeBuildOptions {
  /** An already-validated controller configuration. */
  readonly config: ControllerConfig;
  /** An already-validated path plan that must derive from `config.dataDir`. */
  readonly plan: ControllerPathPlan;
  /** Optional lifecycle hooks (start/stop). No listeners are wired by us. */
  readonly hooks?: RuntimeLifecycleHooks;
  /** Optional dependency overrides for tests / edge cases. */
  readonly dependencies?: RuntimeDependencies;
}

const NATIVE_FLAVOR: "posix" | "win32" = process.platform === "win32" ? "win32" : "posix";

const PLAN_LEAF_DIRS = Object.freeze([
  "artifactDir",
  "cacheDir",
  "stagingDir",
  "quarantineDir",
  "auditDir",
  "certificateDir",
] as const);

const PLAIN_RECORD_ERROR = "ERR_RUNTIME_PATH_PLAN";

function isPlainRecord(input: unknown, keys: readonly string[]): boolean {
  if (typeof input !== "object" || input === null || Array.isArray(input)) return false;
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const own = Reflect.ownKeys(input);
  if (own.length !== keys.length) return false;
  if (own.some((key) => typeof key !== "string" || !keys.includes(key))) return false;
  if (keys.some((key) => !own.includes(key))) return false;
  const descriptors = Object.getOwnPropertyDescriptors(input);
  return keys.every((key) => {
    const descriptor = descriptors[key];
    return !!descriptor && "value" in descriptor;
  });
}

function containsWithin(root: string, child: string): boolean {
  return child === root || child.startsWith(root + sep);
}

/**
 * Internal runtime implementation. Mutable internals are intentional; only the
 * frozen {@link ControllerRuntimeHandle} view exposes this to callers.
 */
class RuntimeImpl {
  readonly rootDir: string;
  readonly plan: ControllerPathPlan;

  private readonly fs: ControllerFs;
  private readonly hooks: RuntimeLifecycleHooks | undefined;
  private readonly openDatabase: OpenDatabaseFn;
  private readonly buildRepositories: BuildRepositoriesFn;
  private readonly buildJobStores: BuildJobStoresFn;
  private readonly now: () => string;
  private readonly random: (size: number) => Uint8Array;
  private readonly ownerId: () => string;
  private readonly passwordCrypto: PasswordCryptoEngine | undefined;
  private readonly certificateEngine: CertificateEngine;

  private state: RuntimeLifecycleState = "created";
  private db: DatabaseSync | null = null;
  private dbSettled = false;
  private repositoriesValue!: ControllerRepositories;
  private jobStoresValue!: JobStores;
  private servicesValue!: ControllerCoreServices;
  private createdDirs: string[] = [];
  private databaseCreated = false;

  constructor(rawOptions: RuntimeBuildOptions) {
    this.fs = rawOptions.dependencies?.fs ?? (fs as unknown as ControllerFs);
    this.now = rawOptions.dependencies?.now ?? (() => new Date().toISOString());
    this.random = rawOptions.dependencies?.random ?? ((size) => randomBytes(size));
    this.ownerId = rawOptions.dependencies?.ownerId ?? (() => Buffer.from(this.random(16)).toString("hex"));
    this.passwordCrypto = rawOptions.dependencies?.passwordCrypto;
    this.certificateEngine = rawOptions.dependencies?.certificateEngine ?? new OpenSslCertificateEngine();
    const options = this.#validate(rawOptions);
    this.plan = options.plan;
    this.rootDir = options.plan.rootDir;
    this.hooks = options.hooks;
    this.openDatabase = options.dependencies?.openDatabase ?? openControllerDatabase;
    this.buildRepositories = options.dependencies?.buildRepositories ?? ((db, now) => createControllerRepositories(db, { now }));
    this.buildJobStores = options.dependencies?.buildJobStores ?? ((db, now) => jobsStoreFactory(db, { now }));

    this.#compose();
  }

  // -- handle view ---------------------------------------------------------

  get isActive(): boolean {
    return this.state === "active";
  }

  get isClosed(): boolean {
    return this.state === "closed";
  }

  get repositories(): ControllerRepositories {
    if (this.state === "closed") throw new ControllerRuntimeError("ERR_RUNTIME_CLOSED");
    return this.repositoriesValue;
  }

  get jobStores(): JobStores {
    if (this.state === "closed") throw new ControllerRuntimeError("ERR_RUNTIME_CLOSED");
    return this.jobStoresValue;
  }

  get services(): ControllerCoreServices {
    if (this.state === "closed") throw new ControllerRuntimeError("ERR_RUNTIME_CLOSED");
    return this.servicesValue;
  }

  start(): void {
    if (this.state === "closed") throw new ControllerRuntimeError("ERR_RUNTIME_CLOSED");
    if (this.state === "active") return;
    const context: RuntimeHookContext = Object.freeze({ plan: this.plan, directories: Object.freeze([...this.createdDirs]) });
    try {
      this.hooks?.onStart?.(context);
      this.state = "active";
    } catch (error) {
      this.#closeDbOnce();
      this.#rollbackCreated();
      this.state = "closed";
      // Redacted: the hook's message/secrets never escape as this code.
      throw new ControllerRuntimeError("ERR_RUNTIME_START_HOOK");
    }
  }

  stop(): void {
    if (this.state === "closed") throw new ControllerRuntimeError("ERR_RUNTIME_CLOSED");
    if (this.state !== "active") return;
    const context: RuntimeHookContext = Object.freeze({ plan: this.plan, directories: Object.freeze([...this.createdDirs]) });
    try {
      this.hooks?.onStop?.(context);
      this.state = "stopped";
    } catch {
      // A failed stop cannot be rolled back (nothing to recreate); close the DB
      // and mark the runtime closed. Directories persist.
      this.#closeDbOnce();
      this.state = "closed";
      throw new ControllerRuntimeError("ERR_RUNTIME_STOP_HOOK");
    }
  }

  close(): void {
    if (this.state === "closed") return;
    this.state = "closed";
    this.#closeDbOnce();
  }

  // -- composition ---------------------------------------------------------

  #validate(options: RuntimeBuildOptions): {
    readonly config: ControllerConfig;
    readonly plan: ControllerPathPlan;
    readonly hooks: RuntimeLifecycleHooks | undefined;
    readonly dependencies: RuntimeDependencies | undefined;
  } {
    const configKeys = CONTROLLER_CONFIG_KEYS as readonly string[];
    if (!isPlainRecord(options.config, configKeys)) {
      throw new ControllerRuntimeError("ERR_RUNTIME_CONFIG");
    }
    const planKeys = Object.freeze(["rootDir", ...PLAN_LEAF_DIRS, "databasePath"] as const);
    if (!isPlainRecord(options.plan, [...planKeys])) {
      throw new ControllerRuntimeError("ERR_RUNTIME_PATH_PLAN");
    }
    // The plan must derive from the configuration's data root.
    if (resolve(options.plan.rootDir) !== resolve(options.config.dataDir)) {
      throw new ControllerRuntimeError("ERR_RUNTIME_CONFIG");
    }
    return { config: options.config, plan: options.plan, hooks: options.hooks, dependencies: options.dependencies };
  }

  #compose(): void {
    const declared: string[] = [this.plan.rootDir, ...PLAN_LEAF_DIRS.map((key) => this.plan[key])];
    let stage: "containment" | "directory" | "database" | "composition" = "containment";
    try {
      const rootLexical = resolve(this.plan.rootDir);
      const rootExists = this.fs.existsSync(this.plan.rootDir);
      if (rootExists && this.fs.lstatSync(this.plan.rootDir).isSymbolicLink()) throw new Error();
      const rootReal = rootExists ? this.fs.realpathSync(this.plan.rootDir) : rootLexical;
      for (const child of [...declared, this.plan.databasePath]) {
        const childLexical = resolve(child);
        if (!containsWithin(rootLexical, childLexical)) throw new Error();
        if (this.fs.existsSync(child)) {
          if (this.fs.lstatSync(child).isSymbolicLink()) throw new Error();
          const childReal = this.fs.realpathSync(child);
          if (!containsWithin(rootReal, childReal)) throw new Error();
        }
      }

      stage = "directory";
      this.createdDirs = [];
      for (const dir of declared) {
        if (this.fs.existsSync(dir)) {
          this.#enforceMode(dir);
          continue;
        }
        this.fs.mkdirSync(dir, { mode: 0o700, recursive: true });
        this.createdDirs.push(dir);
        this.#enforceMode(dir);
      }
      stage = "database";
      this.databaseCreated = !this.fs.existsSync(this.plan.databasePath);
      this.db = this.openDatabase(this.plan.databasePath);
      stage = "composition";
      this.repositoriesValue = this.buildRepositories(this.db, this.now);
      this.jobStoresValue = this.buildJobStores(this.db, this.now);
      const owner = createOwnerBootstrapService(this.db, { now: this.now, ownerId: this.ownerId, ...(this.passwordCrypto ? { crypto: this.passwordCrypto } : {}) });
      const sessions = new SessionManager(this.db, owner, { clock: this.now, random: this.random });
      const authorizeOwner = (value: unknown) => owner.authenticate(value);
      const authorizeSession = async (value: unknown) => sessions.authenticate(value) !== null;
      this.servicesValue = Object.freeze({
        owner,
        sessions,
        inferenceTokens: createInferenceTokenManager(this.db, authorizeSession, { clock: this.now, random: this.random }),
        pairing: new PairingManager(this.db, authorizeOwner, { clock: this.now, random: this.random }),
        certificates: new CertificateManager(this.db, this.certificateEngine, this.plan.certificateDir, { clock: this.now, random: this.random }),
        fleet: new FleetQueryService(this.db, this.repositoriesValue, { clock: this.now }),
        policy: new PolicyService(this.db, { clock: this.now, random: this.random, stores: this.jobStoresValue }),
        replay: new PersistentReplayStore(this.db),
      });
    } catch {
      const code: ControllerRuntimeErrorCode =
        stage === "containment" ? "ERR_RUNTIME_PATH_CONTAINMENT"
          : stage === "directory" ? "ERR_RUNTIME_DIRECTORY"
            : stage === "database" ? "ERR_RUNTIME_DATABASE_OPEN"
              : "ERR_RUNTIME_COMPOSITION";
      this.#closeDbOnce();
      this.#rollbackCreated();
      throw new ControllerRuntimeError(code);
    }
  }

  #enforceMode(dir: string): void {
    if (NATIVE_FLAVOR === "win32") return;
    try {
      this.fs.chmodSync(dir, 0o700);
    } catch {
      /* best effort where the platform does not support restrictive mode */
    }
  }

  #rollbackCreated(): void {
    if (this.databaseCreated) {
      for (const suffix of ["", "-wal", "-shm"]) {
        try { this.fs.rmSync(`${this.plan.databasePath}${suffix}`, { force: true }); } catch { /* best effort */ }
      }
      this.databaseCreated = false;
    }
    const dirs = [...this.createdDirs].reverse();
    this.createdDirs = [];
    for (const dir of dirs) {
      try {
        this.fs.rmSync(dir, { recursive: true, force: true });
      } catch {
        /* best effort; nothing else to recover */
      }
    }
  }

  #closeDbOnce(): void {
    if (this.dbSettled) return;
    this.dbSettled = true;
    const db = this.db;
    this.db = null;
    if (db) {
      try {
        db.close();
      } catch {
        /* already closed / unrecoverable; ignore */
      }
    }
  }
}

/**
 * Build (and compose) a bounded controller runtime from an already-validated
 * config + path plan. This is synchronous and fail-closed: any failure in
 * directory setup, database open/composition, or path containment throws a
 * {@link ControllerRuntimeError} (message equals the code) after rolling back
 * only the directories created by this attempt and closing an obtained
 * database at most once.
 */
export function createControllerRuntime(options: RuntimeBuildOptions): ControllerRuntimeHandle {
  const impl = new RuntimeImpl(options);
  return Object.freeze<ControllerRuntimeHandle>({
    get rootDir() {
      return impl.rootDir;
    },
    get plan() {
      return impl.plan;
    },
    get repositories() {
      return impl.repositories;
    },
    get jobStores() {
      return impl.jobStores;
    },
    get services() {
      return impl.services;
    },
    get isActive() {
      return impl.isActive;
    },
    get isClosed() {
      return impl.isClosed;
    },
    start() {
      impl.start();
    },
    stop() {
      impl.stop();
    },
    close() {
      impl.close();
    },
  });
}
