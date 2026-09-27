import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

export type PersistenceErrorCode =
  | "ERR_DATABASE_PATH"
  | "ERR_DATABASE_OPEN"
  | "ERR_MIGRATION_LEDGER"
  | "ERR_MIGRATION_FUTURE"
  | "ERR_MIGRATION_MISMATCH"
  | "ERR_MIGRATION_APPLY";

export class PersistenceError extends Error {
  readonly code: PersistenceErrorCode;
  constructor(code: PersistenceErrorCode) {
    super(code);
    this.name = "PersistenceError";
    this.code = code;
  }
}

export interface Migration {
  readonly version: number;
  readonly name: string;
  readonly sql: string;
  readonly checksum: string;
}

export function migrationChecksum(sql: string): string {
  return createHash("sha256").update(sql).digest("hex");
}

const migration1Sql = `
CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY CHECK(version > 0),
  name TEXT NOT NULL UNIQUE,
  checksum TEXT NOT NULL CHECK(length(checksum) = 64),
  applied_at TEXT NOT NULL
) STRICT;
CREATE TABLE hosts (
  host_id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  platform TEXT NOT NULL CHECK(platform IN ('linux','darwin','windows')),
  observed_at TEXT NOT NULL,
  online INTEGER NOT NULL CHECK(online IN (0,1)),
  freshness TEXT NOT NULL CHECK(freshness IN ('fresh','stale','offline')),
  snapshot_json TEXT NOT NULL CHECK(json_valid(snapshot_json)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;
CREATE TABLE providers (
  provider_id TEXT PRIMARY KEY,
  host_id TEXT NOT NULL REFERENCES hosts(host_id) ON UPDATE RESTRICT ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK(kind IN ('ollama','lmstudio')),
  endpoint TEXT NOT NULL,
  health TEXT NOT NULL CHECK(health IN ('ready','degraded','unavailable','failed')),
  version TEXT NOT NULL,
  version_known INTEGER NOT NULL CHECK(version_known IN (0,1)),
  observed_at TEXT NOT NULL,
  snapshot_json TEXT NOT NULL CHECK(json_valid(snapshot_json)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;
CREATE INDEX providers_host_idx ON providers(host_id, provider_id);
CREATE TABLE models (
  model_id TEXT PRIMARY KEY,
  provider_id TEXT NOT NULL REFERENCES providers(provider_id) ON UPDATE RESTRICT ON DELETE CASCADE,
  host_id TEXT NOT NULL REFERENCES hosts(host_id) ON UPDATE RESTRICT ON DELETE CASCADE,
  canonical_name TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('available','installed','running')),
  type TEXT NOT NULL CHECK(type IN ('llm','embedding','unknown')),
  digest TEXT NOT NULL,
  digest_known INTEGER NOT NULL CHECK(digest_known IN (0,1)),
  observed_at TEXT NOT NULL,
  snapshot_json TEXT NOT NULL CHECK(json_valid(snapshot_json)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(provider_id, canonical_name)
) STRICT;
CREATE INDEX models_provider_idx ON models(provider_id, canonical_name, model_id);
CREATE INDEX models_host_idx ON models(host_id, canonical_name, model_id);
CREATE INDEX models_state_idx ON models(state, model_id);
`;

const migration2Sql = `
CREATE TABLE jobs (
  job_id TEXT PRIMARY KEY,
  state TEXT NOT NULL CHECK(state IN ('submitted','validated','authorized','dispatched','accepted','running','succeeded','failed','timed-out','cancelled')),
  host_id TEXT NOT NULL,
  submitted_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  attempt INTEGER NOT NULL CHECK(attempt > 0),
  idempotency_key TEXT NOT NULL UNIQUE,
  payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
  created_at TEXT NOT NULL
) STRICT;
CREATE INDEX jobs_state_idx ON jobs(state, updated_at, job_id);
CREATE INDEX jobs_host_idx ON jobs(host_id, updated_at, job_id);
CREATE TABLE job_history (
  history_id INTEGER PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
  from_state TEXT NOT NULL,
  to_state TEXT NOT NULL,
  attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 100),
  occurred_at TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;
CREATE INDEX job_history_job_idx ON job_history(job_id, history_id);
CREATE TABLE audit_events (
  seq INTEGER PRIMARY KEY CHECK(seq > 0),
  event_json TEXT NOT NULL CHECK(json_valid(event_json)),
  body_json TEXT NOT NULL CHECK(json_valid(body_json)),
  outcome TEXT NOT NULL CHECK(outcome IN ('observed','allowed','denied','started','succeeded','failed','cancelled')),
  previous_hash TEXT CHECK(previous_hash IS NULL OR length(previous_hash) = 64),
  hash TEXT NOT NULL UNIQUE CHECK(length(hash) = 64),
  created_at TEXT NOT NULL
) STRICT;
`;

const migration3Sql = `
CREATE TABLE owners (
  singleton_key INTEGER PRIMARY KEY CHECK(singleton_key = 1),
  owner_id TEXT NOT NULL UNIQUE CHECK(length(owner_id) = 32),
  username_display TEXT NOT NULL CHECK(length(username_display) BETWEEN 1 AND 64),
  username_normalized TEXT NOT NULL UNIQUE CHECK(length(username_normalized) BETWEEN 1 AND 64),
  credential_hash TEXT NOT NULL CHECK(length(credential_hash) BETWEEN 64 AND 512),
  disabled INTEGER NOT NULL CHECK(disabled IN (0,1)),
  credential_version INTEGER NOT NULL CHECK(credential_version > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;
`;

export const CONTROLLER_MIGRATIONS: readonly Migration[] = Object.freeze([
  Object.freeze({ version: 1, name: "inventory-v1", sql: migration1Sql, checksum: migrationChecksum(migration1Sql) }),
  Object.freeze({ version: 2, name: "durable-jobs-v1", sql: migration2Sql, checksum: migrationChecksum(migration2Sql) }),
  Object.freeze({ version: 3, name: "owner-credentials-v1", sql: migration3Sql, checksum: migrationChecksum(migration3Sql) }),
]);

function validateMigrations(migrations: readonly Migration[]): void {
  if (migrations.length === 0) throw new PersistenceError("ERR_MIGRATION_LEDGER");
  for (let index = 0; index < migrations.length; index += 1) {
    const item = migrations[index];
    if (!item || item.version !== index + 1 || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(item.name) ||
        !/^[a-f0-9]{64}$/.test(item.checksum) || migrationChecksum(item.sql) !== item.checksum) {
      throw new PersistenceError("ERR_MIGRATION_LEDGER");
    }
  }
}

function userVersion(db: DatabaseSync): number {
  try {
    const row = db.prepare("PRAGMA user_version").get() as { user_version?: unknown } | undefined;
    if (!row || typeof row.user_version !== "number" || !Number.isSafeInteger(row.user_version) || row.user_version < 0) {
      throw new Error();
    }
    return row.user_version;
  } catch {
    throw new PersistenceError("ERR_MIGRATION_MISMATCH");
  }
}

function verifyApplied(db: DatabaseSync, current: number, migrations: readonly Migration[]): void {
  if (current === 0) return;
  try {
    const rows = db.prepare("SELECT version,name,checksum FROM schema_migrations ORDER BY version").all() as
      Array<{ version: number; name: string; checksum: string }>;
    if (rows.length !== current) throw new Error();
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      const expected = migrations[index];
      if (!row || !expected || row.version !== expected.version || row.name !== expected.name || row.checksum !== expected.checksum) throw new Error();
    }
  } catch {
    throw new PersistenceError("ERR_MIGRATION_MISMATCH");
  }
}

export function migrateControllerDatabase(db: DatabaseSync, migrations: readonly Migration[] = CONTROLLER_MIGRATIONS): number {
  validateMigrations(migrations);
  try { db.exec("PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;"); } catch { throw new PersistenceError("ERR_MIGRATION_APPLY"); }
  const current = userVersion(db);
  if (current > migrations.length) throw new PersistenceError("ERR_MIGRATION_FUTURE");
  verifyApplied(db, current, migrations);
  for (const migration of migrations.slice(current)) {
    try {
      db.exec("BEGIN IMMEDIATE");
      db.exec(migration.sql);
      db.prepare("INSERT INTO schema_migrations(version,name,checksum,applied_at) VALUES(?,?,?,?)")
        .run(migration.version, migration.name, migration.checksum, new Date().toISOString());
      db.exec(`PRAGMA user_version=${migration.version}`);
      db.exec("COMMIT");
    } catch {
      try { db.exec("ROLLBACK"); } catch { /* already rolled back */ }
      throw new PersistenceError("ERR_MIGRATION_APPLY");
    }
  }
  return migrations.length;
}

export interface OpenControllerDatabaseOptions { readonly readOnly?: boolean; readonly enableWal?: boolean }

export function openControllerDatabase(path: string, options: OpenControllerDatabaseOptions = {}): DatabaseSync {
  if (typeof path !== "string" || path.length === 0 || path.includes("\0")) throw new PersistenceError("ERR_DATABASE_PATH");
  let db: DatabaseSync;
  try {
    db = new DatabaseSync(path, { open: true, readOnly: options.readOnly ?? false, enableForeignKeyConstraints: true, timeout: 5_000 });
  } catch { throw new PersistenceError("ERR_DATABASE_OPEN"); }
  try {
    db.exec("PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
    if (!(options.readOnly ?? false) && path !== ":memory:" && (options.enableWal ?? true)) db.exec("PRAGMA journal_mode=WAL");
    if (options.readOnly ?? false) {
      const current = userVersion(db);
      if (current > CONTROLLER_MIGRATIONS.length) throw new PersistenceError("ERR_MIGRATION_FUTURE");
      if (current !== CONTROLLER_MIGRATIONS.length) throw new PersistenceError("ERR_MIGRATION_MISMATCH");
      verifyApplied(db, current, CONTROLLER_MIGRATIONS);
    } else migrateControllerDatabase(db);
    return db;
  } catch (error) {
    db.close();
    if (error instanceof PersistenceError) throw error;
    throw new PersistenceError("ERR_DATABASE_OPEN");
  }
}
