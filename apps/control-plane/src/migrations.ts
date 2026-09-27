import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { SqlClient, SqlLease } from "./services/store.js";

export interface ControlPlaneMigration {
  readonly version: string;
  readonly filename: string;
  readonly sql: string;
  readonly checksumSha256: string;
}

export interface ControlPlaneMigrationResult {
  readonly applied: readonly string[];
  readonly skipped: readonly string[];
}

export interface RunControlPlaneMigrationsOptions {
  readonly migrationsDirectory?: string | undefined;
  readonly lockTimeoutMs?: number | undefined;
  readonly appliedBy?: string | undefined;
}

type MigrationRow = Record<string, unknown> & {
  readonly filename: string;
  readonly checksum_sha256: string;
};

const MIGRATION_LOCK_CLASS_ID = 0x41d3;
const MIGRATION_LOCK_OBJECT_ID = 0xc1ea;
const DEFAULT_LOCK_TIMEOUT_MS = 60_000;
const DEFAULT_APPLIED_BY = "control-plane-startup";

export function defaultControlPlaneMigrationsDirectory(): string {
  return join(dirname(fileURLToPath(import.meta.url)), "..", "migrations");
}

function checksumSha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export async function listControlPlaneMigrations(
  migrationsDirectory = defaultControlPlaneMigrationsDirectory()
): Promise<readonly ControlPlaneMigration[]> {
  const entries = await readdir(migrationsDirectory, { withFileTypes: true });
  const filenames = entries
    .filter((entry) => entry.isFile() && /^[0-9]{4}_[A-Za-z0-9_]+\.sql$/.test(entry.name))
    .map((entry) => entry.name)
    .sort();

  return Promise.all(
    filenames.map(async (filename) => {
      const sql = await readFile(join(migrationsDirectory, filename), "utf8");
      return {
        version: filename.slice(0, -".sql".length),
        filename,
        sql,
        checksumSha256: checksumSha256(sql)
      };
    })
  );
}

async function withMigrationClient<T>(client: SqlClient, fn: (executor: SqlClient | SqlLease) => Promise<T>): Promise<T> {
  const lease = await client.connect?.();
  if (lease === undefined) {
    return fn(client);
  }
  try {
    return await fn(lease);
  } finally {
    lease.release();
  }
}

async function ensureMigrationTable(client: SqlClient | SqlLease): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      id bigserial PRIMARY KEY,
      filename text NOT NULL UNIQUE,
      checksum_sha256 text NOT NULL CHECK (checksum_sha256 ~ '^[a-f0-9]{64}$'),
      applied_by text NOT NULL,
      applied_at timestamptz NOT NULL DEFAULT now()
    )
  `);
}

function postgresLockTimeout(timeoutMs: number): string {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    return `${DEFAULT_LOCK_TIMEOUT_MS}ms`;
  }
  return `${Math.trunc(timeoutMs)}ms`;
}

async function advisoryLock(client: SqlClient | SqlLease, timeoutMs: number): Promise<void> {
  await client.query("SELECT set_config('lock_timeout', $1, false)", [postgresLockTimeout(timeoutMs)]);
  try {
    await client.query("SELECT pg_advisory_lock($1, $2)", [MIGRATION_LOCK_CLASS_ID, MIGRATION_LOCK_OBJECT_ID]);
  } catch (error) {
    throw new Error("timed out acquiring control-plane migration advisory lock", { cause: error });
  } finally {
    await client.query("SELECT set_config('lock_timeout', '0', false)").catch(() => undefined);
  }
}

async function advisoryUnlock(client: SqlClient | SqlLease): Promise<void> {
  await client.query("SELECT pg_advisory_unlock($1, $2)", [MIGRATION_LOCK_CLASS_ID, MIGRATION_LOCK_OBJECT_ID]);
}

async function existingMigration(client: SqlClient | SqlLease, filename: string): Promise<MigrationRow | undefined> {
  const result = await client.query<MigrationRow>(
    "SELECT filename, checksum_sha256 FROM schema_migrations WHERE filename = $1",
    [filename]
  );
  return result.rows[0];
}

async function applyMigration(client: SqlClient | SqlLease, migration: ControlPlaneMigration, appliedBy: string): Promise<void> {
  await client.query("BEGIN");
  try {
    await client.query(migration.sql);
    await client.query("INSERT INTO schema_migrations (filename, checksum_sha256, applied_by) VALUES ($1, $2, $3)", [
      migration.filename,
      migration.checksumSha256,
      appliedBy
    ]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  }
}

export async function runControlPlaneMigrations(
  client: SqlClient,
  options: RunControlPlaneMigrationsOptions = {}
): Promise<ControlPlaneMigrationResult> {
  const migrations = await listControlPlaneMigrations(options.migrationsDirectory);
  const applied: string[] = [];
  const skipped: string[] = [];
  const lockTimeoutMs = options.lockTimeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS;
  const appliedBy = options.appliedBy?.trim() === "" ? DEFAULT_APPLIED_BY : options.appliedBy ?? DEFAULT_APPLIED_BY;

  return withMigrationClient(client, async (executor) => {
    await advisoryLock(executor, lockTimeoutMs);
    try {
      await ensureMigrationTable(executor);
      for (const migration of migrations) {
        const existing = await existingMigration(executor, migration.filename);
        if (existing !== undefined) {
          if (existing.checksum_sha256 !== migration.checksumSha256) {
            throw new Error(`control-plane migration checksum mismatch for ${migration.filename}`);
          }
          skipped.push(migration.version);
          continue;
        }
        await applyMigration(executor, migration, appliedBy);
        applied.push(migration.version);
      }
    } finally {
      await advisoryUnlock(executor);
    }
    return { applied, skipped };
  });
}
