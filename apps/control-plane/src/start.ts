import { controlPlaneDatabaseUrlFromEnvironment, createControlPlaneApp } from "./app.js";
import { runControlPlaneMigrations } from "./migrations.js";

function truthy(value: string | undefined): boolean {
  return /^(1|true|yes)$/i.test(value ?? "");
}

function migrationsEnabled(value: string | undefined): boolean {
  if (value === undefined || value.trim().length === 0) {
    return true;
  }
  return truthy(value);
}

function parsePort(value: string | undefined): number {
  const port = Number.parseInt(value ?? "3000", 10);
  if (!Number.isInteger(port) || port <= 0 || port > 65_535) {
    throw new Error("PORT must be a valid TCP port");
  }
  return port;
}

function parseOptionalPositiveInteger(value: string | undefined, name: string): number | undefined {
  if (value === undefined || value.trim().length === 0) {
    return undefined;
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

const host = process.env.HOST ?? "0.0.0.0";
const port = parsePort(process.env.PORT);

const databaseUrl = controlPlaneDatabaseUrlFromEnvironment(process.env);
if (databaseUrl !== undefined && migrationsEnabled(process.env.AIDENID_CONTROL_PLANE_RUN_MIGRATIONS)) {
  const { Pool } = await import("pg");
  const pool = new Pool({ connectionString: databaseUrl });
  try {
    const result = await runControlPlaneMigrations(pool);
    console.log(
      JSON.stringify({
        event: "control_plane_migrations_applied",
        applied_count: result.applied.length,
        skipped_count: result.skipped.length
      })
    );
  } finally {
    await pool.end();
  }
}

const app = await createControlPlaneApp({
  issuer: process.env.AIDENID_CONTROL_PLANE_ISSUER,
  sessionTtlSeconds: parseOptionalPositiveInteger(
    process.env.AIDENID_CONTROL_PLANE_SESSION_TTL_SECONDS,
    "AIDENID_CONTROL_PLANE_SESSION_TTL_SECONDS"
  )
});

const close = async (signal: NodeJS.Signals) => {
  app.log.info({ signal }, "shutting down AIdenID control plane");
  await app.close();
};

process.once("SIGINT", () => {
  void close("SIGINT").then(() => process.exit(0));
});
process.once("SIGTERM", () => {
  void close("SIGTERM").then(() => process.exit(0));
});

await app.listen({ host, port });
app.log.info({ host, port }, "AIdenID control plane listening");
