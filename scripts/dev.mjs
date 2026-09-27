import { execFileSync, spawn } from "node:child_process";
import { error, log } from "node:console";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

/**
 * Local demo launcher.
 *
 * Topology (loopback only, ephemeral state, restart resets the demo):
 *
 *   protected site  http://127.0.0.1:4100   Glasswing demo shop + operator API (/glasswing/*)
 *   control plane   http://127.0.0.1:4000   served BY the protected-site process (one store, one
 *                                            revocation epoch, one decision log)
 *   dashboard       http://127.0.0.1:3000   Next.js console; /glasswing is the operator UI
 *
 * Credentials are generated per run and handed to the child processes only. Two distinct
 * secrets exist on purpose: the operator token is what the dashboard SERVER presents to the
 * site and control plane, the dashboard request token is what a browser on loopback presents
 * to the dashboard. The dashboard fails closed if they are the same value.
 *
 * Until apps/protected-site is built (`pnpm build` produces apps/protected-site/dist/start.js),
 * the launcher falls back to the standalone control plane so the dashboard still runs.
 */

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const windows = process.platform === "win32";
const packageManagerScript = process.env.npm_execpath;
const children = new Set();

const LOOPBACK = "127.0.0.1";
const DEMO_SITE_ID = "sit_glasswing_demo";
const MINIMUM_SECRET_LENGTH = 32;

function safeHostEnvironment() {
  const environment = {};
  const allowed = [
    "PATH",
    "Path",
    "SYSTEMROOT",
    "SystemRoot",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "HOMEDRIVE",
    "HOMEPATH",
    "HOME",
    "COMSPEC",
    "PATHEXT",
  ];
  for (const key of allowed) {
    const value = process.env[key];
    if (value !== undefined) {
      environment[key] = value;
    }
  }
  return environment;
}

/** Model credentials for Jev. Forwarded to the protected-site process only, never to the dashboard. */
function jevEnvironment() {
  const environment = {};
  for (const key of ["ANTHROPIC_API_KEY", "JEV_MODEL"]) {
    const value = process.env[key];
    if (value !== undefined && value.trim().length > 0) {
      environment[key] = value;
    }
  }
  return environment;
}

/**
 * A fixed value may be supplied through the host environment so scripts can drive the
 * operator API with a known credential; otherwise a fresh secret is generated for this run.
 * Secrets are never printed.
 */
function devSecret(name) {
  const configured = process.env[name]?.trim();
  if (configured !== undefined && configured.length >= MINIMUM_SECRET_LENGTH) {
    return configured;
  }
  if (configured !== undefined && configured.length > 0) {
    error(`[dev] ${name} is shorter than ${MINIMUM_SECRET_LENGTH} characters; generating a random value instead.`);
  }
  return randomBytes(32).toString("base64url");
}

function pnpmProcess(args, env) {
  if (packageManagerScript) {
    return spawn(process.execPath, [packageManagerScript, ...args], {
      cwd: root,
      detached: !windows,
      env,
      stdio: "inherit",
    });
  }
  return spawn(windows ? "pnpm.cmd" : "pnpm", args, {
    cwd: root,
    detached: !windows,
    env,
    shell: windows,
    stdio: "inherit",
  });
}

function runPnpm(args, env) {
  return new Promise((resolve, reject) => {
    const child = pnpmProcess(args, env);
    // Tracked like the services so Ctrl+C during the build stops the build tree too.
    children.add(child);
    child.once("error", (failure) => {
      children.delete(child);
      reject(failure);
    });
    child.once("close", (code, signal) => {
      children.delete(child);
      if (signal !== null) {
        reject(new Error(`pnpm ${args.join(" ")} stopped by ${signal}`));
      } else if (code !== 0) {
        reject(new Error(`pnpm ${args.join(" ")} exited with ${code}`));
      } else {
        resolve();
      }
    });
  });
}

function validPort(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 && parsed <= 65_535
    ? parsed
    : fallback;
}

let stopping = false;
function stopChildTree(child) {
  if (windows && child.pid !== undefined) {
    try {
      execFileSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], {
        stdio: "ignore",
      });
      return;
    } catch {
      // Fall through to the portable signal path if taskkill is unavailable.
    }
  }
  if (!windows && child.pid !== undefined) {
    try {
      process.kill(-child.pid, "SIGTERM");
      return;
    } catch {
      // Fall through to the direct child signal if the process group is gone.
    }
  }
  child.kill("SIGTERM");
}

function stop(code = 0) {
  if (stopping) {
    return;
  }
  stopping = true;
  process.exitCode = code;
  for (const child of children) {
    stopChildTree(child);
  }
}

process.once("SIGINT", () => stop(0));
process.once("SIGTERM", () => stop(0));
process.once("exit", () => {
  for (const child of children) {
    stopChildTree(child);
  }
});

const hostEnvironment = safeHostEnvironment();
const buildEnvironment = { ...hostEnvironment };
const controlPlanePort = validPort(process.env.AIDENID_DEV_CONTROL_PLANE_PORT, 4000);
const protectedSitePort = validPort(process.env.AIDENID_DEV_PROTECTED_SITE_PORT, 4100);
const dashboardPort = validPort(process.env.AIDENID_DEV_DASHBOARD_PORT, 3000);
if (new Set([controlPlanePort, protectedSitePort, dashboardPort]).size !== 3) {
  error("[dev] AIDENID_DEV_CONTROL_PLANE_PORT, AIDENID_DEV_PROTECTED_SITE_PORT and AIDENID_DEV_DASHBOARD_PORT must be three different ports.");
  process.exitCode = 1;
  process.exit();
}

const operatorToken = devSecret("AIDENID_DEV_OPERATOR_TOKEN");
const dashboardRequestToken = devSecret("AIDENID_DEV_DASHBOARD_REQUEST_TOKEN");
if (operatorToken === dashboardRequestToken) {
  error("[dev] AIDENID_DEV_OPERATOR_TOKEN and AIDENID_DEV_DASHBOARD_REQUEST_TOKEN must be different secrets; the dashboard refuses a request credential that equals its upstream credential.");
  process.exitCode = 1;
  process.exit();
}

try {
  await runPnpm(["build"], buildEnvironment);
} catch (failure) {
  if (!stopping) {
    error(failure instanceof Error ? failure.message : "Local build failed.");
    process.exitCode = 1;
  }
  process.exit();
}
if (stopping) {
  // Interrupted during the build: do not start the services on the way out.
  process.exit();
}

const controlPlaneUrl = `http://${LOOPBACK}:${controlPlanePort}`;
const protectedSiteUrl = `http://${LOOPBACK}:${protectedSitePort}`;
const protectedSiteEntrypoint = path.join(root, "apps", "protected-site", "dist", "start.js");
const protectedSiteAvailable = existsSync(protectedSiteEntrypoint);

const ephemeralControlPlaneEnvironment = {
  NODE_ENV: "development",
  AIDENID_CONTROL_PLANE_RUN_MIGRATIONS: "false",
  AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE: "true",
  AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX: "true",
  AIDENID_ALLOW_EPHEMERAL_DECISION_RECEIPT_KEY: "true",
};

// Site mode: one process serves the demo shop on the site port and its embedded control plane
// on the control-plane port. The operator token is the credential the dashboard presents.
const protectedSiteEnvironment = {
  ...hostEnvironment,
  ...jevEnvironment(),
  ...ephemeralControlPlaneEnvironment,
  HOST: LOOPBACK,
  PORT: String(protectedSitePort),
  AIDENID_CONTROL_PLANE_PORT: String(controlPlanePort),
  GLASSWING_OPERATOR_TOKEN: operatorToken,
};

// Fallback: the standalone control plane with the same operator token registered, so the
// dashboard decision views work even before the protected site is built.
const controlPlaneEnvironment = {
  ...hostEnvironment,
  ...ephemeralControlPlaneEnvironment,
  HOST: LOOPBACK,
  PORT: String(controlPlanePort),
  AIDENID_CONTROL_PLANE_ISSUER: "https://aidenid.local",
  AIDENID_OPERATOR_TOKENS: JSON.stringify({
    glasswing_demo_operator: {
      token: operatorToken,
      roles: ["admin", "decision_operator", "decision_search"],
    },
  }),
};

const dashboardEnvironment = {
  ...hostEnvironment,
  NODE_ENV: "development",
  AIDENID_CONTROL_PLANE_URL: controlPlaneUrl,
  ...(protectedSiteAvailable ? { AIDENID_PROTECTED_SITE_URL: protectedSiteUrl } : {}),
  AIDENID_OPERATOR_TOKEN: operatorToken,
  AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: dashboardRequestToken,
  AIDENID_DASHBOARD_SITE_ID: DEMO_SITE_ID,
  AIDENID_DASHBOARD_REQUIRE_LIVE_DATA: "true",
  AIDENID_REQUIRE_LOGIN: "false",
  // Enables the loopback-only dev session route; only this launcher profile sets it.
  AIDENID_DASHBOARD_DEV_SESSION: "true",
  NEXT_TELEMETRY_DISABLED: "1",
};

function startNode(label, entrypoint, args, env, cwd) {
  const child = spawn(process.execPath, [entrypoint, ...args], {
    cwd,
    detached: !windows,
    env,
    stdio: "inherit",
  });
  children.add(child);
  child.once("error", (failure) => {
    error(`[dev] ${label} failed to start: ${failure.message}`);
    stop(1);
  });
  child.once("close", (code, signal) => {
    children.delete(child);
    if (!stopping) {
      error(`[dev] ${label} stopped (${signal ?? code ?? "unknown"}).`);
      stop(code === 0 ? 0 : 1);
    }
  });
  return child;
}

if (protectedSiteAvailable) {
  log(`[dev] Protected site: ${protectedSiteUrl}/healthz (site ${DEMO_SITE_ID})`);
  log(`[dev] Control plane: ${controlPlaneUrl}/healthz (served by the protected-site process)`);
} else {
  log("[dev] apps/protected-site is not built; starting the standalone control plane instead. The /glasswing console will report the operator API as unreachable.");
  log(`[dev] Control plane: ${controlPlaneUrl}/healthz`);
}
log(`[dev] Dashboard: http://${LOOPBACK}:${dashboardPort} (Glasswing console: http://${LOOPBACK}:${dashboardPort}/glasswing)`);
log("[dev] Operator credentials were generated for this run and passed to the services only; they are not printed.");
log("[dev] Using loopback listeners and ephemeral in-memory state; restart resets the demo.");

if (protectedSiteAvailable) {
  startNode(
    "protected site",
    protectedSiteEntrypoint,
    [],
    protectedSiteEnvironment,
    path.join(root, "apps", "protected-site"),
  );
} else {
  startNode(
    "control plane",
    path.join(root, "apps", "control-plane", "dist", "start.js"),
    [],
    controlPlaneEnvironment,
    path.join(root, "apps", "control-plane"),
  );
}
startNode(
  "dashboard",
  path.join(root, "apps", "dashboard", "node_modules", "next", "dist", "bin", "next"),
  [
    "dev",
    "--hostname",
    LOOPBACK,
    "--port",
    String(dashboardPort),
  ],
  dashboardEnvironment,
  path.join(root, "apps", "dashboard"),
);
