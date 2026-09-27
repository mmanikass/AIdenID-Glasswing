import { execFileSync, spawn } from "node:child_process";
import { error, log } from "node:console";
import path from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const windows = process.platform === "win32";
const packageManagerScript = process.env.npm_execpath;
const children = new Set();

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
    child.once("error", reject);
    child.once("close", (code, signal) => {
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
const dashboardPort = validPort(process.env.AIDENID_DEV_DASHBOARD_PORT, 3000);

try {
  await runPnpm(["build"], buildEnvironment);
} catch (failure) {
  error(failure instanceof Error ? failure.message : "Local build failed.");
  process.exitCode = 1;
  process.exit();
}

const controlPlaneEnvironment = {
  ...hostEnvironment,
  NODE_ENV: "development",
  HOST: "127.0.0.1",
  PORT: String(controlPlanePort),
  AIDENID_CONTROL_PLANE_ISSUER: "https://aidenid.local",
  AIDENID_CONTROL_PLANE_RUN_MIGRATIONS: "false",
  AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE: "true",
  AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX: "true",
  AIDENID_ALLOW_EPHEMERAL_DECISION_RECEIPT_KEY: "true",
};
const dashboardEnvironment = {
  ...hostEnvironment,
  NODE_ENV: "development",
  AIDENID_CONTROL_PLANE_URL: `http://127.0.0.1:${controlPlanePort}`,
  AIDENID_DASHBOARD_REQUIRE_LIVE_DATA: "true",
  AIDENID_REQUIRE_LOGIN: "false",
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

log(`[dev] Control plane: http://127.0.0.1:${controlPlanePort}/healthz`);
log(`[dev] Dashboard: http://127.0.0.1:${dashboardPort}`);
log("[dev] Using loopback listeners and ephemeral in-memory state; restart resets the demo.");

startNode(
  "control plane",
  path.join(root, "apps", "control-plane", "dist", "start.js"),
  [],
  controlPlaneEnvironment,
  path.join(root, "apps", "control-plane"),
);
startNode(
  "dashboard",
  path.join(root, "apps", "dashboard", "node_modules", "next", "dist", "bin", "next"),
  [
    "dev",
    "--hostname",
    "127.0.0.1",
    "--port",
    String(dashboardPort),
  ],
  dashboardEnvironment,
  path.join(root, "apps", "dashboard"),
);
