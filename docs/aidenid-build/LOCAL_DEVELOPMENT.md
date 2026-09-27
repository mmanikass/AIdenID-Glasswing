# Local development

## Requirements

- Node.js 22 or newer
- pnpm 10.28.0 (activate it with Corepack)

From the repository root:

```powershell
corepack enable
corepack prepare pnpm@10.28.0 --activate
pnpm install --frozen-lockfile
pnpm dev
```

## What `pnpm dev` starts

The launcher (`scripts/dev.mjs`) builds the workspace, then starts the demo on loopback:

| Listener | Address | Process |
| --- | --- | --- |
| Protected site (Glasswing demo shop + operator API under `/glasswing/*`) | `http://127.0.0.1:4100` | `apps/protected-site` |
| Control plane (grants, sessions, revocation, decisions, receipts) | `http://127.0.0.1:4000` | served by the protected-site process |
| Dashboard (operator console at `/glasswing`) | `http://127.0.0.1:3000` | `apps/dashboard` |

The control plane is served by the protected-site process on purpose. The site embeds the control-plane runtime so that the store, the revocation epoch and the decision log the dashboard reads are the same ones the site enforces against. Running a second, separate control plane would give the dashboard a different world from the site.

Everything is in memory: grants, sessions, the decision outbox and the decision-receipt key. Stopping the launcher resets the demo. The launcher passes a minimal environment to the child processes and binds every listener to `127.0.0.1`. No cloud account, database, Redis service or production secret is needed.

## Credentials

The launcher generates two secrets per run and hands them to the child processes only. They are never printed.

| Value | Site process | Dashboard process | Purpose |
| --- | --- | --- | --- |
| Operator token | `GLASSWING_OPERATOR_TOKEN` | `AIDENID_OPERATOR_TOKEN` | What the dashboard server presents to the site operator API and to the control plane. |
| Dashboard request token | not shared | `AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN` | What a browser on loopback presents to the dashboard. The dashboard issues it as a cookie to loopback callers when login is disabled. |

The two values are always different. The dashboard fails closed if its request token equals its upstream credential, so the launcher refuses to start with equal values.

To drive the operator API from a script with a known credential, set `AIDENID_DEV_OPERATOR_TOKEN` and `AIDENID_DEV_DASHBOARD_REQUEST_TOKEN` (at least 32 characters each, different from each other; the site refuses a shorter operator token) before running `pnpm dev`. Anything shorter is ignored and a random value is generated instead.

Jev, the semantic reviewer used for the ambiguous `/reports/bulk` request, needs a model credential. If `ANTHROPIC_API_KEY` (and optionally `JEV_MODEL`) is set in the shell that runs `pnpm dev`, the launcher forwards it to the protected-site process only. Without it the site still runs; Jev reports `unavailable` and the request queues for review instead of being cleared.

## Environment contract

Variables the launcher sets for each process. Keep these names in sync with `apps/protected-site/src/start.ts` and the dashboard route handlers.

Protected site:

- `HOST=127.0.0.1`, `PORT=4100`
- `AIDENID_CONTROL_PLANE_PORT=4000` (the embedded control plane listens here, loopback only)
- `GLASSWING_OPERATOR_TOKEN` (generated)
- `AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE=true`, `AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX=true`, `AIDENID_ALLOW_EPHEMERAL_DECISION_RECEIPT_KEY=true`, `AIDENID_CONTROL_PLANE_RUN_MIGRATIONS=false`
- `ANTHROPIC_API_KEY`, `JEV_MODEL` (forwarded only when present)

Dashboard:

- `AIDENID_CONTROL_PLANE_URL=http://127.0.0.1:4000`
- `AIDENID_PROTECTED_SITE_URL=http://127.0.0.1:4100`
- `AIDENID_OPERATOR_TOKEN` (generated, same value as the site's `GLASSWING_OPERATOR_TOKEN`)
- `AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN` (generated, distinct)
- `AIDENID_DASHBOARD_SITE_ID=sit_glasswing_demo`
- `AIDENID_DASHBOARD_REQUIRE_LIVE_DATA=true`, `AIDENID_REQUIRE_LOGIN=false`, `AIDENID_DASHBOARD_DEV_SESSION=true` (enables the loopback-only dev session route that hands the browser its request token as a cookie; only this launcher profile sets it), `NEXT_TELEMETRY_DISABLED=1`

## Ports

To choose different ports, set any of these before running `pnpm dev`. The three must differ.

```powershell
$env:AIDENID_DEV_CONTROL_PLANE_PORT = "4488"
$env:AIDENID_DEV_PROTECTED_SITE_PORT = "4588"
$env:AIDENID_DEV_DASHBOARD_PORT = "3488"
pnpm dev
```

## Verifying

In another PowerShell window:

```powershell
Invoke-RestMethod http://127.0.0.1:4100/healthz
Invoke-RestMethod http://127.0.0.1:4000/healthz
Invoke-RestMethod http://127.0.0.1:3000/api/status/health
```

The site returns `status: "ok"` with its `site_id`; the control plane returns `ok: true`; the dashboard endpoint returns `state: "connected"` when it reaches the control plane and `state: "unavailable"` otherwise. Then open `http://127.0.0.1:3000/glasswing` for the operator console. The demo click path is in `docs/runbook.md`.

Press Ctrl+C in the launcher terminal to stop the process trees.

## Before the protected site is built

If `apps/protected-site/dist/start.js` does not exist after the build, the launcher starts the standalone control plane (`apps/control-plane`) on the control-plane port with the generated operator token registered, and starts the dashboard without `AIDENID_PROTECTED_SITE_URL`. The dashboard decision views work; the `/glasswing` console reports the operator API as unreachable. The launcher says which mode it chose in its first log lines.

## Scope

This profile is for local development only. It disables dashboard login and uses ephemeral in-memory state, so do not expose these listeners to a network or use this configuration for deployment.
