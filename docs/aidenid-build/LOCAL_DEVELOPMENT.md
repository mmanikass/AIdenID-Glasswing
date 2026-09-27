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

The launcher builds the nine-workspace tree, then starts the control plane at `http://127.0.0.1:4000` and the dashboard at `http://127.0.0.1:3000`. The dashboard status indicator polls its server health endpoint and shows whether the control plane is reachable.

The control plane uses in-memory grants, outbox, and an ephemeral decision-receipt key. The launcher binds both services to loopback and passes a minimal environment to them. No cloud account, database, Redis service, or production secret is needed. State resets when the launcher stops.

To choose different ports, set `AIDENID_DEV_CONTROL_PLANE_PORT` and `AIDENID_DEV_DASHBOARD_PORT` before running `pnpm dev`. For example:

```powershell
$env:AIDENID_DEV_CONTROL_PLANE_PORT = "4488"
$env:AIDENID_DEV_DASHBOARD_PORT = "3488"
pnpm dev
```

Verify both endpoints in another PowerShell window:

```powershell
Invoke-RestMethod http://127.0.0.1:4488/healthz
Invoke-RestMethod http://127.0.0.1:3488/api/status/health
```

The control plane returns `ok: true` when healthy; the dashboard endpoint returns `state: "connected"` when it reaches the control plane and `state: "unavailable"` otherwise. Press Ctrl+C in the launcher terminal to stop both service process trees.

This profile is for local development only. It disables dashboard login and uses ephemeral in-memory state, so do not expose these listeners to a network or use this configuration for deployment.
