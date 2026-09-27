# Protected-site demo

This Fastify app runs the verifier in enforce mode in front of four sample routes. It creates a scoped in-process control plane, provisions one demo target and route-specific grants, and issues a DPoP-bound session for each exact resource URL. The route-specific grants match the verifier's exact resource check while keeping each permission narrow.

The demo routes are `GET /catalog`, `POST /items/demo-item/reserve`, `GET /customers/export` (denied for every actor class), and `GET /reports/bulk` (purpose allowlist plus mandatory Jev review). Decisions are synchronously recorded in the control plane before a request continues. Without an Anthropic credential or injected test provider, the mandatory Jev check remains unavailable and the reports request is queued.

Run with `pnpm --filter @aidenid/protected-site-demo start`. State, keys, grants, replay protection, and the decision stream are in memory for this local demo; this package is not a production deployment template.
