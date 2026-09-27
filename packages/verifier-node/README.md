# @aidenid/verifier-node

Node.js verifier middleware for the AIdenID Clearance Layer.

## Install From The CI SDK Bundle

The SDK is not currently advertised as a public npm registry package. CI publishes a tarball bundle named `aidenid-verifier-node-sdk-<source_sha>` that includes the verifier with its AIdenID runtime workspace dependencies bundled inside the verifier tarball.

After downloading and extracting that CI artifact, install the complete bundle from the artifact directory:

```sh
pnpm add ./aidenid-verifier-node-0.0.0.tgz
```

The artifact includes `aidenid-verifier-node-sdk-manifest.json` and `aidenid-verifier-node-sdk.SHA256SUMS`; verify them with:

```sh
node verify-verifier-sdk-pack.mjs aidenid-verifier-node-sdk-manifest.json
```

## Omar Gate CI

Verifier adopters can gate their own pull requests with the reusable AIdenID Omar Gate workflow:

```yaml
jobs:
  aidenid-verifier-gate:
    uses: mrrCarter/aidenid-clearance/.github/workflows/aidenid-verifier-gate.yml@v0
    secrets: inherit
```

Required caller repository settings:

- `SENTINELAYER_TOKEN` secret.
- `OPENAI_API_KEY` secret.
- `SENTINELAYER_SPEC_ID` variable, or pass `with.sentinelayer_spec_id`.

The packaged starter workflow is `templates/github/aidenid-omar-gate.yml`. It runs on pull requests, calls the reusable workflow, uses `scan_mode: deep`, and blocks on P0/P1 findings.

The reusable workflow uses Sentinelayer's BYO OpenAI path, so LLM provider values stay in repository secrets rather than literal pull-request workflow YAML.

The SDK also exports `renderAidenIdVerifierGateJob()` for generators that want to render the job block without copying YAML by hand.

## Distributed Rate Limits

Production verifier middleware should use a shared token bucket store so horizontal replicas enforce one tenant/route bucket instead of per-process buckets. The policy engine exports a Redis Lua-backed store that accepts a narrow script runner adapter:

```ts
import { RedisTokenBucketStore } from "@aidenid/policy-engine";
import { aidenidVerifier } from "@aidenid/verifier-node";

app.use(
  aidenidVerifier({
    siteId: "sit_live",
    apiKey: process.env.AIDENID_API_KEY ?? "",
    policy: {
      trie: policyBundle.trie,
      asyncTokenBucketStore: new RedisTokenBucketStore(redisScriptRunner)
    }
  })
);
```

`MemoryTokenBucketStore` remains available for tests and single-process local development.

For production, pass the shared Redis script runner once at the top level. The verifier will then use Redis for both strict-route token buckets and DPoP/HTTP-signature replay protection on `evaluateRequestAsync()` / `evaluateAndEmit()`:

```ts
app.use(
  aidenidVerifier({
    siteId: "sit_live",
    apiKey: process.env.AIDENID_API_KEY ?? "",
    redis: {
      scriptRunner: redisScriptRunner
    },
    crypto: verifierCryptoBundle,
    policy: {
      trie: policyBundle.trie
    }
  })
);
```

Set `AIDENID_REQUIRE_DISTRIBUTED_STORES=true` in multi-pod deployments to fail startup if Redis-backed replay and rate-limit stores are not configured.

## Provider Metrics

`evaluateAndEmit()` can record decision counters and optional cascade provider metrics through `InMemoryVerifierMetricsSink`. Fingerprint and operator reputation providers stay default-off; when a site injects them, set a stable `providerId` so timeout/error/pass metrics remain low cardinality.

```ts
import { InMemoryVerifierMetricsSink, evaluateAndEmit } from "@aidenid/verifier-node";

const metrics = new InMemoryVerifierMetricsSink();

await evaluateAndEmit(request, {
  siteId: "sit_live",
  apiKey: process.env.AIDENID_API_KEY ?? "",
  metrics,
  fingerprint: {
    providerId: "datadome",
    provider: datadomeFingerprintProvider
  },
  operatorReputation: {
    providerId: "aidenid-reputation-cache",
    provider: reputationCacheProvider
  }
});

metrics.renderPrometheus();
```

The Prometheus output includes:

- `aidenid_decision_total{site_id,action,actor_class,mode,route_template}`
- `aidenid_provider_layer_total{site_id,layer,provider,status,reason,route_template}`
- `aidenid_operator_scope_mismatch_total{site_id,actor_class,mode,route_template}`
- `aidenid_sandbox_route_total{site_id,actor_class,mode,route_template}`
- matching `_latency_us_sum` and `_latency_us_p95` series for both decision and provider layers

Provider recipe examples live in `docs/integrations/provider-observability-recipes.md`.

For L4 operator reputation, prefer `createCachedOperatorReputationProvider()`
from `@aidenid/operator-reputation`. Hydrate it from Ed25519-signed
control-plane snapshots at startup/background refresh time, then pass the
provider into verifier options. Request-time reputation lookup remains
in-memory and database-free; failed snapshot refreshes should keep the last
verified cache and alert on staleness rather than replacing it with unverified
data.

Cache records may carry `defaultAction`, `defaultScopeRoutes`, and
`defaultScopeRedirectPath`. Verifier-node applies those fields only after the
provider has returned a validated in-memory result: suspended operators still
deny first, default actions reuse the existing six decision outcomes, and
non-empty scope routes deny with `operator_scope_mismatch` when neither the
request path nor route template matches the bounded exact/trailing-`/*` scope.
The optional redirect path must be a local path beginning with `/`, never an
absolute or cross-origin URL. Do not fetch these fields from the control plane
inside a request handler.

## Agent Identity Challenge

Denied `unknown` / `suspicious_automation` requests, and purpose-denied agent
requests, include an `identity_challenge` object. The challenge asks the actor
to declare a structured purpose, requested access duration, provider name,
contact URL, optional operator actor ID, and the four Clearance cascade layers
before the control plane accepts a bounded `POST /v1/identities` submission for
operator review. Submissions do
not auto-allow traffic; operators still promote or restrict providers through
the Operator Registry.
