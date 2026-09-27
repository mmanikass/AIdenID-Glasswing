import { suggestPolicyDiffs, type PolicyCopilotDecisionSample } from "@aidenid/policy-engine";

import {
  cascadeTelemetryFromBenchmarkArtifact,
  type CascadeLatencyBenchmarkArtifact,
  type DashboardCascadeTraceEntry,
  type CascadeTelemetrySummary,
  type DashboardDecisionEvent,
  type PersonaAuditIncident,
  type RouteMetric
} from "./dashboardModel.js";

const verifiedCascadeTrace: readonly DashboardCascadeTraceEntry[] = [
  { ordinal: 1, layer: "crypto_identity", status: "pass", reason: "http_signature_dpop_verified", latencyUs: 410, evidence: [] },
  { ordinal: 2, layer: "delegation_authorization", status: "pass", reason: "proof_bound_session_verified", latencyUs: 410, evidence: [] },
  { ordinal: 3, layer: "fingerprint_sidecar", status: "pass", reason: "fingerprint_provider_low_risk", latencyUs: 720, evidence: ["fingerprint:bot_score=0.04"] },
  { ordinal: 4, layer: "operator_reputation", status: "pass", reason: "operator_reputation_trusted", latencyUs: 640, evidence: ["operator:openai:score=92"] }
];

const signedNoDelegationCascadeTrace: readonly DashboardCascadeTraceEntry[] = [
  { ordinal: 1, layer: "crypto_identity", status: "pass", reason: "http_signature_verified", latencyUs: 380, evidence: [] },
  { ordinal: 2, layer: "delegation_authorization", status: "fail", reason: "delegation_proof_missing", latencyUs: 140, evidence: [] },
  { ordinal: 3, layer: "fingerprint_sidecar", status: "pass", reason: "fingerprint_provider_low_risk", latencyUs: 760, evidence: ["fingerprint:bot_score=0.19"] },
  { ordinal: 4, layer: "operator_reputation", status: "fail", reason: "operator_reputation_queue_required", latencyUs: 680, evidence: ["operator:anthropic:score=54"] }
];

const automationCascadeTrace: readonly DashboardCascadeTraceEntry[] = [
  { ordinal: 1, layer: "crypto_identity", status: "skipped", reason: "actor_class_not_signed_agent", latencyUs: 0, evidence: [] },
  { ordinal: 2, layer: "delegation_authorization", status: "skipped", reason: "depends_on_crypto_identity", latencyUs: 0, evidence: [] },
  { ordinal: 3, layer: "fingerprint_sidecar", status: "fail", reason: "fingerprint_provider_high_risk", latencyUs: 820, evidence: ["fingerprint:bot_score=0.94"] },
  { ordinal: 4, layer: "operator_reputation", status: "fail", reason: "operator_reputation_untrusted", latencyUs: 610, evidence: ["operator:unknown:score=18"] }
];

const humanCascadeTrace: readonly DashboardCascadeTraceEntry[] = [
  { ordinal: 1, layer: "crypto_identity", status: "skipped", reason: "actor_class_not_signed_agent", latencyUs: 0, evidence: [] },
  { ordinal: 2, layer: "delegation_authorization", status: "skipped", reason: "depends_on_crypto_identity", latencyUs: 0, evidence: [] },
  { ordinal: 3, layer: "fingerprint_sidecar", status: "pass", reason: "human_behavior_baseline", latencyUs: 690, evidence: ["fingerprint:bot_score=0.08"] },
  { ordinal: 4, layer: "operator_reputation", status: "skipped", reason: "no_llm_operator_claim", latencyUs: 0, evidence: [] }
];

const unknownCascadeTrace: readonly DashboardCascadeTraceEntry[] = [
  { ordinal: 1, layer: "crypto_identity", status: "skipped", reason: "actor_class_not_signed_agent", latencyUs: 0, evidence: [] },
  { ordinal: 2, layer: "delegation_authorization", status: "skipped", reason: "depends_on_crypto_identity", latencyUs: 0, evidence: [] },
  { ordinal: 3, layer: "fingerprint_sidecar", status: "pass", reason: "fingerprint_provider_neutral", latencyUs: 710, evidence: ["fingerprint:bot_score=0.46"] },
  { ordinal: 4, layer: "operator_reputation", status: "skipped", reason: "no_llm_operator_claim", latencyUs: 0, evidence: [] }
];

export const sampleDecisionEvents: readonly DashboardDecisionEvent[] = [
  {
    id: "dec_live_1",
    occurredAt: "2026-04-24T08:55:18.000Z",
    requestId: "req_931",
    siteId: "sit_demo",
    actorClass: "verified_agent",
    issuer: "https://api.aidenid.com",
    llmBrand: "openai",
    purpose: "research",
    decision: "allow",
    routeTemplate: "/dashboard/ai/assistant",
    method: "POST",
    latencyMs: 1.1,
    reasonCodes: ["aidenid_sdk_dogfood", "matched_policy"],
    cascadeTrace: verifiedCascadeTrace
  },
  {
    id: "dec_live_2",
    occurredAt: "2026-04-24T08:55:17.000Z",
    requestId: "req_930",
    siteId: "sit_demo",
    actorClass: "signed_agent",
    issuer: "https://crawler-market.example",
    llmBrand: "anthropic",
    decision: "queue",
    recommendedDecision: "queue",
    routeTemplate: "/checkout",
    method: "POST",
    latencyMs: 1.4,
    reasonCodes: ["matched_policy"],
    cascadeTrace: signedNoDelegationCascadeTrace
  },
  {
    id: "dec_live_3",
    occurredAt: "2026-04-24T08:55:16.000Z",
    requestId: "req_929",
    siteId: "sit_demo",
    actorClass: "suspicious_automation",
    decision: "allow",
    recommendedDecision: "sandbox",
    routeTemplate: "/comments/:id",
    method: "POST",
    latencyMs: 1.7,
    reasonCodes: ["sandbox_policy"],
    cascadeTrace: automationCascadeTrace
  },
  {
    id: "dec_live_4",
    occurredAt: "2026-04-24T08:55:15.000Z",
    requestId: "req_928",
    siteId: "sit_demo",
    actorClass: "unknown",
    decision: "allow",
    recommendedDecision: "throttle",
    routeTemplate: "/checkout",
    method: "POST",
    latencyMs: 1.3,
    reasonCodes: ["rate_limited"],
    cascadeTrace: unknownCascadeTrace
  },
  {
    id: "dec_live_5",
    occurredAt: "2026-04-24T08:55:14.000Z",
    requestId: "req_927",
    siteId: "sit_demo",
    actorClass: "verified_agent",
    issuer: "https://partner-broker.example",
    llmBrand: "openai",
    decision: "price_required",
    routeTemplate: "/premium-content/*",
    method: "GET",
    latencyMs: 1.0,
    priceUsd: 0.01,
    reasonCodes: ["price_required"],
    cascadeTrace: verifiedCascadeTrace
  },
  {
    id: "dec_live_6",
    occurredAt: "2026-04-24T08:55:13.000Z",
    requestId: "req_926",
    siteId: "sit_demo",
    actorClass: "verified_agent",
    issuer: "https://partner-broker.example",
    decision: "deny",
    routeTemplate: "/benefits/PHI/*",
    method: "GET",
    latencyMs: 1.2,
    reasonCodes: ["matched_policy", "operator_override", "quarantine"],
    cascadeTrace: verifiedCascadeTrace,
    operatorAction: "quarantine",
    operatorActionActorId: "ciso_demo",
    operatorActionReason: "manual quarantine during AHP review",
    operatorActionAt: "2026-04-24T08:55:13.500Z",
    operatorActionEffectiveDecision: "deny",
    operatorActionExpiresAt: "2026-04-24T09:55:13.500Z",
    operatorActionEffects: ["deny", "actor_pin", "ocsf_emit", "webhook_emit"]
  },
  {
    id: "dec_live_7",
    occurredAt: "2026-04-24T08:55:12.000Z",
    requestId: "req_925",
    siteId: "sit_demo",
    actorClass: "likely_human",
    decision: "allow",
    routeTemplate: "/health/profile",
    method: "GET",
    latencyMs: 1.6,
    reasonCodes: ["human_baseline"],
    cascadeTrace: humanCascadeTrace
  },
  {
    id: "dec_live_8",
    occurredAt: "2026-04-24T08:55:11.000Z",
    requestId: "req_924",
    siteId: "sit_demo",
    actorClass: "suspicious_automation",
    decision: "sandbox",
    routeTemplate: "/admin/login",
    method: "POST",
    latencyMs: 1.9,
    reasonCodes: ["fingerprint_high_risk"],
    cascadeTrace: automationCascadeTrace
  },
  {
    id: "dec_live_9",
    occurredAt: "2026-04-24T08:55:10.000Z",
    requestId: "req_923",
    siteId: "sit_demo",
    actorClass: "unknown",
    decision: "throttle",
    recommendedDecision: "throttle",
    routeTemplate: "/api/search",
    method: "GET",
    latencyMs: 1.5,
    reasonCodes: ["rate_limited"],
    cascadeTrace: unknownCascadeTrace
  }
];

export const samplePolicyYaml = `version: 1
site_id: sit_demo
mode: enforce
defaults:
  strict: false
  on_degraded: queue
  sandbox_origin: https://sandbox.example.com
  suspicion_threshold: 0.85
  rate: { capacity: 100, refill_per_sec: 10, cost: 1 }
routes:
  - template: /checkout
    method: POST
    strict: true
    per_actor_class:
      verified_agent: { decision: allow }
      signed_agent: { decision: queue, queue_retry_s: 30 }
      suspicious_automation: { decision: deny }
      unknown: { decision: throttle }
  - template: /premium-content/*
    method: GET
    per_actor_class:
      verified_agent: { decision: price_required, price_usd: 0.01 }
      unknown: { decision: deny }
`;

export const sampleRevocations = [
  { chainId: "chn_7e51", epoch: 3, reason: "user_revoked", updatedAt: "2026-04-24T08:50:00.000Z" },
  { chainId: "chn_8a22", epoch: 1, reason: "operator_block", updatedAt: "2026-04-24T08:42:00.000Z" }
] as const;

export const sampleUsage: readonly RouteMetric[] = [
  { routeTemplate: "/checkout", count: 328, p95LatencyMs: 1.8, denyRate: 0.04 },
  { routeTemplate: "/comments/:id", count: 144, p95LatencyMs: 1.6, denyRate: 0.02 },
  { routeTemplate: "/premium-content/*", count: 96, p95LatencyMs: 1.3, denyRate: 0.08 }
];

const sampleCascadeLatencyArtifact = {
  generatedAt: "2026-05-02T08:24:57.712Z",
  decisions: 1000,
  concurrency: 50,
  seed: 20260502,
  cascade: {
    mode: "all_layers_worst_case",
    shortCircuiting: false,
    layerOrder: ["web_bot_auth_verify", "delegation_lookup", "fingerprint_stub", "operator_reputation_lookup"]
  },
  profiles: [
    {
      name: "web_bot_auth_verify",
      timeoutMs: 50,
      description: "Cloudflare Web Bot Auth token verification and key-material cache hit path."
    },
    {
      name: "delegation_lookup",
      timeoutMs: 75,
      description: "Delegation and grant lookup from the control-plane cache/read replica profile."
    },
    {
      name: "fingerprint_stub",
      timeoutMs: 95,
      description: "Default-off fingerprint sidecar stub with vendor-like latency and bounded timeout."
    },
    {
      name: "operator_reputation_lookup",
      timeoutMs: 85,
      description: "Operator reputation directory lookup using an external-cache timing profile."
    }
  ],
  overall: {
    count: 1000,
    minMs: 86.941,
    avgMs: 120.725,
    p50Ms: 122.496,
    p95Ms: 154.777,
    p99Ms: 184.667,
    maxMs: 231.648
  },
  layers: {
    web_bot_auth_verify: {
      count: 1000,
      minMs: 9.254,
      avgMs: 16.355,
      p50Ms: 15.486,
      p95Ms: 24.917,
      p99Ms: 46.075,
      maxMs: 46.893
    },
    delegation_lookup: {
      count: 1000,
      minMs: 14.17,
      avgMs: 20.955,
      p50Ms: 15.592,
      p95Ms: 31.031,
      p99Ms: 61.464,
      maxMs: 76.424
    },
    fingerprint_stub: {
      count: 1000,
      minMs: 31.058,
      avgMs: 53.229,
      p50Ms: 46.575,
      p95Ms: 62.173,
      p99Ms: 107.7,
      maxMs: 108.654
    },
    operator_reputation_lookup: {
      count: 1000,
      minMs: 14.908,
      avgMs: 30.177,
      p50Ms: 30.728,
      p95Ms: 31.263,
      p99Ms: 77.078,
      maxMs: 93.043
    }
  }
} satisfies CascadeLatencyBenchmarkArtifact;

export const sampleCascadeTelemetry: CascadeTelemetrySummary = cascadeTelemetryFromBenchmarkArtifact(sampleCascadeLatencyArtifact);

export const samplePersonaAuditIncidents: readonly PersonaAuditIncident[] = [
  {
    id: "aud_revocation_1",
    triggerType: "revocation_epoch",
    status: "queued",
    severity: "high",
    tool: "create-sentinelayer",
    title: "Revocation root-cause audit queued",
    summary: "Revocation epoch 3 for chn_7e51 is queued for post-incident narrative review.",
    evidenceRefs: ["chain:chn_7e51", "revocation_epoch:3"],
    recommendedActions: ["review-delegation-chain", "summarize-revocation-reason", "verify-downstream-session-denials"],
    createdAt: "2026-04-24T08:50:00.000Z"
  },
  {
    id: "aud_suspicion_1",
    triggerType: "suspicion_threshold",
    status: "queued",
    severity: "medium",
    tool: "create-sentinelayer",
    title: "Suspicion spike audit queued",
    summary: "Suspicion score 0.91 breached the audit threshold for req_929.",
    evidenceRefs: ["decision_stream:sit_demo", "request:req_929"],
    recommendedActions: ["review-recent-route-decisions", "compare-actor-classification-evidence"],
    createdAt: "2026-04-24T08:55:16.000Z"
  }
];

const samplePolicyCopilotYaml = `version: 1
site_id: sit_demo
mode: enforce
defaults:
  strict: false
  on_degraded: queue
  rate: { capacity: 100, refill_per_sec: 10, cost: 1 }
routes:
  - template: /comments/:id
    method: POST
    per_actor_class:
      likely_human: { decision: allow }
`;

const samplePolicyCopilotDecisionSamples: readonly PolicyCopilotDecisionSample[] = [
  {
    routeTemplate: "/comments/:id",
    method: "POST",
    actorClass: "suspicious_automation",
    decision: "allow",
    reasonCodes: ["matched_policy"],
    occurredAt: "2026-04-24T08:55:16.000Z"
  },
  {
    routeTemplate: "/comments/:id",
    method: "POST",
    actorClass: "suspicious_automation",
    decision: "allow",
    reasonCodes: ["matched_policy"],
    occurredAt: "2026-04-24T08:55:15.000Z"
  }
];

export const samplePolicyCopilotSuggestions = suggestPolicyDiffs({
  policyYaml: samplePolicyCopilotYaml,
  decisionSamples: samplePolicyCopilotDecisionSamples,
  prompt: "dashboard offline sample policy copilot",
  inputRefs: ["dashboard:sample_decision_stream"],
  generatedAt: "2026-04-24T08:56:00.000Z",
  suspiciousAutomationThreshold: 2
});
