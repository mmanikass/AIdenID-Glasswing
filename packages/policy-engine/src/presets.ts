import type { PolicyDocumentInput } from "./schema.js";

export type PolicyPresetName = "starter" | "strict_auth" | "content_site" | "marketplace";

export const POLICY_PRESETS: Readonly<Record<PolicyPresetName, PolicyDocumentInput>> = {
  starter: {
    version: 1,
    site_id: "sit_preset_starter",
    mode: "observe",
    defaults: {
      strict: false,
      on_degraded: "queue",
      sandbox_origin: "https://sandbox.aidenid.invalid",
      suspicion_threshold: 0.85,
      rate: { capacity: 120, refill_per_sec: 20, cost: 1 }
    },
    routes: [
      {
        template: "/**",
        method: "*",
        per_actor_class: {
          verified_agent: { decision: "allow" },
          likely_human: { decision: "allow" },
          suspicious_automation: { decision: "throttle", retry_after_s: 30 }
        }
      }
    ]
  },
  strict_auth: {
    version: 1,
    site_id: "sit_preset_strict_auth",
    mode: "enforce",
    defaults: {
      strict: true,
      on_degraded: "deny",
      sandbox_origin: "https://sandbox.aidenid.invalid",
      suspicion_threshold: 0.8,
      rate: { capacity: 60, refill_per_sec: 5, cost: 1 }
    },
    routes: [
      {
        template: "/checkout",
        method: "POST",
        signature_required: ["@method", "@authority", "@path", "content-digest"],
        per_actor_class: {
          verified_agent: { decision: "allow" },
          signed_agent: { decision: "queue", queue_retry_s: 30 },
          suspicious_automation: { decision: "deny" },
          unknown: { decision: "throttle", retry_after_s: 15 }
        }
      },
      {
        template: "/admin/**",
        method: "*",
        per_actor_class: {
          verified_agent: { decision: "allow" },
          signed_agent: { decision: "deny" },
          likely_human: { decision: "deny" },
          suspicious_automation: { decision: "deny" },
          unknown: { decision: "deny" }
        }
      }
    ]
  },
  content_site: {
    version: 1,
    site_id: "sit_preset_content",
    mode: "enforce",
    defaults: {
      strict: false,
      on_degraded: "queue",
      sandbox_origin: "https://sandbox.aidenid.invalid",
      suspicion_threshold: 0.9,
      rate: { capacity: 500, refill_per_sec: 50, cost: 1 }
    },
    routes: [
      {
        template: "/premium-content/*",
        method: "GET",
        per_actor_class: {
          verified_agent: { decision: "price_required", price_usd: 0.01 },
          signed_agent: { decision: "queue", queue_retry_s: 10 },
          likely_human: { decision: "allow" },
          unknown: { decision: "deny" }
        }
      },
      {
        template: "/comments/*",
        method: "POST",
        per_actor_class: {
          suspicious_automation: { decision: "sandbox", sandbox_origin: "https://sandbox.aidenid.invalid" },
          unknown: { decision: "queue", queue_retry_s: 20 }
        }
      }
    ]
  },
  marketplace: {
    version: 1,
    site_id: "sit_preset_marketplace",
    mode: "enforce",
    defaults: {
      strict: false,
      on_degraded: "queue",
      sandbox_origin: "https://sandbox.aidenid.invalid",
      suspicion_threshold: 0.85,
      rate: { capacity: 300, refill_per_sec: 25, cost: 1 }
    },
    routes: [
      {
        template: "/checkout",
        method: "POST",
        strict: true,
        route_bucket: "checkout",
        rate: { capacity: 100, refill_per_sec: 10, cost: 1 },
        per_actor_class: {
          verified_agent: { decision: "allow" },
          signed_agent: { decision: "queue", queue_retry_s: 15 },
          likely_human: { decision: "allow" },
          suspicious_automation: { decision: "deny" },
          unknown: { decision: "throttle", retry_after_s: 10 }
        }
      },
      {
        template: "/seller/:id/messages",
        method: "POST",
        per_actor_class: {
          suspicious_automation: { decision: "sandbox", sandbox_origin: "https://sandbox.aidenid.invalid" },
          unknown: { decision: "queue", queue_retry_s: 30 }
        }
      }
    ]
  }
} as const;

export function policyPreset(name: PolicyPresetName): PolicyDocumentInput {
  return structuredClone(POLICY_PRESETS[name]);
}
