import { describe, expect, it } from "vitest";

import { GET as getOperatorList } from "../src/app/api/operators/reputation/route.js";
import {
  GET as getOperatorDetail,
  PUT as putOperatorDetail
} from "../src/app/api/operators/reputation/[operatorActorId]/route.js";
import { POST as postIdentityChallengeReview } from "../src/app/api/identity-challenges/[submissionId]/review/route.js";
import {
  buildAgentIdentitySubmissionReviewUrl,
  buildAgentIdentitySubmissionListUrl,
  parseAgentIdentityReviewRequest,
  parseAgentIdentityReviewResponse,
  parseAgentIdentitySubmissionList
} from "../src/dashboardIdentityChallenges.js";
import {
  buildAgentIdentityReviewNotificationListUrl,
  buildAgentIdentityReviewNotificationReadUrl,
  parseAgentIdentityReviewNotificationList,
  parseAgentIdentityReviewNotificationResponse
} from "../src/dashboardIdentityReviewNotifications.js";
import {
  buildOperatorReputationDetailUrl,
  buildOperatorReputationListUrl,
  dashboardSiteId,
  isValidOperatorActorId,
  isValidSiteId,
  parseOperatorReputationUpsert
} from "../src/dashboardOperatorRegistry.js";
import {
  fetchAuthorizedOperatorRegistry,
  fetchOperatorRegistry,
  type OperatorRegistryServerEnvironment
} from "../src/operatorRegistryServer.js";
import {
  fetchAuthorizedIdentityChallengeSubmissions,
  fetchIdentityChallengeSubmissions
} from "../src/identityChallengeServer.js";
import {
  fetchAuthorizedIdentityReviewNotifications,
  fetchIdentityReviewNotifications
} from "../src/identityReviewNotificationServer.js";

const OPERATOR_TOKEN = "operator_token_123456";
// The credential the dashboard presents UPSTREAM must never be the one clients present to it.
const UPSTREAM_TOKEN = "upstream_control_plane_token_123456";
const CONTROL_PLANE = "https://control.example.com/";
const SITE_ID = "sit_demo";

function bearer(token: string): string {
  return `Bearer ${token}`;
}

async function withDashboardEnv<T>(
  updates: Readonly<Record<string, string | undefined>>,
  callback: () => Promise<T>
): Promise<T> {
  const previous = new Map<string, string | undefined>();
  for (const key of Object.keys(updates)) {
    previous.set(key, process.env[key]);
    const value = updates[key];
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  try {
    return await callback();
  } finally {
    for (const [key, value] of previous.entries()) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

function replaceFetch(implementation: typeof fetch): () => void {
  const previous = globalThis.fetch;
  globalThis.fetch = implementation;
  return () => {
    globalThis.fetch = previous;
  };
}

function listRequest(headers: Readonly<Record<string, string>> = {}): Request {
  return new Request("https://dashboard.example.com/api/operators/reputation", {
    method: "GET",
    headers
  });
}

function detailRequest(
  operatorActorId: string,
  init: RequestInit & { readonly headers?: Readonly<Record<string, string>> } = {}
): Request {
  return new Request(
    `https://dashboard.example.com/api/operators/reputation/${encodeURIComponent(operatorActorId)}`,
    init
  );
}

function detailContext(operatorActorId: string): {
  readonly params: Promise<{ readonly operatorActorId: string }>;
} {
  return { params: Promise.resolve({ operatorActorId }) };
}

function reviewRequest(
  submissionId: string,
  init: RequestInit & { readonly headers?: Readonly<Record<string, string>> } = {}
): Request {
  return new Request(
    `https://dashboard.example.com/api/identity-challenges/${encodeURIComponent(submissionId)}/review`,
    init
  );
}

function reviewContext(submissionId: string): {
  readonly params: Promise<{ readonly submissionId: string }>;
} {
  return { params: Promise.resolve({ submissionId }) };
}

const sampleOperator = {
  id: "opr_demo",
  site_id: SITE_ID,
  operator_actor_id: "operator:openai",
  display_name: "OpenAI",
  trust_tier: "trusted",
  status: "active",
  reputation_score: 92,
  default_action: "allow",
  default_scope_routes: [],
  notes: "Default seed.",
  expires_at: "2099-05-18T00:00:00.000Z",
  updated_by: "ops",
  created_at: "2026-04-01T00:00:00.000Z",
  updated_at: "2026-04-01T00:00:00.000Z"
};

const sampleIdentitySubmission = {
  id: "ais_demo",
  site_id: SITE_ID,
  request_id: "req_agent_1",
  purpose: "research",
  requested_access_duration_seconds: 3_600,
  requested_access_expires_at: "2026-05-18T01:00:00.000Z",
  purpose_rationale: "Design-partner research crawl.",
  provider_name: "Example Agent Lab",
  operator_actor_id: "operator:example-lab",
  contact_url: "https://example.com/security",
  jwks_url: "https://example.com/.well-known/aidenid-jwks.json",
  delegation_authority_jwk_thumbprint_sha256: "a".repeat(64),
  cascade_attestation: ["crypto_identity", "delegation_authorization", "fingerprint_sidecar", "operator_reputation"],
  status: "pending_review",
  submitted_at: "2026-05-18T00:00:00.000Z"
};

const reviewedIdentitySubmission = {
  ...sampleIdentitySubmission,
  status: "approved",
  reviewed_at: "2026-05-18T01:00:00.000Z",
  review_decision: "approve",
  reviewer_identity_hash_sha256: "b".repeat(64),
  review_reason: "security contact verified",
  approved_operator_actor_id: "operator:example-lab",
  operator_reputation_id: "opr_example_lab",
  assigned_trust_tier: "trusted",
  assigned_operator_status: "active",
  assigned_reputation_score: 90
};

const sampleIdentityReviewNotification = {
  id: "arn_demo",
  site_id: SITE_ID,
  submission_id: "ais_demo",
  review_decision: "approve",
  provider_name: "Example Agent Lab",
  operator_actor_id: "operator:example-lab",
  contact_url: "https://example.com/security",
  reviewer_identity_hash_sha256: "b".repeat(64),
  review_reason: "security contact verified",
  status: "unread",
  created_at: "2026-05-18T01:00:00.000Z"
};

describe("dashboardOperatorRegistry helpers", () => {
  it("dashboardSiteId defaults to sit_demo and respects override", () => {
    expect(dashboardSiteId({})).toBe("sit_demo");
    expect(
      dashboardSiteId({ AIDENID_DASHBOARD_SITE_ID: "sit_acme-prod" })
    ).toBe("sit_acme-prod");
    expect(dashboardSiteId({ AIDENID_DASHBOARD_SITE_ID: "   " })).toBe(
      "sit_demo"
    );
  });

  it("isValidSiteId enforces the sit_ prefix and charset", () => {
    expect(isValidSiteId("sit_demo")).toBe(true);
    expect(isValidSiteId("sit_acme-prod_42")).toBe(true);
    expect(isValidSiteId("acme")).toBe(false);
    expect(isValidSiteId("sit_")).toBe(false);
    expect(isValidSiteId("sit_bad space")).toBe(false);
  });

  it("isValidOperatorActorId rejects empty and too-long inputs", () => {
    expect(isValidOperatorActorId("operator:openai")).toBe(true);
    expect(isValidOperatorActorId("op_42")).toBe(true);
    expect(isValidOperatorActorId("")).toBe(false);
    expect(isValidOperatorActorId("bad whitespace")).toBe(false);
    expect(isValidOperatorActorId("a".repeat(129))).toBe(false);
  });

  it("buildOperatorReputationListUrl includes site_id and optional filters", () => {
    const basic = new URL(buildOperatorReputationListUrl(CONTROL_PLANE, SITE_ID));
    expect(basic.pathname).toBe("/v1/operators/reputation");
    expect(basic.searchParams.get("site_id")).toBe(SITE_ID);
    expect(basic.searchParams.get("status")).toBeNull();

    const filtered = new URL(
      buildOperatorReputationListUrl(CONTROL_PLANE, SITE_ID, {
        status: "watchlist",
        trustTier: "restricted",
        limit: 25
      })
    );
    expect(filtered.searchParams.get("status")).toBe("watchlist");
    expect(filtered.searchParams.get("trust_tier")).toBe("restricted");
    expect(filtered.searchParams.get("limit")).toBe("25");
  });

  it("buildOperatorReputationDetailUrl URL-encodes the actor id", () => {
    const url = new URL(
      buildOperatorReputationDetailUrl(CONTROL_PLANE, SITE_ID, "operator:openai")
    );
    expect(url.pathname).toBe("/v1/operators/reputation/operator%3Aopenai");
    expect(url.searchParams.get("site_id")).toBe(SITE_ID);
  });

  it("builds and parses pending identity challenge submission lists", () => {
    const url = new URL(
      buildAgentIdentitySubmissionListUrl(CONTROL_PLANE, SITE_ID, {
        status: "pending_review",
        limit: 25
      })
    );
    expect(url.pathname).toBe("/v1/identities/submissions");
    expect(url.searchParams.get("site_id")).toBe(SITE_ID);
    expect(url.searchParams.get("status")).toBe("pending_review");
    expect(url.searchParams.get("limit")).toBe("25");

    expect(parseAgentIdentitySubmissionList({ submissions: [sampleIdentitySubmission] })).toEqual([sampleIdentitySubmission]);
    expect(parseAgentIdentitySubmissionList({ submissions: [{ id: "bad" }] })).toEqual([]);
    expect(parseAgentIdentitySubmissionList({ unexpected: true })).toBeUndefined();
  });

  it("builds, validates, and parses identity challenge review requests", () => {
    const reviewUrl = new URL(buildAgentIdentitySubmissionReviewUrl(CONTROL_PLANE, "ais_demo"));
    expect(reviewUrl.pathname).toBe("/v1/identities/submissions/ais_demo/review");

    expect(parseAgentIdentityReviewRequest({ action: "reject" })).toEqual({
      ok: false,
      error: "invalid_review_reason"
    });
    expect(
      parseAgentIdentityReviewRequest({
        action: "approve",
        operator_actor_id: "bad whitespace",
        trust_tier: "trusted",
        operator_status: "active",
        reputation_score: 90
      })
    ).toEqual({ ok: false, error: "invalid_operator_actor_id" });
    expect(
      parseAgentIdentityReviewRequest({
        action: "approve",
        operator_actor_id: " operator:example-lab ",
        trust_tier: "trusted",
        operator_status: "watchlist",
        reputation_score: 76,
        default_action: "price_required",
        default_scope_routes: [" /docs ", "/pricing/*"],
        default_scope_redirect_path: "/agent-access",
        approval_expires_at: "2026-05-18T00:45:00.000Z",
        notes: " reviewer notes ",
        review_reason: " security contact verified "
      })
    ).toEqual({
      ok: true,
      payload: {
        action: "approve",
        operator_actor_id: "operator:example-lab",
        trust_tier: "trusted",
        operator_status: "watchlist",
        reputation_score: 76,
        default_action: "price_required",
        default_scope_routes: ["/docs", "/pricing/*"],
        default_scope_redirect_path: "/agent-access",
        approval_expires_at: "2026-05-18T00:45:00.000Z",
        notes: "reviewer notes",
        review_reason: "security contact verified"
      }
    });
    expect(parseAgentIdentityReviewResponse({ submission: reviewedIdentitySubmission })?.submission.status).toBe("approved");
    expect(parseAgentIdentityReviewResponse({ submission: { id: "bad" } })).toBeUndefined();
  });

  it("builds and parses identity review notification payloads", () => {
    const listUrl = new URL(
      buildAgentIdentityReviewNotificationListUrl(CONTROL_PLANE, SITE_ID, {
        status: "unread",
        limit: 25
      })
    );
    expect(listUrl.pathname).toBe("/v1/identities/review-notifications");
    expect(listUrl.searchParams.get("site_id")).toBe(SITE_ID);
    expect(listUrl.searchParams.get("status")).toBe("unread");
    expect(listUrl.searchParams.get("limit")).toBe("25");

    const readUrl = new URL(buildAgentIdentityReviewNotificationReadUrl(CONTROL_PLANE, "arn_demo"));
    expect(readUrl.pathname).toBe("/v1/identities/review-notifications/arn_demo");

    expect(parseAgentIdentityReviewNotificationList({ notifications: [sampleIdentityReviewNotification] })).toEqual([
      sampleIdentityReviewNotification
    ]);
    expect(parseAgentIdentityReviewNotificationList({ notifications: [{ id: "bad" }] })).toEqual([]);
    expect(parseAgentIdentityReviewNotificationList({ unexpected: true })).toBeUndefined();
    expect(parseAgentIdentityReviewNotificationResponse({ notification: sampleIdentityReviewNotification })?.id).toBe("arn_demo");
    expect(parseAgentIdentityReviewNotificationResponse({ notification: { id: "bad" } })).toBeUndefined();
  });

  it("parseOperatorReputationUpsert rejects missing or out-of-range fields", () => {
    expect(parseOperatorReputationUpsert(undefined, SITE_ID)).toEqual({
      ok: false,
      error: "missing_trust_tier"
    });
    expect(parseOperatorReputationUpsert({}, SITE_ID)).toEqual({
      ok: false,
      error: "missing_trust_tier"
    });
    expect(
      parseOperatorReputationUpsert({ trust_tier: "weird" }, SITE_ID)
    ).toEqual({ ok: false, error: "invalid_trust_tier" });
    expect(
      parseOperatorReputationUpsert(
        { trust_tier: "trusted" },
        SITE_ID
      )
    ).toEqual({ ok: false, error: "missing_status" });
    expect(
      parseOperatorReputationUpsert(
        { trust_tier: "trusted", status: "warmlist" },
        SITE_ID
      )
    ).toEqual({ ok: false, error: "invalid_status" });
    expect(
      parseOperatorReputationUpsert(
        { trust_tier: "trusted", status: "active", reputation_score: 200 },
        SITE_ID
      )
    ).toEqual({ ok: false, error: "invalid_reputation_score" });
    expect(
      parseOperatorReputationUpsert(
        { trust_tier: "trusted", status: "active", reputation_score: 50, default_action: "block" },
        SITE_ID
      )
    ).toEqual({ ok: false, error: "invalid_default_action" });
    expect(
      parseOperatorReputationUpsert(
        { trust_tier: "trusted", status: "active", reputation_score: 50, default_scope_routes: ["https://evil.example/"] },
        SITE_ID
      )
    ).toEqual({ ok: false, error: "invalid_default_scope_routes" });
    expect(
      parseOperatorReputationUpsert(
        { trust_tier: "trusted", status: "active", reputation_score: 50, notes: "" },
        SITE_ID
      )
    ).toEqual({ ok: false, error: "invalid_notes" });
    expect(
      parseOperatorReputationUpsert(
        {
          trust_tier: "trusted",
          status: "active",
          reputation_score: 50,
          last_reviewed_at: "not-a-date"
        },
        SITE_ID
      )
    ).toEqual({ ok: false, error: "invalid_last_reviewed_at" });
    expect(
      parseOperatorReputationUpsert(
        {
          trust_tier: "trusted",
          status: "active",
          reputation_score: 50,
          expires_at: "not-a-date"
        },
        SITE_ID
      )
    ).toEqual({ ok: false, error: "invalid_expires_at" });
  });

  it("parseOperatorReputationUpsert normalizes a valid payload and stamps the site_id", () => {
    const result = parseOperatorReputationUpsert(
      {
        trust_tier: "trusted",
        status: "active",
        reputation_score: 92,
        default_action: "queue",
        default_scope_routes: [" /docs ", "/pricing/*"],
        default_scope_redirect_path: "/agent-access",
        display_name: "  OpenAI  ",
        notes: " Allowed for production traffic ",
        last_reviewed_at: "2026-05-01T00:00:00.000Z",
        expires_at: "2026-05-18T00:45:00.000Z",
        site_id: "sit_someone_lied"
      },
      SITE_ID
    );
    expect(result).toEqual({
      ok: true,
      payload: {
        site_id: SITE_ID,
        trust_tier: "trusted",
        status: "active",
        reputation_score: 92,
        default_action: "queue",
        default_scope_routes: ["/docs", "/pricing/*"],
        default_scope_redirect_path: "/agent-access",
        display_name: "OpenAI",
        notes: "Allowed for production traffic",
        last_reviewed_at: "2026-05-01T00:00:00.000Z",
        expires_at: "2026-05-18T00:45:00.000Z"
      }
    });
  });
});

describe("operator registry BFF — list", () => {
  it("rejects requests without operator auth", async () => {
    let fetchCalled = false;
    const restore = replaceFetch(async () => {
      fetchCalled = true;
      return Response.json({});
    });
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: CONTROL_PLANE,
          AIDENID_OPERATOR_TOKEN: UPSTREAM_TOKEN,
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: OPERATOR_TOKEN
        },
        () => getOperatorList(listRequest())
      );
      expect(response.status).toBe(401);
      expect(fetchCalled).toBe(false);
    } finally {
      restore();
    }
  });

  it("returns 503 live_control_plane_required when control plane URL is missing", async () => {
    let fetchCalled = false;
    const restore = replaceFetch(async () => {
      fetchCalled = true;
      return Response.json({});
    });
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: undefined,
          AIDENID_OPERATOR_TOKEN: UPSTREAM_TOKEN,
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: OPERATOR_TOKEN
        },
        () =>
          getOperatorList(
            listRequest({ Authorization: bearer(OPERATOR_TOKEN) })
          )
      );
      expect(response.status).toBe(503);
      const body = (await response.json()) as Readonly<Record<string, unknown>>;
      expect(body.error).toBe("live_control_plane_required");
      expect(fetchCalled).toBe(false);
      expect(response.headers.get("X-AIdenID-Dashboard-Data-Source")).toBe(
        "live"
      );
    } finally {
      restore();
    }
  });

  it("forwards the upstream payload with live data-source header", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const restore = replaceFetch(async (input, init) => {
      calls.push({ url: typeof input === "string" ? input : input.toString(), init: init ?? {} });
      return Response.json({ operators: [sampleOperator] });
    });
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: CONTROL_PLANE,
          AIDENID_OPERATOR_TOKEN: UPSTREAM_TOKEN,
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: OPERATOR_TOKEN,
          AIDENID_DASHBOARD_SITE_ID: SITE_ID
        },
        () =>
          getOperatorList(
            listRequest({ Authorization: bearer(OPERATOR_TOKEN) })
          )
      );
      expect(response.status).toBe(200);
      expect(response.headers.get("X-AIdenID-Dashboard-Data-Source")).toBe(
        "live"
      );
      const body = (await response.json()) as { operators: unknown[] };
      expect(body.operators).toHaveLength(1);
      expect(calls).toHaveLength(1);
      const call = calls[0]!;
      expect(call.url).toContain("/v1/operators/reputation");
      expect(call.url).toContain(`site_id=${SITE_ID}`);
      const headers = new Headers(call.init.headers ?? {});
      expect(headers.get("authorization")).toBe(bearer(UPSTREAM_TOKEN));
    } finally {
      restore();
    }
  });
});

describe("operator registry BFF — detail PUT", () => {
  it("rejects requests without operator auth", async () => {
    let fetchCalled = false;
    const restore = replaceFetch(async () => {
      fetchCalled = true;
      return Response.json({});
    });
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: CONTROL_PLANE,
          AIDENID_OPERATOR_TOKEN: UPSTREAM_TOKEN,
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: OPERATOR_TOKEN
        },
        () =>
          putOperatorDetail(
            detailRequest("operator:openai", {
              method: "PUT",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({})
            }),
            detailContext("operator:openai")
          )
      );
      expect(response.status).toBe(401);
      expect(fetchCalled).toBe(false);
    } finally {
      restore();
    }
  });

  it("returns 400 when the body is not valid JSON", async () => {
    const restore = replaceFetch(async () => Response.json({}));
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: CONTROL_PLANE,
          AIDENID_OPERATOR_TOKEN: UPSTREAM_TOKEN,
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: OPERATOR_TOKEN,
          AIDENID_DASHBOARD_SITE_ID: SITE_ID
        },
        () =>
          putOperatorDetail(
            detailRequest("operator:openai", {
              method: "PUT",
              headers: {
                "Content-Type": "application/json",
                Authorization: bearer(OPERATOR_TOKEN)
              },
              body: "{not-json"
            }),
            detailContext("operator:openai")
          )
      );
      expect(response.status).toBe(400);
      const body = (await response.json()) as Readonly<Record<string, unknown>>;
      expect(body.error).toBe("invalid_operator_reputation_body");
    } finally {
      restore();
    }
  });

  it("returns the validation error from parseOperatorReputationUpsert when the body is invalid", async () => {
    let fetchCalled = false;
    const restore = replaceFetch(async () => {
      fetchCalled = true;
      return Response.json({});
    });
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: CONTROL_PLANE,
          AIDENID_OPERATOR_TOKEN: UPSTREAM_TOKEN,
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: OPERATOR_TOKEN,
          AIDENID_DASHBOARD_SITE_ID: SITE_ID
        },
        () =>
          putOperatorDetail(
            detailRequest("operator:openai", {
              method: "PUT",
              headers: {
                "Content-Type": "application/json",
                Authorization: bearer(OPERATOR_TOKEN)
              },
              body: JSON.stringify({
                trust_tier: "trusted",
                status: "active",
                reputation_score: 250
              })
            }),
            detailContext("operator:openai")
          )
      );
      expect(response.status).toBe(400);
      const body = (await response.json()) as Readonly<Record<string, unknown>>;
      expect(body.error).toBe("invalid_reputation_score");
      expect(fetchCalled).toBe(false);
    } finally {
      restore();
    }
  });

  it("forwards a valid PUT body with site_id stamped onto the upstream payload", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const restore = replaceFetch(async (input, init) => {
      calls.push({ url: typeof input === "string" ? input : input.toString(), init: init ?? {} });
      return Response.json({ operator: sampleOperator });
    });
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: CONTROL_PLANE,
          AIDENID_OPERATOR_TOKEN: UPSTREAM_TOKEN,
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: OPERATOR_TOKEN,
          AIDENID_DASHBOARD_SITE_ID: SITE_ID
        },
        () =>
          putOperatorDetail(
            detailRequest("operator:openai", {
              method: "PUT",
              headers: {
                "Content-Type": "application/json",
                Authorization: bearer(OPERATOR_TOKEN)
              },
              body: JSON.stringify({
                trust_tier: "trusted",
                status: "watchlist",
                reputation_score: 88,
                default_action: "throttle",
                default_scope_routes: ["/docs", "/pricing/*"],
                default_scope_redirect_path: "/agent-access",
                notes: "Heightened review for new SDK release.",
                expires_at: "2026-05-18T00:45:00.000Z"
              })
            }),
            detailContext("operator:openai")
          )
      );
      expect(response.status).toBe(200);
      const body = (await response.json()) as { operator: { operator_actor_id: string } };
      expect(body.operator.operator_actor_id).toBe("operator:openai");

      expect(calls).toHaveLength(1);
      const call = calls[0]!;
      expect(call.url).toContain(
        "/v1/operators/reputation/operator%3Aopenai"
      );
      expect(call.init.method).toBe("PUT");
      const headers = new Headers(call.init.headers ?? {});
      expect(headers.get("authorization")).toBe(bearer(UPSTREAM_TOKEN));
      const sentBody = JSON.parse(String(call.init.body)) as Readonly<
        Record<string, unknown>
      >;
      expect(sentBody).toMatchObject({
        site_id: SITE_ID,
        trust_tier: "trusted",
        status: "watchlist",
        reputation_score: 88,
        default_action: "throttle",
        default_scope_routes: ["/docs", "/pricing/*"],
        default_scope_redirect_path: "/agent-access",
        notes: "Heightened review for new SDK release.",
        expires_at: "2026-05-18T00:45:00.000Z"
      });
    } finally {
      restore();
    }
  });

  it("returns the GET detail proxy response with the live data-source header", async () => {
    const restore = replaceFetch(async () =>
      Response.json({ operator: sampleOperator })
    );
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: CONTROL_PLANE,
          AIDENID_OPERATOR_TOKEN: UPSTREAM_TOKEN,
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: OPERATOR_TOKEN,
          AIDENID_DASHBOARD_SITE_ID: SITE_ID
        },
        () =>
          getOperatorDetail(
            detailRequest("operator:openai", {
              method: "GET",
              headers: { Authorization: bearer(OPERATOR_TOKEN) }
            }),
            detailContext("operator:openai")
          )
      );
      expect(response.status).toBe(200);
      expect(response.headers.get("X-AIdenID-Dashboard-Data-Source")).toBe(
        "live"
      );
    } finally {
      restore();
    }
  });
});

describe("identity challenge review BFF", () => {
  it("rejects review requests without dashboard operator auth", async () => {
    let fetchCalled = false;
    const restore = replaceFetch(async () => {
      fetchCalled = true;
      return Response.json({});
    });
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: CONTROL_PLANE,
          AIDENID_OPERATOR_TOKEN: UPSTREAM_TOKEN,
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: OPERATOR_TOKEN
        },
        () =>
          postIdentityChallengeReview(
            reviewRequest("ais_demo", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ action: "approve" })
            }),
            reviewContext("ais_demo")
          )
      );
      expect(response.status).toBe(401);
      expect(fetchCalled).toBe(false);
    } finally {
      restore();
    }
  });

  it("validates review payloads before proxying to the control plane", async () => {
    let fetchCalled = false;
    const restore = replaceFetch(async () => {
      fetchCalled = true;
      return Response.json({});
    });
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: CONTROL_PLANE,
          AIDENID_OPERATOR_TOKEN: UPSTREAM_TOKEN,
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: OPERATOR_TOKEN
        },
        () =>
          postIdentityChallengeReview(
            reviewRequest("ais_demo", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: bearer(OPERATOR_TOKEN)
              },
              body: JSON.stringify({ action: "reject" })
            }),
            reviewContext("ais_demo")
          )
      );
      expect(response.status).toBe(400);
      const body = (await response.json()) as Readonly<Record<string, unknown>>;
      expect(body.error).toBe("invalid_review_reason");
      expect(fetchCalled).toBe(false);
    } finally {
      restore();
    }
  });

  it("forwards a valid review request with the server-side operator token", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const restore = replaceFetch(async (input, init) => {
      calls.push({ url: typeof input === "string" ? input : input.toString(), init: init ?? {} });
      return Response.json({ submission: reviewedIdentitySubmission, operator: sampleOperator });
    });
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: CONTROL_PLANE,
          AIDENID_OPERATOR_TOKEN: UPSTREAM_TOKEN,
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: OPERATOR_TOKEN
        },
        () =>
          postIdentityChallengeReview(
            reviewRequest("ais_demo", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: bearer(OPERATOR_TOKEN)
              },
              body: JSON.stringify({
                action: "approve",
                operator_actor_id: "operator:example-lab",
                trust_tier: "trusted",
                operator_status: "active",
                reputation_score: 90,
                default_action: "sandbox",
                default_scope_routes: ["/research/*"],
                default_scope_redirect_path: "/agent-access",
                approval_expires_at: "2026-05-18T00:45:00.000Z",
                review_reason: "security contact verified"
              })
            }),
            reviewContext("ais_demo")
          )
      );
      expect(response.status).toBe(200);
      expect(response.headers.get("X-AIdenID-Dashboard-Data-Source")).toBe("live");
      expect(calls).toHaveLength(1);
      const call = calls[0]!;
      expect(call.url).toBe(`${CONTROL_PLANE}v1/identities/submissions/ais_demo/review`);
      expect(call.init.method).toBe("PATCH");
      const headers = new Headers(call.init.headers ?? {});
      expect(headers.get("authorization")).toBe(bearer(UPSTREAM_TOKEN));
      expect(headers.get("x-aidenid-reviewer-id")).toBe("dashboard_operator");
      expect(JSON.parse(String(call.init.body))).toMatchObject({
        action: "approve",
        operator_actor_id: "operator:example-lab",
        trust_tier: "trusted",
        operator_status: "active",
        reputation_score: 90,
        default_action: "sandbox",
        default_scope_routes: ["/research/*"],
        default_scope_redirect_path: "/agent-access",
        approval_expires_at: "2026-05-18T00:45:00.000Z",
        review_reason: "security contact verified"
      });
    } finally {
      restore();
    }
  });
});

describe("fetchOperatorRegistry server helper", () => {
  function baseEnv(
    overrides: Readonly<Record<string, string | undefined>> = {}
  ): OperatorRegistryServerEnvironment {
    return {
      AIDENID_CONTROL_PLANE_URL: CONTROL_PLANE,
      AIDENID_OPERATOR_TOKEN: UPSTREAM_TOKEN,
      AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: OPERATOR_TOKEN,
      AIDENID_DASHBOARD_SITE_ID: SITE_ID,
      ...overrides
    };
  }

  it("reports control_plane_unconfigured when the URL is unset", async () => {
    const outcome = await fetchOperatorRegistry(
      baseEnv({ AIDENID_CONTROL_PLANE_URL: undefined }),
      { fetchImpl: async () => new Response("never called", { status: 500 }) }
    );
    expect(outcome.status).toBe("control_plane_unconfigured");
  });

  it("reports operator_token_missing when the token is unset", async () => {
    const outcome = await fetchOperatorRegistry(
      baseEnv({ AIDENID_OPERATOR_TOKEN: undefined }),
      { fetchImpl: async () => new Response("never called", { status: 500 }) }
    );
    expect(outcome.status).toBe("operator_token_missing");
  });

  it("returns the operators when the upstream responds 200 with a valid shape", async () => {
    const outcome = await fetchOperatorRegistry(baseEnv(), {
      fetchImpl: async () =>
        new Response(JSON.stringify({ operators: [sampleOperator] }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        })
    });
    expect(outcome.status).toBe("live");
    if (outcome.status === "live") {
      expect(outcome.operators).toHaveLength(1);
      expect(outcome.operators[0]!.operator_actor_id).toBe("operator:openai");
    }
  });

  it("returns fetch_failed when the upstream responds non-200", async () => {
    const outcome = await fetchOperatorRegistry(baseEnv(), {
      fetchImpl: async () => new Response("nope", { status: 502 })
    });
    expect(outcome.status).toBe("fetch_failed");
    if (outcome.status === "fetch_failed") {
      expect(outcome.httpStatus).toBe(502);
    }
  });

  it("returns fetch_failed when the upstream payload shape is unexpected", async () => {
    const outcome = await fetchOperatorRegistry(baseEnv(), {
      fetchImpl: async () =>
        new Response(JSON.stringify({ unexpected: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        })
    });
    expect(outcome.status).toBe("fetch_failed");
  });

  it("does not fetch live operator registry data until dashboard operator auth passes", async () => {
    let fetchCalled = false;
    const outcome = await fetchAuthorizedOperatorRegistry(
      new Headers(),
      baseEnv(),
      {
        fetchImpl: async () => {
          fetchCalled = true;
          return Response.json({ operators: [sampleOperator] });
        }
      }
    );

    expect(outcome.status).toBe("operator_auth_required");
    expect(fetchCalled).toBe(false);
  });

  it("fetches live operator registry data after cookie-based dashboard operator auth", async () => {
    const outcome = await fetchAuthorizedOperatorRegistry(
      new Headers({ cookie: `aidenid_operator_token=${encodeURIComponent(OPERATOR_TOKEN)}` }),
      baseEnv(),
      {
        fetchImpl: async () =>
          Response.json({ operators: [sampleOperator] })
      }
    );

    expect(outcome.status).toBe("live");
    if (outcome.status === "live") {
      expect(outcome.operators).toHaveLength(1);
      expect(outcome.operators[0]!.operator_actor_id).toBe("operator:openai");
    }
  });
});

describe("fetchIdentityChallengeSubmissions server helper", () => {
  function baseEnv(
    overrides: Readonly<Record<string, string | undefined>> = {}
  ): OperatorRegistryServerEnvironment {
    return {
      AIDENID_CONTROL_PLANE_URL: CONTROL_PLANE,
      AIDENID_OPERATOR_TOKEN: UPSTREAM_TOKEN,
      AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: OPERATOR_TOKEN,
      AIDENID_DASHBOARD_SITE_ID: SITE_ID,
      ...overrides
    };
  }

  it("returns pending identity challenge submissions with operator auth", async () => {
    const outcome = await fetchIdentityChallengeSubmissions(baseEnv(), {
      fetchImpl: async (input, init) => {
        expect(String(input)).toContain("/v1/identities/submissions");
        expect(String(input)).toContain("status=pending_review");
        const headers = new Headers(init?.headers);
        expect(headers.get("authorization")).toBe(bearer(UPSTREAM_TOKEN));
        return Response.json({ submissions: [sampleIdentitySubmission] });
      }
    });
    expect(outcome.status).toBe("live");
    if (outcome.status === "live") {
      expect(outcome.submissions[0]?.provider_name).toBe("Example Agent Lab");
    }
  });

  it("does not fetch identity challenges until dashboard operator auth passes", async () => {
    let fetchCalled = false;
    const outcome = await fetchAuthorizedIdentityChallengeSubmissions(
      new Headers(),
      baseEnv(),
      {
        fetchImpl: async () => {
          fetchCalled = true;
          return Response.json({ submissions: [sampleIdentitySubmission] });
        }
      }
    );

    expect(outcome.status).toBe("operator_auth_required");
    expect(fetchCalled).toBe(false);
  });
});

describe("fetchIdentityReviewNotifications server helper", () => {
  function baseEnv(
    overrides: Readonly<Record<string, string | undefined>> = {}
  ): OperatorRegistryServerEnvironment {
    return {
      AIDENID_CONTROL_PLANE_URL: CONTROL_PLANE,
      AIDENID_OPERATOR_TOKEN: UPSTREAM_TOKEN,
      AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: OPERATOR_TOKEN,
      AIDENID_DASHBOARD_SITE_ID: SITE_ID,
      ...overrides
    };
  }

  it("returns unread review notifications with operator auth", async () => {
    const outcome = await fetchIdentityReviewNotifications(baseEnv(), {
      fetchImpl: async (input, init) => {
        expect(String(input)).toContain("/v1/identities/review-notifications");
        expect(String(input)).toContain("status=unread");
        const headers = new Headers(init?.headers);
        expect(headers.get("authorization")).toBe(bearer(UPSTREAM_TOKEN));
        return Response.json({ notifications: [sampleIdentityReviewNotification] });
      }
    });
    expect(outcome.status).toBe("live");
    if (outcome.status === "live") {
      expect(outcome.notifications[0]?.submission_id).toBe("ais_demo");
    }
  });

  it("does not fetch review notifications until dashboard operator auth passes", async () => {
    let fetchCalled = false;
    const outcome = await fetchAuthorizedIdentityReviewNotifications(
      new Headers(),
      baseEnv(),
      {
        fetchImpl: async () => {
          fetchCalled = true;
          return Response.json({ notifications: [sampleIdentityReviewNotification] });
        }
      }
    );

    expect(outcome.status).toBe("operator_auth_required");
    expect(fetchCalled).toBe(false);
  });
});
