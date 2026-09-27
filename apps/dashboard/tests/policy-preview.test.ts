import { describe, expect, it } from "vitest";

import { POST as postPolicyPreview } from "../src/app/api/policy/preview/route.js";
import {
  buildPolicyPreviewProxyRequest,
  buildPolicyPreviewResponse,
  buildSideBySidePolicyDiff,
  samplePolicyYaml,
} from "../src/index.js";

const proposedPolicyYaml = samplePolicyYaml
  .replace("mode: enforce", "mode: observe")
  .replace("unknown: { decision: throttle }", "unknown: { decision: deny }");

function bearerHeader(value: string): string {
  return ["Bearer", value].join(" ");
}

async function withDashboardEnv<T>(
  updates: Readonly<Record<string, string | undefined>>,
  callback: () => Promise<T>,
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

function previewRequest(
  headers: Readonly<Record<string, string>> = {},
): Request {
  return new Request("https://dashboard.example.com/api/policy/preview", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify({
      current_policy_yaml: samplePolicyYaml,
      proposed_policy_yaml: proposedPolicyYaml,
      prompt: "preview draft",
    }),
  });
}

describe("dashboard policy diff preview", () => {
  it("builds a side-by-side diff without mutating policy text", () => {
    const diff = buildSideBySidePolicyDiff(
      samplePolicyYaml,
      proposedPolicyYaml,
    );

    expect(
      diff.some(
        (line) =>
          line.status === "removed" && line.current.includes("mode: enforce"),
      ),
    ).toBe(true);
    expect(
      diff.some(
        (line) =>
          line.status === "added" && line.proposed.includes("mode: observe"),
      ),
    ).toBe(true);
    expect(diff.every((line, index) => line.index === index + 1)).toBe(true);
  });

  it("builds a control-plane Policy Copilot preview proxy request with no apply path", () => {
    const proxy = buildPolicyPreviewProxyRequest({
      controlPlaneUrl: "https://control.example.com/",
      apiKey: "cp_key",
      proposedPolicyYaml,
      prompt: "preview draft",
      maxSuggestions: 3,
    });

    expect(proxy).toEqual(
      expect.objectContaining({
        url: "https://control.example.com/v1/policy-copilot/suggestions",
        headers: {
          "Content-Type": "application/json",
          Authorization: bearerHeader("cp_key"),
        },
      }),
    );
    const body = JSON.parse(proxy?.body ?? "{}") as Record<string, unknown>;
    expect(body).toMatchObject({
      policy_yaml: proposedPolicyYaml,
      prompt: "preview draft",
      max_suggestions: 3,
    });
    expect(body).not.toHaveProperty("apply_policy");
  });

  it("normalizes Policy Copilot metadata while forcing read-only preview semantics", () => {
    const preview = buildPolicyPreviewResponse({
      currentPolicyYaml: samplePolicyYaml,
      proposedPolicyYaml,
      copilotPayload: {
        apply_policy: true,
        suggestions: [
          {
            id: "pcs_preview",
            label: "ai_proposed",
            approval_status: "pending",
            risk_level: "low",
            rationale: "Preview only",
            output_diff: {
              format: "aidenid.policy.diff.v1",
              summary: "replace /mode",
              operations: [
                {
                  op: "replace",
                  path: "/mode",
                  before: "enforce",
                  after: "observe",
                },
              ],
            },
          },
        ],
      },
    });

    expect(preview.applyPolicy).toBe(false);
    expect(preview.changedLineCount).toBeGreaterThan(0);
    expect(preview.suggestions[0]).toMatchObject({
      id: "pcs_preview",
      approvalStatus: "pending",
      outputSummary: "replace /mode",
      operationCount: 1,
    });
  });

  it("requires inbound operator auth before proxying live Policy Copilot preview requests", async () => {
    let fetchCalled = false;
    const restoreFetch = replaceFetch(async () => {
      fetchCalled = true;
      return Response.json({});
    });
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: "https://control.example.com/",
          AIDENID_CONTROL_PLANE_API_KEY: "cp_key",
          AIDENID_OPERATOR_TOKEN: "upstream_control_plane_token_123456",
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: "operator_token_123456",
        },
        async () => postPolicyPreview(previewRequest()),
      );
      const body = (await response.json()) as Readonly<Record<string, unknown>>;

      expect(response.status).toBe(401);
      expect(body.error).toBe("operator_auth_required");
      expect(fetchCalled).toBe(false);
    } finally {
      restoreFetch();
    }
  });

  it("bounds live Policy Copilot preview fetches with AbortSignal timeouts", async () => {
    const calls: RequestInit[] = [];
    const restoreFetch = replaceFetch(
      async (_input: Parameters<typeof fetch>[0], init?: RequestInit) => {
        calls.push(init ?? {});
        throw new DOMException("aborted", "AbortError");
      },
    );
    try {
      const response = await withDashboardEnv(
        {
          AIDENID_CONTROL_PLANE_URL: "https://control.example.com/",
          AIDENID_CONTROL_PLANE_API_KEY: "cp_key",
          AIDENID_OPERATOR_TOKEN: "upstream_control_plane_token_123456",
          AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN: "operator_token_123456",
        },
        async () =>
          postPolicyPreview(
            previewRequest({
              Authorization: bearerHeader("operator_token_123456"),
            }),
          ),
      );

      expect(response.status).toBe(504);
      expect(calls[0]?.signal).toBeInstanceOf(AbortSignal);
      await expect(response.json()).resolves.toMatchObject({
        error: "policy_preview_unavailable",
        status: 504,
      });
    } finally {
      restoreFetch();
    }
  });
});
