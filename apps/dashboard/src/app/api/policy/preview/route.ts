import {
  ACTOR_CLASSES,
  DECISION_ACTIONS,
  suggestPolicyDiffs,
  type ActorClass,
  type DecisionAction,
} from "@aidenid/policy-engine";

import {
  authorizeDashboardOperatorRequest,
  dashboardControlPlaneTimeoutMs,
  dashboardUpstreamStatusForError,
  fetchDashboardControlPlaneWithTimeout,
  operatorAuthFailureResponse,
} from "../../../../dashboardApi.js";
import {
  buildPolicyPreviewProxyRequest,
  buildPolicyPreviewResponse,
  type PolicyPreviewDecisionSample,
} from "../../../../policyPreview.js";

export const dynamic = "force-dynamic";

function recordFromUnknown(
  value: unknown,
): Readonly<Record<string, unknown>> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Readonly<Record<string, unknown>>)
    : undefined;
}

function stringField(
  source: Readonly<Record<string, unknown>>,
  key: string,
): string | undefined {
  const value = source[key];
  return typeof value === "string" && value.trim().length > 0
    ? value
    : undefined;
}

function decisionSamplesFromUnknown(
  value: unknown,
): readonly PolicyPreviewDecisionSample[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.flatMap((sample): PolicyPreviewDecisionSample[] => {
    const source = recordFromUnknown(sample);
    if (source === undefined) {
      return [];
    }
    const routeTemplate =
      typeof source?.route_template === "string"
        ? source.route_template
        : undefined;
    const method =
      typeof source?.method === "string" ? source.method : undefined;
    const actorClass =
      typeof source?.actor_class === "string" ? source.actor_class : undefined;
    const decision =
      typeof source?.decision === "string" ? source.decision : undefined;
    if (
      routeTemplate === undefined ||
      method === undefined ||
      actorClass === undefined ||
      decision === undefined ||
      !ACTOR_CLASSES.includes(actorClass as ActorClass) ||
      !DECISION_ACTIONS.includes(decision as DecisionAction)
    ) {
      return [];
    }
    return [
      {
        route_template: routeTemplate,
        method,
        actor_class: actorClass,
        decision,
        ...(Array.isArray(source.reason_codes)
          ? {
              reason_codes: source.reason_codes.filter(
                (reason): reason is string => typeof reason === "string",
              ),
            }
          : {}),
        ...(typeof source.occurred_at === "string"
          ? { occurred_at: source.occurred_at }
          : {}),
      },
    ];
  });
}

function localCopilotPayload(
  proposedPolicyYaml: string,
  prompt: string | undefined,
  decisionSamples: readonly PolicyPreviewDecisionSample[],
): unknown {
  return {
    apply_policy: false,
    suggestions: suggestPolicyDiffs({
      policyYaml: proposedPolicyYaml,
      prompt,
      inputRefs: ["dashboard:policy-preview:local"],
      maxSuggestions: 5,
      decisionSamples: decisionSamples.map((sample) => ({
        routeTemplate: sample.route_template,
        method: sample.method,
        actorClass: sample.actor_class as ActorClass,
        decision: sample.decision as DecisionAction,
        reasonCodes: sample.reason_codes,
        occurredAt: sample.occurred_at,
      })),
    }),
  };
}

export async function POST(request: Request): Promise<Response> {
  let rawPayload: unknown;
  try {
    rawPayload = (await request.json()) as unknown;
  } catch (error) {
    return Response.json(
      {
        error: "invalid_policy_preview_request",
        message:
          error instanceof Error
            ? error.message
            : "request body must be valid JSON",
      },
      { status: 400 },
    );
  }

  const payload = recordFromUnknown(rawPayload);
  if (payload === undefined) {
    return Response.json(
      {
        error: "invalid_policy_preview_request",
        message: "request body must be an object",
      },
      { status: 400 },
    );
  }

  const currentPolicyYaml = stringField(payload, "current_policy_yaml");
  const proposedPolicyYaml = stringField(payload, "proposed_policy_yaml");
  if (currentPolicyYaml === undefined || proposedPolicyYaml === undefined) {
    return Response.json(
      {
        error: "invalid_policy_preview_request",
        message: "current_policy_yaml and proposed_policy_yaml are required",
      },
      { status: 400 },
    );
  }

  const prompt = stringField(payload, "prompt");
  const decisionSamples = decisionSamplesFromUnknown(payload.decision_samples);
  const proxy = buildPolicyPreviewProxyRequest({
    controlPlaneUrl: process.env.AIDENID_CONTROL_PLANE_URL,
    apiKey: process.env.AIDENID_CONTROL_PLANE_API_KEY,
    proposedPolicyYaml,
    prompt,
    decisionSamples,
    inputRefs: ["dashboard:policy-preview"],
    maxSuggestions: 5,
  });

  try {
    if (proxy === undefined) {
      return Response.json(
        buildPolicyPreviewResponse({
          currentPolicyYaml,
          proposedPolicyYaml,
          copilotPayload: localCopilotPayload(
            proposedPolicyYaml,
            prompt,
            decisionSamples,
          ),
        }),
      );
    }

    const auth = authorizeDashboardOperatorRequest(request, process.env);
    if (!auth.ok) {
      return operatorAuthFailureResponse(auth);
    }

    let upstream: Response;
    let text: string;
    try {
      upstream = await fetchDashboardControlPlaneWithTimeout(proxy.url, {
        method: "POST",
        headers: proxy.headers,
        body: proxy.body,
        cache: "no-store",
        timeoutMs: dashboardControlPlaneTimeoutMs(process.env),
      });
      text = await upstream.text();
    } catch (error) {
      return Response.json(
        {
          error: "policy_preview_unavailable",
          status: dashboardUpstreamStatusForError(error),
          message: "control plane policy preview request failed",
        },
        { status: dashboardUpstreamStatusForError(error) },
      );
    }

    let copilotPayload: unknown;
    try {
      copilotPayload = text.length === 0 ? {} : (JSON.parse(text) as unknown);
    } catch {
      return Response.json(
        {
          error: "policy_preview_unavailable",
          status: 502,
          message: "control plane policy preview returned invalid JSON",
        },
        { status: 502 },
      );
    }
    if (!upstream.ok) {
      return Response.json(
        {
          error: "policy_preview_unavailable",
          status: upstream.status,
          message:
            recordFromUnknown(copilotPayload)?.message ??
            recordFromUnknown(copilotPayload)?.error ??
            "control plane policy preview failed",
        },
        { status: upstream.status },
      );
    }

    return Response.json(
      buildPolicyPreviewResponse({
        currentPolicyYaml,
        proposedPolicyYaml,
        copilotPayload,
      }),
    );
  } catch (error) {
    return Response.json(
      {
        error: "invalid_policy_preview",
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 400 },
    );
  }
}
