import { mkdir, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { dirname } from "node:path";

import { createControlPlaneRuntime } from "../../control-plane/src/index.js";
import { dashboardDecisionEventFromPayload, type DashboardDecisionEvent } from "../src/dashboardLiveModel.js";
import { describe, expect, it } from "vitest";

interface LatencySample {
  readonly requestId: string;
  readonly actorClass: DashboardDecisionEvent["actorClass"];
  readonly decision: DashboardDecisionEvent["decision"];
  readonly routeTemplate: string;
  readonly latencyMs: number;
}

interface LatencySummary {
  readonly artifact_type: "decision_stream_ui_latency";
  readonly generated_at: string;
  readonly source_ref: string;
  readonly event_count: number;
  readonly budget_median_ms: number;
  readonly median_ms: number;
  readonly p95_ms: number;
  readonly max_ms: number;
  readonly status: "pass" | "fail";
  readonly path: {
    readonly control_plane_stream: "/v1/decisions/stream";
    readonly dashboard_parser: "apps/dashboard/src/dashboardLiveModel.ts";
  };
  readonly notes: readonly string[];
  readonly sample_preview: readonly LatencySample[];
}

interface ParsedSseEvent {
  readonly eventType: string;
  readonly data: unknown;
}

function numberFromEnv(name: string, fallback: number): number {
  const parsed = Number(process.env[name]);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function quantile(sorted: readonly number[], percentile: number): number {
  if (sorted.length === 0) {
    return Number.POSITIVE_INFINITY;
  }
  const index = Math.min(sorted.length - 1, Math.floor(sorted.length * percentile));
  return sorted[index] ?? Number.POSITIVE_INFINITY;
}

function roundMs(value: number): number {
  return Math.round(value * 1000) / 1000;
}

function sourceRef(): string {
  return process.env.AIDENID_STREAM_LATENCY_SOURCE_REF ?? "local-in-process";
}

function parseSseFrame(frame: string): ParsedSseEvent | undefined {
  const lines = frame.split(/\r?\n/);
  const eventType = lines
    .find((line) => line.startsWith("event:"))
    ?.slice("event:".length)
    .trim();
  const data = lines
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice("data:".length).trim())
    .join("\n");
  if (eventType === undefined || data.length === 0) {
    return undefined;
  }
  return {
    eventType,
    data: JSON.parse(data) as unknown
  };
}

async function collectStreamSamples(input: {
  readonly streamUrl: string;
  readonly expectedCount: number;
  readonly emittedAtByRequestId: ReadonlyMap<string, number>;
  readonly operatorToken: string;
  readonly signal: AbortSignal;
}): Promise<readonly LatencySample[]> {
  const response = await fetch(input.streamUrl, {
    signal: input.signal,
    headers: { Authorization: `Bearer ${input.operatorToken}` }
  });
  expect(response.status).toBe(200);
  expect(response.headers.get("content-type")).toContain("text/event-stream");
  expect(response.body).not.toBeNull();

  const reader = response.body?.getReader();
  if (reader === undefined) {
    throw new Error("decision stream response did not expose a readable body");
  }

  const decoder = new TextDecoder();
  let buffer = "";
  const samples: LatencySample[] = [];
  while (samples.length < input.expectedCount) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    buffer += decoder.decode(value, { stream: true });
    while (true) {
      const boundary = buffer.indexOf("\n\n");
      if (boundary < 0) {
        break;
      }
      const frame = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 2);
      const parsed = parseSseFrame(frame);
      if (parsed === undefined || parsed.eventType !== "recorded") {
        continue;
      }
      const dashboardEvent = dashboardDecisionEventFromPayload(parsed.data);
      if (dashboardEvent === undefined) {
        continue;
      }
      const emittedAt = input.emittedAtByRequestId.get(dashboardEvent.requestId);
      if (emittedAt === undefined) {
        continue;
      }
      samples.push({
        requestId: dashboardEvent.requestId,
        actorClass: dashboardEvent.actorClass,
        decision: dashboardEvent.decision,
        routeTemplate: dashboardEvent.routeTemplate,
        latencyMs: roundMs(Date.now() - emittedAt)
      });
    }
  }

  return samples;
}

async function postDecision(baseUrl: string, index: number, emittedAtByRequestId: Map<string, number>): Promise<void> {
  const requestId = `req_stream_ui_latency_${index}`;
  emittedAtByRequestId.set(requestId, Date.now());
  const response = await fetch(`${baseUrl}/v1/decisions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      site_id: "sit_stream_latency",
      request_id: requestId,
      actor_class: index % 2 === 0 ? "verified_agent" : "signed_agent",
      decision: "allow",
      recommended_decision: "allow",
      route_template: index % 2 === 0 ? "/checkout" : "/premium-content/*",
      method: "GET",
      occurred_at: new Date().toISOString(),
      latency_us: 750 + index,
      reason_codes: ["stream_latency_proof"]
    })
  });
  expect(response.status).toBe(201);
}

async function runDecisionStreamLatencyProof(): Promise<LatencySummary> {
  const eventCount = Math.floor(numberFromEnv("AIDENID_STREAM_LATENCY_EVENTS", 25));
  const budgetMedianMs = numberFromEnv("AIDENID_STREAM_LATENCY_BUDGET_MEDIAN_MS", 500);
  const operatorToken = "test_stream_latency_operator_token_123456";
  const siteId = "sit_stream_latency";
  const runtime = await createControlPlaneRuntime({
    operatorAuth: {
      entries: [{ actorId: "stream_latency_operator", token: operatorToken, roles: ["decision_search"] }]
    }
  });
  const emittedAtByRequestId = new Map<string, number>();
  const abort = new AbortController();

  try {
    await runtime.app.listen({ host: "127.0.0.1", port: 0 });
    const address = runtime.app.server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${address.port}`;
    const samplesPromise = collectStreamSamples({
      streamUrl: `${baseUrl}/v1/decisions/stream?site_id=${siteId}`,
      expectedCount: eventCount,
      emittedAtByRequestId,
      operatorToken,
      signal: abort.signal
    });

    await new Promise((resolve) => setTimeout(resolve, 10));
    await Promise.all(Array.from({ length: eventCount }, (_unused, index) => postDecision(baseUrl, index, emittedAtByRequestId)));
    const samples = await samplesPromise;
    expect(samples).toHaveLength(eventCount);

    const sorted = [...samples.map((sample) => sample.latencyMs)].sort((left, right) => left - right);
    const medianMs = roundMs(quantile(sorted, 0.5));
    const p95Ms = roundMs(quantile(sorted, 0.95));
    const maxMs = roundMs(sorted.at(-1) ?? Number.POSITIVE_INFINITY);
    return {
      artifact_type: "decision_stream_ui_latency",
      generated_at: new Date().toISOString(),
      source_ref: sourceRef(),
      event_count: eventCount,
      budget_median_ms: budgetMedianMs,
      median_ms: medianMs,
      p95_ms: p95Ms,
      max_ms: maxMs,
      status: medianMs < budgetMedianMs ? "pass" : "fail",
      path: {
        control_plane_stream: "/v1/decisions/stream",
        dashboard_parser: "apps/dashboard/src/dashboardLiveModel.ts"
      },
      notes: [
        "Opens the real control-plane SSE route over HTTP, posts decision records, and parses streamed payloads through the dashboard live model.",
        "This measures dashboard ingest/parsing latency, not browser paint or operator screen refresh."
      ],
      sample_preview: samples.slice(0, 5)
    };
  } finally {
    abort.abort();
    await runtime.app.close();
  }
}

async function writeArtifact(summary: LatencySummary): Promise<void> {
  if (!/^(1|true|yes)$/i.test(process.env.AIDENID_WRITE_STREAM_LATENCY_ARTIFACT ?? "")) {
    return;
  }
  const artifactPath = process.env.AIDENID_STREAM_LATENCY_ARTIFACT ?? "docs/dd/artifacts/decision-stream-ui-latency-2026-05-02.json";
  await mkdir(dirname(artifactPath), { recursive: true });
  await writeFile(artifactPath, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
}

describe("decision stream UI latency proof", () => {
  it("keeps request-to-dashboard-ingest median below the 500ms spec budget", async () => {
    const summary = await runDecisionStreamLatencyProof();
    await writeArtifact(summary);

    expect(summary.status).toBe("pass");
    expect(summary.median_ms).toBeLessThan(summary.budget_median_ms);
    expect(summary.sample_preview.length).toBeGreaterThan(0);
    expect(summary.sample_preview.every((sample) => sample.decision === "allow")).toBe(true);
  }, 10_000);
});
