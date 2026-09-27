import { createHash } from "node:crypto";

import type {
  FingerprintEvidenceProvider,
  FingerprintProviderResult,
  SanitizedFingerprintRequest
} from "./index.js";

/**
 * Demo-grade local fingerprint provider.
 *
 * Implements the FingerprintEvidenceProvider interface using a small set of
 * fixed pattern-matching rules over already-sanitized request headers. There
 * is intentionally no machine learning, no probabilistic classifier, and no
 * LLM call — this is a transparent lookup table whose output is deterministic
 * for a given input. Production deployments are expected to plug in a real
 * fingerprint sidecar (e.g., DataDome, hCaptcha Enterprise) in place of this
 * provider.
 */

interface KnownBotPattern {
  readonly userAgentFragment: string;
  readonly operatorActorId: string;
  readonly llmBrandHint: string;
  readonly evidenceLabel: string;
  /**
   * Score in the 0-1 unit interval. Higher = more bot-like. Used by the
   * verifier as `botScore` when evaluating layer-3.
   */
  readonly botScore: number;
}

const KNOWN_BOT_PATTERNS: readonly KnownBotPattern[] = Object.freeze([
  Object.freeze({
    userAgentFragment: "GPTBot",
    operatorActorId: "operator:openai",
    llmBrandHint: "openai",
    evidenceLabel: "ua-match-gptbot",
    botScore: 0.95
  }),
  Object.freeze({
    userAgentFragment: "OAI-SearchBot",
    operatorActorId: "operator:openai",
    llmBrandHint: "openai",
    evidenceLabel: "ua-match-oai-searchbot",
    botScore: 0.95
  }),
  Object.freeze({
    userAgentFragment: "ChatGPT-User",
    operatorActorId: "operator:openai",
    llmBrandHint: "openai",
    evidenceLabel: "ua-match-chatgpt-user",
    botScore: 0.9
  }),
  Object.freeze({
    userAgentFragment: "anthropic-ai",
    operatorActorId: "operator:anthropic",
    llmBrandHint: "anthropic",
    evidenceLabel: "ua-match-anthropic-ai",
    botScore: 0.95
  }),
  Object.freeze({
    userAgentFragment: "Claude-Web",
    operatorActorId: "operator:anthropic",
    llmBrandHint: "anthropic",
    evidenceLabel: "ua-match-claude-web",
    botScore: 0.9
  }),
  Object.freeze({
    userAgentFragment: "ClaudeBot",
    operatorActorId: "operator:anthropic",
    llmBrandHint: "anthropic",
    evidenceLabel: "ua-match-claudebot",
    botScore: 0.95
  }),
  Object.freeze({
    userAgentFragment: "Googlebot",
    operatorActorId: "operator:google",
    llmBrandHint: "google",
    evidenceLabel: "ua-match-googlebot",
    botScore: 0.95
  }),
  Object.freeze({
    userAgentFragment: "GoogleOther",
    operatorActorId: "operator:google",
    llmBrandHint: "google",
    evidenceLabel: "ua-match-googleother",
    botScore: 0.9
  }),
  Object.freeze({
    userAgentFragment: "Google-InspectionTool",
    operatorActorId: "operator:google",
    llmBrandHint: "google",
    evidenceLabel: "ua-match-google-inspectiontool",
    botScore: 0.9
  }),
  Object.freeze({
    userAgentFragment: "Google-CloudVertexBot",
    operatorActorId: "operator:google",
    llmBrandHint: "google",
    evidenceLabel: "ua-match-google-cloudvertexbot",
    botScore: 0.9
  }),
  Object.freeze({
    userAgentFragment: "PerplexityBot",
    operatorActorId: "operator:perplexity",
    llmBrandHint: "perplexity",
    evidenceLabel: "ua-match-perplexitybot",
    botScore: 0.95
  })
]);

const HUMAN_BROWSER_HINTS: readonly string[] = Object.freeze([
  "sec-fetch-dest",
  "sec-fetch-mode",
  "sec-fetch-site"
]);

const MODERN_CHROMIUM_HINTS: readonly string[] = Object.freeze([
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform"
]);

function lowerCaseHeader(headers: Readonly<Record<string, string>>, name: string): string | undefined {
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) {
      return value;
    }
  }
  return undefined;
}

function hashShort(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex").slice(0, 16);
}

function deviceIdFor(request: SanitizedFingerprintRequest): string {
  const ua = lowerCaseHeader(request.headers, "user-agent") ?? "";
  const lang = lowerCaseHeader(request.headers, "accept-language") ?? "";
  const platform = lowerCaseHeader(request.headers, "sec-ch-ua-platform") ?? "";
  const ip = (request.remoteAddress ?? "").split(",")[0]?.trim() ?? "";
  return `dev_${hashShort(`${ua}|${lang}|${platform}|${ip}`)}`;
}

function findBotPattern(userAgent: string): KnownBotPattern | undefined {
  if (userAgent.length === 0) {
    return undefined;
  }
  const lowerUserAgent = userAgent.toLowerCase();
  return KNOWN_BOT_PATTERNS.find((pattern) => lowerUserAgent.includes(pattern.userAgentFragment.toLowerCase()));
}

function countHumanBrowserHints(headers: Readonly<Record<string, string>>): number {
  let count = 0;
  for (const hint of HUMAN_BROWSER_HINTS) {
    if (lowerCaseHeader(headers, hint) !== undefined) {
      count += 1;
    }
  }
  return count;
}

function countModernChromiumHints(headers: Readonly<Record<string, string>>): number {
  let count = 0;
  for (const hint of MODERN_CHROMIUM_HINTS) {
    if (lowerCaseHeader(headers, hint) !== undefined) {
      count += 1;
    }
  }
  return count;
}

function isTruncatedChromiumUserAgent(userAgent: string): boolean {
  const lower = userAgent.toLowerCase();
  return (
    lower.includes("mozilla/5.0") &&
    lower.includes("applewebkit/537.36") &&
    !/(chrome|chromium|crios|edg|opr|safari|firefox|version)\/[0-9]/u.test(lower)
  );
}

function scraperProfileEvidence(
  headers: Readonly<Record<string, string>>,
  userAgent: string,
  browserHints: number,
  chromiumHints: number
): readonly string[] {
  const labels: string[] = [];
  if (isTruncatedChromiumUserAgent(userAgent)) {
    labels.push("scraper-profile-static-playwright-ua", "chromium-ua-truncated");
  }
  if (browserHints === 0) {
    labels.push("browser-hints-missing");
  }
  if (chromiumHints === 0) {
    labels.push("client-hints-missing");
  }
  if (lowerCaseHeader(headers, "accept-language") === undefined) {
    labels.push("accept-language-missing");
  }
  return labels;
}

function hasEvidence(evidence: readonly string[], label: string): boolean {
  return evidence.includes(label);
}

/**
 * Build a deterministic local fingerprint provider suitable for demo flows.
 * For a given input the provider returns the same result every call.
 */
export function createLocalFingerprintProvider(): FingerprintEvidenceProvider {
  return {
    async lookup(request: SanitizedFingerprintRequest, _signal: AbortSignal): Promise<FingerprintProviderResult> {
      const userAgent = lowerCaseHeader(request.headers, "user-agent") ?? "";
      const deviceId = deviceIdFor(request);
      const knownBot = findBotPattern(userAgent);

      if (knownBot !== undefined) {
        return {
          provider: "demo-local",
          deviceId,
          botScore: knownBot.botScore,
          suspicionDelta: 0,
          operatorActorIdHint: knownBot.operatorActorId,
          llmBrandHint: knownBot.llmBrandHint,
          evidence: ["local-pattern-match", knownBot.evidenceLabel, `operator-actor-id-hint-${knownBot.operatorActorId.split(":")[1] ?? "unknown"}`]
        };
      }

      const browserHints = countHumanBrowserHints(request.headers);
      const chromiumHints = countModernChromiumHints(request.headers);
      const hasAcceptLanguage = lowerCaseHeader(request.headers, "accept-language") !== undefined;
      const whiteBoxScraperEvidence = scraperProfileEvidence(request.headers, userAgent, browserHints, chromiumHints);
      const hasTruncatedChromiumUserAgent = hasEvidence(whiteBoxScraperEvidence, "chromium-ua-truncated");

      if (
        hasEvidence(whiteBoxScraperEvidence, "scraper-profile-static-playwright-ua") &&
        hasEvidence(whiteBoxScraperEvidence, "browser-hints-missing") &&
        hasEvidence(whiteBoxScraperEvidence, "client-hints-missing")
      ) {
        return {
          provider: "demo-local",
          deviceId,
          botScore: 0.88,
          suspicionDelta: 0.85,
          evidence: ["local-pattern-match", ...whiteBoxScraperEvidence]
        };
      }

      if (hasTruncatedChromiumUserAgent) {
        return {
          provider: "demo-local",
          deviceId,
          botScore: 0.82,
          suspicionDelta: 0.8,
          evidence: ["local-pattern-match", ...whiteBoxScraperEvidence]
        };
      }

      // No UA at all → highly suspicious.
      if (userAgent.length === 0) {
        return {
          provider: "demo-local",
          deviceId,
          botScore: 0.6,
          suspicionDelta: 0.4,
          evidence: ["local-pattern-match", "ua-empty"]
        };
      }

      // Browser-shaped requests with full sec-fetch-* set.
      if (browserHints === HUMAN_BROWSER_HINTS.length && hasAcceptLanguage) {
        return {
          provider: "demo-local",
          deviceId,
          botScore: 0.1,
          suspicionDelta: 0,
          evidence: ["local-pattern-match", "browser-shaped-headers"]
        };
      }

      // Anything else: middle-of-the-road, with a small suspicion delta when
      // the request is missing the standard browser hints.
      const missingHints = HUMAN_BROWSER_HINTS.length - browserHints;
      const missingChromiumHints = MODERN_CHROMIUM_HINTS.length - chromiumHints;
      const suspicionDelta = Math.min(0.75, missingHints * 0.15 + missingChromiumHints * 0.05 + (hasAcceptLanguage ? 0 : 0.1));
      return {
        provider: "demo-local",
        deviceId,
        botScore: 0.5,
        suspicionDelta,
        evidence: [
          "local-pattern-match",
          "ua-unrecognized",
          ...whiteBoxScraperEvidence.filter((label) => label !== "scraper-profile-static-playwright-ua" && label !== "chromium-ua-truncated"),
          ...(hasAcceptLanguage || whiteBoxScraperEvidence.includes("accept-language-missing") ? [] : ["accept-language-missing"])
        ]
      };
    }
  };
}
