import { describe, expect, it } from "vitest";

import { createLocalFingerprintProvider, sanitizeFingerprintRequest } from "../src/index.js";

const signal = new AbortController().signal;

const baseRequest = {
  method: "GET",
  url: "https://example.test/",
  routeTemplate: "/"
} as const;

describe("createLocalFingerprintProvider", () => {
  const provider = createLocalFingerprintProvider();

  it("flags GPTBot user-agents with high botScore and zero suspicion", async () => {
    const request = sanitizeFingerprintRequest({
      ...baseRequest,
      headers: { "user-agent": "Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)" }
    });
    const result = await provider.lookup(request, signal);
    expect(result.provider).toBe("demo-local");
    expect(result.botScore).toBe(0.95);
    expect(result.suspicionDelta).toBe(0);
    expect(result.operatorActorIdHint).toBe("operator:openai");
    expect(result.llmBrandHint).toBe("openai");
    expect(result.evidence).toContain("ua-match-gptbot");
    expect(result.evidence).toContain("operator-actor-id-hint-openai");
  });

  it("flags ChatGPT-User browser-on-behalf-of-user with high botScore and zero suspicion", async () => {
    const request = sanitizeFingerprintRequest({
      ...baseRequest,
      headers: { "user-agent": "Mozilla/5.0 (ChatGPT-User/1.0)" }
    });
    const result = await provider.lookup(request, signal);
    expect(result.botScore).toBe(0.9);
    expect(result.operatorActorIdHint).toBe("operator:openai");
    expect(result.llmBrandHint).toBe("openai");
    expect(result.evidence).toContain("ua-match-chatgpt-user");
  });

  it("flags Anthropic crawler with the anthropic operator hint", async () => {
    const request = sanitizeFingerprintRequest({
      ...baseRequest,
      headers: { "user-agent": "anthropic-ai/1.0" }
    });
    const result = await provider.lookup(request, signal);
    expect(result.botScore).toBe(0.95);
    expect(result.operatorActorIdHint).toBe("operator:anthropic");
    expect(result.llmBrandHint).toBe("anthropic");
    expect(result.evidence).toContain("operator-actor-id-hint-anthropic");
  });

  it("flags Google crawler user-agents with google operator identity hints", async () => {
    const request = sanitizeFingerprintRequest({
      ...baseRequest,
      headers: {
        "user-agent":
          "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/136.0.0.0 Safari/537.36"
      }
    });
    const result = await provider.lookup(request, signal);
    expect(result.botScore).toBe(0.95);
    expect(result.operatorActorIdHint).toBe("operator:google");
    expect(result.llmBrandHint).toBe("google");
    expect(result.evidence).toContain("ua-match-googlebot");
  });

  it.each([
    ["OAI-SearchBot", "Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)", "operator:openai", "openai", "ua-match-oai-searchbot"],
    ["Claude-Web", "Claude-Web/1.0", "operator:anthropic", "anthropic", "ua-match-claude-web"],
    ["ClaudeBot", "Mozilla/5.0 (compatible; ClaudeBot/1.0; +https://www.anthropic.com)", "operator:anthropic", "anthropic", "ua-match-claudebot"],
    ["GoogleOther", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GoogleOther/1.0)", "operator:google", "google", "ua-match-googleother"],
    [
      "Google-InspectionTool",
      "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Google-InspectionTool/1.0)",
      "operator:google",
      "google",
      "ua-match-google-inspectiontool"
    ],
    [
      "Google-CloudVertexBot",
      "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Google-CloudVertexBot/1.0)",
      "operator:google",
      "google",
      "ua-match-google-cloudvertexbot"
    ],
    ["PerplexityBot", "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)", "operator:perplexity", "perplexity", "ua-match-perplexitybot"]
  ])("flags recognized crawler user-agent hints for %s", async (_label, userAgent, operatorActorIdHint, llmBrandHint, evidenceLabel) => {
    const request = sanitizeFingerprintRequest({
      ...baseRequest,
      headers: { "user-agent": userAgent }
    });
    const result = await provider.lookup(request, signal);
    expect(result.operatorActorIdHint).toBe(operatorActorIdHint);
    expect(result.llmBrandHint).toBe(llmBrandHint);
    expect(result.evidence).toContain(evidenceLabel);
  });

  it("treats requests with full browser sec-fetch-* hints + accept-language as low-bot", async () => {
    const request = sanitizeFingerprintRequest({
      ...baseRequest,
      headers: {
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "accept-language": "en-US,en;q=0.9",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none"
      }
    });
    const result = await provider.lookup(request, signal);
    expect(result.botScore).toBe(0.1);
    expect(result.suspicionDelta).toBe(0);
    expect(result.operatorActorIdHint).toBeUndefined();
    expect(result.llmBrandHint).toBeUndefined();
    expect(result.evidence).toContain("browser-shaped-headers");
  });

  it("flags the white-box Playwright scraper's truncated Chromium profile", async () => {
    const request = sanitizeFingerprintRequest({
      ...baseRequest,
      headers: {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        accept: "text/html"
      },
      remoteAddress: "198.51.100.42"
    });
    const result = await provider.lookup(request, signal);
    expect(result.botScore).toBeGreaterThanOrEqual(0.88);
    expect(result.suspicionDelta).toBeGreaterThanOrEqual(0.85);
    expect(result.evidence).toEqual(
      expect.arrayContaining([
        "scraper-profile-static-playwright-ua",
        "chromium-ua-truncated",
        "browser-hints-missing",
        "client-hints-missing",
        "accept-language-missing"
      ])
    );
  });

  it("keeps malformed Chromium UA suspicious even when browser hints are present", async () => {
    const request = sanitizeFingerprintRequest({
      ...baseRequest,
      headers: {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "accept-language": "en-US,en;q=0.9",
        "sec-ch-ua": '"Chromium";v="136", "Not.A/Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none"
      },
      remoteAddress: "198.51.100.42"
    });
    const result = await provider.lookup(request, signal);
    expect(result.botScore).toBeGreaterThanOrEqual(0.82);
    expect(result.suspicionDelta).toBeGreaterThanOrEqual(0.8);
    expect(result.evidence).toEqual(expect.arrayContaining(["scraper-profile-static-playwright-ua", "chromium-ua-truncated"]));
    expect(result.evidence).not.toContain("browser-shaped-headers");
  });

  it.each([
    ["Lynx", "Lynx/2.9.0 libwww-FM/2.14 SSL-MM/1.4.1"],
    ["w3m", "w3m/0.5.3+git20230121"],
    ["IE11", "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"],
    ["screen-reader browser", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Accessibility) Gecko/20100101 Firefox/115.0"]
  ])("does not turn legitimate uncommon UA into a suspicious local fingerprint: %s", async (_label, userAgent) => {
    const request = sanitizeFingerprintRequest({
      ...baseRequest,
      headers: { "user-agent": userAgent }
    });
    const result = await provider.lookup(request, signal);
    expect(result.botScore).toBeLessThan(0.8);
    expect(result.suspicionDelta).toBeLessThan(0.75);
    expect(result.operatorActorIdHint).toBeUndefined();
    expect(result.llmBrandHint).toBeUndefined();
    expect(result.evidence).not.toContain("scraper-profile-static-playwright-ua");
    expect(result.evidence).not.toContain("chromium-ua-truncated");
  });

  it("returns elevated suspicion when sec-fetch-* hints and accept-language are missing", async () => {
    const request = sanitizeFingerprintRequest({
      ...baseRequest,
      headers: { "user-agent": "curl/8.0.1" }
    });
    const result = await provider.lookup(request, signal);
    expect(result.botScore).toBe(0.5);
    expect(result.suspicionDelta).toBeGreaterThan(0);
    expect(result.evidence).toContain("browser-hints-missing");
    expect(result.evidence).toContain("accept-language-missing");
  });

  it("returns the highest demo suspicion when the user-agent is missing entirely", async () => {
    const request = sanitizeFingerprintRequest({
      ...baseRequest,
      headers: {}
    });
    const result = await provider.lookup(request, signal);
    expect(result.botScore).toBe(0.6);
    expect(result.suspicionDelta).toBe(0.4);
    expect(result.evidence).toContain("ua-empty");
  });

  it("is deterministic — same input yields the same deviceId and scores", async () => {
    const request = sanitizeFingerprintRequest({
      ...baseRequest,
      headers: { "user-agent": "GPTBot/1.0" }
    });
    const a = await provider.lookup(request, signal);
    const b = await provider.lookup(request, signal);
    expect(a.deviceId).toBe(b.deviceId);
    expect(a.botScore).toBe(b.botScore);
    expect(a.suspicionDelta).toBe(b.suspicionDelta);
  });

  it("produces distinct deviceIds for different user-agents", async () => {
    const gpt = sanitizeFingerprintRequest({
      ...baseRequest,
      headers: { "user-agent": "GPTBot/1.0" }
    });
    const claude = sanitizeFingerprintRequest({
      ...baseRequest,
      headers: { "user-agent": "anthropic-ai/1.0" }
    });
    const a = await provider.lookup(gpt, signal);
    const b = await provider.lookup(claude, signal);
    expect(a.deviceId).not.toBe(b.deviceId);
  });
});
