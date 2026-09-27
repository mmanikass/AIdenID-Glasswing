import { describe, expect, it } from "vitest";

import { classifyRequest } from "../src/index.js";

describe("soft-path classifier", () => {
  it("labels signed traffic as signed_agent until crypto verification lands", () => {
    expect(classifyRequest({ signature: "sig", "signature-input": "sig1=()" })).toMatchObject({
      actorClass: "signed_agent"
    });
  });

  it("uses humble likely_human label for browser-shaped traffic", () => {
    expect(
      classifyRequest({
        "user-agent": "Mozilla/5.0 Chrome/123",
        accept: "text/html,application/xhtml+xml"
      })
    ).toMatchObject({ actorClass: "likely_human" });
  });

  it("labels automation signals without claiming certainty", () => {
    expect(classifyRequest({ "user-agent": "python-requests/2.0" })).toMatchObject({
      actorClass: "suspicious_automation"
    });
  });
});
