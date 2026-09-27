import { describe, expect, it } from "vitest";

import { orgSubjectHandle, pairwiseSubjectHandle } from "../src/index.js";

describe("subject handles", () => {
  it("derives pairwise handles per site", () => {
    const subjectId = "sub_123";

    expect(pairwiseSubjectHandle({ siteSecret: "site-secret-a", siteId: "sit_a", subjectId })).not.toBe(
      pairwiseSubjectHandle({ siteSecret: "site-secret-b", siteId: "sit_b", subjectId })
    );
    expect(pairwiseSubjectHandle({ siteSecret: "site-secret-a", siteId: "sit_a", subjectId })).toBe(
      pairwiseSubjectHandle({ siteSecret: "site-secret-a", siteId: "sit_a", subjectId })
    );
  });

  it("requires explicit delegated consent for org handles", () => {
    expect(() =>
      orgSubjectHandle({
        orgSecret: "org-secret",
        orgId: "org_a",
        subjectId: "sub_123",
        delegatedConsent: false
      })
    ).toThrow(/delegated consent/);
  });

  it("derives org handles when delegated consent is present", () => {
    expect(
      orgSubjectHandle({
        orgSecret: "org-secret",
        orgId: "org_a",
        subjectId: "sub_123",
        delegatedConsent: true
      })
    ).toMatch(/^subh_/);
  });
});
