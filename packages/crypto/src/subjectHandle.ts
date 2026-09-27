import { hkdfSync } from "node:crypto";

import { base64Url } from "./digest.js";

export interface PairwiseSubjectHandleInput {
  readonly siteSecret: string;
  readonly siteId: string;
  readonly subjectId: string;
}

export interface OrgSubjectHandleInput {
  readonly orgSecret: string;
  readonly orgId: string;
  readonly subjectId: string;
  readonly delegatedConsent: boolean;
}

function requireNonEmpty(value: string, name: string): string {
  const normalized = value.trim();
  if (!normalized) {
    throw new Error(`${name} is required`);
  }
  return normalized;
}

function deriveHandle(secret: string, subjectId: string, info: string): string {
  const keyMaterial = Buffer.from(requireNonEmpty(secret, "secret"), "utf8");
  const salt = Buffer.from(requireNonEmpty(subjectId, "subjectId"), "utf8");
  const raw = Buffer.from(hkdfSync("sha256", keyMaterial, salt, Buffer.from(info, "utf8"), 32));
  return `subh_${base64Url(raw)}`;
}

export function pairwiseSubjectHandle(input: PairwiseSubjectHandleInput): string {
  const siteId = requireNonEmpty(input.siteId, "siteId");
  return deriveHandle(input.siteSecret, input.subjectId, `aidenid:pairwise-subject:v1:${siteId}`);
}

export function orgSubjectHandle(input: OrgSubjectHandleInput): string {
  if (!input.delegatedConsent) {
    throw new Error("org subject handles require explicit delegated consent");
  }
  const orgId = requireNonEmpty(input.orgId, "orgId");
  return deriveHandle(input.orgSecret, input.subjectId, `aidenid:org-subject:v1:${orgId}`);
}
