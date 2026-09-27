export type AgentIdentityReviewNotificationStatus = "unread" | "read";
export type AgentIdentityReviewDecision = "approve" | "reject";

export interface AgentIdentityReviewNotificationView {
  readonly id: string;
  readonly site_id: string;
  readonly submission_id: string;
  readonly review_decision: AgentIdentityReviewDecision;
  readonly provider_name: string;
  readonly operator_actor_id?: string;
  readonly contact_url: string;
  readonly reviewer_identity_hash_sha256: string;
  readonly review_reason?: string;
  readonly status: AgentIdentityReviewNotificationStatus;
  readonly created_at: string;
  readonly read_at?: string;
}

export interface AgentIdentityReviewNotificationListFilters {
  readonly status?: AgentIdentityReviewNotificationStatus | undefined;
  readonly limit?: number | undefined;
}

const NOTIFICATION_STATUSES: readonly AgentIdentityReviewNotificationStatus[] = ["unread", "read"];
const REVIEW_DECISIONS: readonly AgentIdentityReviewDecision[] = ["approve", "reject"];

function isOptionalString(value: unknown): boolean {
  return value === undefined || typeof value === "string";
}

function isNotificationStatus(value: unknown): value is AgentIdentityReviewNotificationStatus {
  return typeof value === "string" && (NOTIFICATION_STATUSES as readonly string[]).includes(value);
}

function isReviewDecision(value: unknown): value is AgentIdentityReviewDecision {
  return typeof value === "string" && (REVIEW_DECISIONS as readonly string[]).includes(value);
}

export function buildAgentIdentityReviewNotificationListUrl(
  controlPlaneUrl: string,
  siteId: string,
  filters: AgentIdentityReviewNotificationListFilters = {}
): string {
  const url = new URL("/v1/identities/review-notifications", controlPlaneUrl);
  url.searchParams.set("site_id", siteId);
  if (filters.status !== undefined) {
    url.searchParams.set("status", filters.status);
  }
  if (filters.limit !== undefined) {
    url.searchParams.set("limit", String(filters.limit));
  }
  return url.toString();
}

export function buildAgentIdentityReviewNotificationReadUrl(
  controlPlaneUrl: string,
  notificationId: string
): string {
  return new URL(
    `/v1/identities/review-notifications/${encodeURIComponent(notificationId)}`,
    controlPlaneUrl
  ).toString();
}

function isNotification(value: unknown): value is AgentIdentityReviewNotificationView {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const candidate = value as Partial<AgentIdentityReviewNotificationView>;
  return (
    typeof candidate.id === "string" &&
    typeof candidate.site_id === "string" &&
    typeof candidate.submission_id === "string" &&
    isReviewDecision(candidate.review_decision) &&
    typeof candidate.provider_name === "string" &&
    isOptionalString(candidate.operator_actor_id) &&
    typeof candidate.contact_url === "string" &&
    typeof candidate.reviewer_identity_hash_sha256 === "string" &&
    isOptionalString(candidate.review_reason) &&
    isNotificationStatus(candidate.status) &&
    typeof candidate.created_at === "string" &&
    isOptionalString(candidate.read_at)
  );
}

export function parseAgentIdentityReviewNotificationList(
  value: unknown
): readonly AgentIdentityReviewNotificationView[] | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const notifications = (value as { notifications?: unknown }).notifications;
  if (!Array.isArray(notifications)) {
    return undefined;
  }
  return notifications.filter(isNotification);
}

export function parseAgentIdentityReviewNotificationResponse(
  value: unknown
): AgentIdentityReviewNotificationView | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const notification = (value as { notification?: unknown }).notification;
  return isNotification(notification) ? notification : undefined;
}
