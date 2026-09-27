"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import type {
  AgentIdentityReviewOperatorStatus,
  AgentIdentityReviewTrustTier,
  AgentIdentityDefaultAction,
  AgentIdentitySubmissionView
} from "../dashboardIdentityChallenges.js";
import { fetchWithDashboardMutationTimeout } from "../clientMutationFetch.js";

interface IdentityChallengeQueueProps {
  readonly submissions: readonly AgentIdentitySubmissionView[];
}

type FormControlWithValue = { readonly value: string };
type SaveState = { readonly status: "idle" | "saving" | "saved" | "error"; readonly message?: string };

interface ReviewDraft {
  readonly operatorActorId: string;
  readonly trustTier: AgentIdentityReviewTrustTier;
  readonly operatorStatus: AgentIdentityReviewOperatorStatus;
  readonly reputationScore: string;
  readonly defaultAction: AgentIdentityDefaultAction;
  readonly defaultScopeRoutes: string;
  readonly defaultScopeRedirectPath: string;
  readonly approvalExpiresAtLocal: string;
  readonly notes: string;
  readonly reviewReason: string;
}

const CASCADE_LABELS: Readonly<Record<string, string>> = {
  crypto_identity: "Crypto",
  delegation_authorization: "Delegation",
  fingerprint_sidecar: "Fingerprint",
  operator_reputation: "Reputation"
};

const TRUST_TIER_LABELS: Record<AgentIdentityReviewTrustTier, string> = {
  restricted: "Restricted",
  trusted: "Trusted"
};

const OPERATOR_STATUS_LABELS: Record<AgentIdentityReviewOperatorStatus, string> = {
  active: "Active",
  watchlist: "Watchlist"
};

const TRUST_TIERS: readonly AgentIdentityReviewTrustTier[] = ["restricted", "trusted"];
const OPERATOR_STATUSES: readonly AgentIdentityReviewOperatorStatus[] = ["active", "watchlist"];
const DECISION_ACTIONS: readonly AgentIdentityDefaultAction[] = ["allow", "throttle", "queue", "sandbox", "deny", "price_required"];

const DECISION_LABELS: Record<AgentIdentityDefaultAction, string> = {
  allow: "Allow",
  throttle: "Throttle",
  queue: "Queue",
  sandbox: "Sandbox",
  deny: "Deny",
  price_required: "Price required"
};

function cascadeSummary(submission: AgentIdentitySubmissionView): string {
  return submission.cascade_attestation.map((layer) => CASCADE_LABELS[layer] ?? layer).join(" / ");
}

function formatRequestedDuration(seconds: number): string {
  if (seconds % 86_400 === 0) {
    const days = seconds / 86_400;
    return `${days} ${days === 1 ? "day" : "days"}`;
  }
  if (seconds % 3_600 === 0) {
    const hours = seconds / 3_600;
    return `${hours} ${hours === 1 ? "hour" : "hours"}`;
  }
  const minutes = Math.ceil(seconds / 60);
  return `${minutes} ${minutes === 1 ? "minute" : "minutes"}`;
}

function toDateTimeLocalValue(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

function isoFromDateTimeLocal(value: string): string | undefined {
  const trimmedValue = value.trim();
  if (trimmedValue.length === 0) {
    return undefined;
  }
  const date = new Date(trimmedValue);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

function draftFromSubmission(submission: AgentIdentitySubmissionView): ReviewDraft {
  return {
    operatorActorId: submission.operator_actor_id ?? "",
    trustTier: "restricted",
    operatorStatus: "active",
    reputationScore: "60",
    defaultAction: "allow",
    defaultScopeRoutes: "",
    defaultScopeRedirectPath: "",
    approvalExpiresAtLocal: toDateTimeLocalValue(submission.requested_access_expires_at),
    notes: "",
    reviewReason: ""
  };
}

function initialDrafts(submissions: readonly AgentIdentitySubmissionView[]): ReadonlyMap<string, ReviewDraft> {
  const drafts = new Map<string, ReviewDraft>();
  for (const submission of submissions) {
    drafts.set(submission.id, draftFromSubmission(submission));
  }
  return drafts;
}

function reviewApiUrl(submissionId: string): string {
  return `/api/identity-challenges/${encodeURIComponent(submissionId)}/review`;
}

function trimmed(value: string): string | undefined {
  const next = value.trim();
  return next.length === 0 ? undefined : next;
}

export function IdentityChallengeQueue({ submissions }: IdentityChallengeQueueProps) {
  const router = useRouter();
  const [pending, setPending] = useState<readonly AgentIdentitySubmissionView[]>(submissions);
  const [drafts, setDrafts] = useState<ReadonlyMap<string, ReviewDraft>>(() => initialDrafts(submissions));
  const [saveState, setSaveState] = useState<SaveState>({ status: "idle" });

  useEffect(() => {
    setPending(submissions);
    setDrafts((current) => {
      const next = new Map<string, ReviewDraft>();
      for (const submission of submissions) {
        next.set(submission.id, current.get(submission.id) ?? draftFromSubmission(submission));
      }
      return next;
    });
  }, [submissions]);

  const updateDraft = useCallback((submissionId: string, partial: Partial<ReviewDraft>) => {
    setDrafts((current) => {
      const existing = current.get(submissionId);
      if (existing === undefined) {
        return current;
      }
      const next = new Map(current);
      next.set(submissionId, { ...existing, ...partial });
      return next;
    });
  }, []);

  const review = useCallback(
    async (submission: AgentIdentitySubmissionView, action: "approve" | "reject") => {
      const draft = drafts.get(submission.id) ?? draftFromSubmission(submission);
      const reason = trimmed(draft.reviewReason);

      if (action === "reject" && reason === undefined) {
        setSaveState({ status: "error", message: "Rejecting a challenge requires a review reason." });
        return;
      }

      const body =
        action === "reject"
          ? { action, review_reason: reason }
          : (() => {
              const operatorActorId = trimmed(draft.operatorActorId);
              if (operatorActorId === undefined) {
                return { error: "Approving a challenge requires an operator actor id." };
              }
              const score = Number.parseInt(draft.reputationScore, 10);
              if (!Number.isInteger(score) || score < 0 || score > 100) {
                return { error: "Reputation score must be an integer between 0 and 100." };
              }
              const defaultScopeRoutes = draft.defaultScopeRoutes
                .split(/[\n,]+/u)
                .map((route) => route.trim())
                .filter((route) => route.length > 0);
              const defaultScopeRedirectPath = trimmed(draft.defaultScopeRedirectPath);
              const approvalExpiresAt = isoFromDateTimeLocal(draft.approvalExpiresAtLocal);
              if (approvalExpiresAt === undefined) {
                return { error: "Approval expiry must be a valid date and time." };
              }
              return {
                action,
                operator_actor_id: operatorActorId,
                trust_tier: draft.trustTier,
                operator_status: draft.operatorStatus,
                reputation_score: score,
                default_action: draft.defaultAction,
                default_scope_routes: defaultScopeRoutes,
                ...(defaultScopeRedirectPath === undefined ? {} : { default_scope_redirect_path: defaultScopeRedirectPath }),
                approval_expires_at: approvalExpiresAt,
                display_name: submission.provider_name,
                ...(trimmed(draft.notes) === undefined ? {} : { notes: trimmed(draft.notes) }),
                ...(reason === undefined ? {} : { review_reason: reason })
              };
            })();

      if ("error" in body) {
        setSaveState({ status: "error", message: body.error });
        return;
      }

      setSaveState({ status: "saving" });
      try {
        const response = await fetchWithDashboardMutationTimeout(reviewApiUrl(submission.id), {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body)
        });
        if (!response.ok) {
          const text = await response.text();
          setSaveState({ status: "error", message: `Review failed (HTTP ${response.status}): ${text || "no body"}` });
          return;
        }
        setPending((current) => current.filter((entry) => entry.id !== submission.id));
        setSaveState({ status: "saved", message: action === "approve" ? "Approved" : "Rejected" });
        router.refresh();
      } catch (error) {
        setSaveState({ status: "error", message: error instanceof Error ? error.message : "Review failed" });
      }
    },
    [drafts, router]
  );

  if (pending.length === 0) {
    return (
      <section className="panel">
        <div className="panel-heading">
          <h2>Identity Challenges</h2>
        </div>
        <p className="empty-table-cell">
          No pending agent identity challenges. New unknown-agent submissions will appear here before operators add them
          to the allowlist.
        </p>
      </section>
    );
  }

  return (
    <section className="panel operator-registry-panel">
      <div className="panel-heading">
        <h2>Identity Challenges</h2>
        <span aria-live="polite" className={`save-state save-state-${saveState.status}`}>
          {saveState.status === "saving" ? "Reviewing..." : saveState.message ?? `${pending.length} pending`}
        </span>
      </div>
      <p className="operator-registry-subtitle">
        Review agent identity submissions and write approved operators directly into the site allowlist.
      </p>
      <div className="operator-registry-table-wrap">
        <table className="operator-registry-table identity-challenge-table">
          <thead>
            <tr>
              <th scope="col">Provider</th>
              <th scope="col">Purpose</th>
              <th scope="col">Operator</th>
              <th scope="col">Tier</th>
              <th scope="col">Default</th>
              <th scope="col">Notes</th>
              <th scope="col">Review</th>
            </tr>
          </thead>
          <tbody>
            {pending.map((submission) => {
              const draft = drafts.get(submission.id) ?? draftFromSubmission(submission);
              return (
                <tr key={submission.id}>
                  <td>
                    <div className="operator-cell">
                      <strong>{submission.provider_name}</strong>
                      <small>{submission.contact_url}</small>
                      <small>{new Date(submission.submitted_at).toLocaleString()}</small>
                    </div>
                  </td>
                  <td>
                    <span className="trust-pill trust-pill-unknown">{submission.purpose}</span>
                    {submission.purpose_rationale === undefined ? null : (
                      <small className="operator-notes">{submission.purpose_rationale}</small>
                    )}
                    <small className="status-hint">
                      Requested stay: {formatRequestedDuration(submission.requested_access_duration_seconds)} until{" "}
                      {new Date(submission.requested_access_expires_at).toLocaleString()}
                    </small>
                    <small className="status-hint">{cascadeSummary(submission)}</small>
                  </td>
                  <td>
                    <input
                      aria-label={`Operator actor id for ${submission.provider_name}`}
                      maxLength={128}
                      onChange={(event) =>
                        updateDraft(submission.id, {
                          operatorActorId: (event.currentTarget as unknown as FormControlWithValue).value
                        })
                      }
                      placeholder="operator:provider"
                      type="text"
                      value={draft.operatorActorId}
                    />
                    {submission.jwks_url === undefined ? null : <small className="status-hint">{submission.jwks_url}</small>}
                  </td>
                  <td>
                    <select
                      aria-label={`Trust tier for ${submission.provider_name}`}
                      onChange={(event) =>
                        updateDraft(submission.id, {
                          trustTier: (event.currentTarget as unknown as FormControlWithValue).value as AgentIdentityReviewTrustTier
                        })
                      }
                      value={draft.trustTier}
                    >
                      {TRUST_TIERS.map((tier) => (
                        <option key={tier} value={tier}>
                          {TRUST_TIER_LABELS[tier]}
                        </option>
                      ))}
                    </select>
                    <select
                      aria-label={`Operator status for ${submission.provider_name}`}
                      onChange={(event) =>
                        updateDraft(submission.id, {
                          operatorStatus: (event.currentTarget as unknown as FormControlWithValue).value as AgentIdentityReviewOperatorStatus
                        })
                      }
                      value={draft.operatorStatus}
                    >
                      {OPERATOR_STATUSES.map((status) => (
                        <option key={status} value={status}>
                          {OPERATOR_STATUS_LABELS[status]}
                        </option>
                      ))}
                    </select>
                    <input
                      aria-label={`Reputation score for ${submission.provider_name}`}
                      max={100}
                      min={0}
                      onChange={(event) =>
                        updateDraft(submission.id, {
                          reputationScore: (event.currentTarget as unknown as FormControlWithValue).value
                        })
                      }
                      type="number"
                      value={draft.reputationScore}
                    />
                  </td>
                  <td>
                    <select
                      aria-label={`Default action for ${submission.provider_name}`}
                      onChange={(event) =>
                        updateDraft(submission.id, {
                          defaultAction: (event.currentTarget as unknown as FormControlWithValue).value as AgentIdentityDefaultAction
                        })
                      }
                      value={draft.defaultAction}
                    >
                      {DECISION_ACTIONS.map((action) => (
                        <option key={action} value={action}>
                          {DECISION_LABELS[action]}
                        </option>
                      ))}
                    </select>
                    <textarea
                      aria-label={`Default scope routes for ${submission.provider_name}`}
                      maxLength={2048}
                      onChange={(event) =>
                        updateDraft(submission.id, {
                          defaultScopeRoutes: (event.currentTarget as unknown as FormControlWithValue).value
                        })
                      }
                      placeholder={"/docs\n/pricing/*"}
                      rows={2}
                      value={draft.defaultScopeRoutes}
                    />
                    <input
                      aria-label={`Scope redirect path for ${submission.provider_name}`}
                      maxLength={256}
                      onChange={(event) =>
                        updateDraft(submission.id, {
                          defaultScopeRedirectPath: (event.currentTarget as unknown as FormControlWithValue).value
                        })
                      }
                      placeholder="/agent-access"
                      type="text"
                      value={draft.defaultScopeRedirectPath}
                    />
                    <input
                      aria-label={`Approval expiry for ${submission.provider_name}`}
                      max={toDateTimeLocalValue(submission.requested_access_expires_at)}
                      onChange={(event) =>
                        updateDraft(submission.id, {
                          approvalExpiresAtLocal: (event.currentTarget as unknown as FormControlWithValue).value
                        })
                      }
                      type="datetime-local"
                      value={draft.approvalExpiresAtLocal}
                    />
                    <small className="status-hint">
                      Expires no later than {new Date(submission.requested_access_expires_at).toLocaleString()}
                    </small>
                  </td>
                  <td>
                    <textarea
                      aria-label={`Allowlist notes for ${submission.provider_name}`}
                      maxLength={1024}
                      onChange={(event) =>
                        updateDraft(submission.id, {
                          notes: (event.currentTarget as unknown as FormControlWithValue).value
                        })
                      }
                      placeholder="Allowlist note"
                      rows={2}
                      value={draft.notes}
                    />
                    <textarea
                      aria-label={`Review reason for ${submission.provider_name}`}
                      maxLength={1024}
                      onChange={(event) =>
                        updateDraft(submission.id, {
                          reviewReason: (event.currentTarget as unknown as FormControlWithValue).value
                        })
                      }
                      placeholder="Review reason"
                      rows={2}
                      value={draft.reviewReason}
                    />
                  </td>
                  <td>
                    <div className="operator-actions">
                      <button
                        className="action-button primary"
                        disabled={saveState.status === "saving"}
                        onClick={() => void review(submission, "approve")}
                        type="button"
                      >
                        Approve
                      </button>
                      <button
                        className="action-button"
                        disabled={saveState.status === "saving"}
                        onClick={() => void review(submission, "reject")}
                        type="button"
                      >
                        Reject
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
