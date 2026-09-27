"use client";

import { useCallback, useMemo, useState } from "react";

import type {
  OperatorDefaultAction,
  OperatorReputationStatus,
  OperatorReputationView,
  OperatorTrustTier
} from "../dashboardOperatorRegistry.js";
import { fetchWithDashboardMutationTimeout } from "../clientMutationFetch.js";

type FormControlWithValue = { readonly value: string };

interface OperatorRegistryEditorProps {
  readonly initialOperators: readonly OperatorReputationView[];
}

interface DraftFields {
  readonly trustTier: OperatorTrustTier;
  readonly status: OperatorReputationStatus;
  readonly reputationScore: string;
  readonly defaultAction: OperatorDefaultAction;
  readonly defaultScopeRoutes: string;
  readonly defaultScopeRedirectPath: string;
  readonly expiresAtLocal: string;
  readonly notes: string;
}

interface SaveState {
  readonly status: "idle" | "saving" | "saved" | "error";
  readonly message?: string | undefined;
}

const TRUST_TIERS: readonly OperatorTrustTier[] = ["unknown", "trusted", "restricted"];
const STATUSES: readonly OperatorReputationStatus[] = ["active", "watchlist", "suspended"];
const DECISION_ACTIONS: readonly OperatorDefaultAction[] = ["allow", "throttle", "queue", "sandbox", "deny", "price_required"];
const OPERATOR_REPUTATION_API_BASE = "/api/operators/reputation";

const TRUST_TIER_LABELS: Record<OperatorTrustTier, string> = {
  unknown: "Unknown",
  trusted: "Trusted",
  restricted: "Restricted"
};

const STATUS_LABELS: Record<OperatorReputationStatus, string> = {
  active: "Active",
  watchlist: "Watchlist",
  suspended: "Suspended",
  expired: "Expired"
};

const DECISION_LABELS: Record<OperatorDefaultAction, string> = {
  allow: "Allow",
  throttle: "Throttle",
  queue: "Queue",
  sandbox: "Sandbox",
  deny: "Deny",
  price_required: "Price required"
};

const ALLOWLIST_GUIDANCE: Record<OperatorReputationStatus, string> = {
  active: "Allowed — operator decisions flow normally.",
  watchlist: "Allowed under heightened review — decisions logged for audit follow-up.",
  suspended: "Blocked — operator is rejected at the gate.",
  expired: "Expired — excluded from verifier snapshots until re-approved."
};

function toDateTimeLocalValue(iso: string | undefined): string {
  if (iso === undefined) {
    return "";
  }
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

function isoFromDateTimeLocal(value: string): string | null | undefined {
  const trimmedValue = value.trim();
  if (trimmedValue.length === 0) {
    return null;
  }
  const date = new Date(trimmedValue);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

function draftFromOperator(operator: OperatorReputationView): DraftFields {
  return {
    trustTier: operator.trust_tier,
    status: operator.status,
    reputationScore: String(operator.reputation_score),
    defaultAction: operator.default_action ?? "allow",
    defaultScopeRoutes: (operator.default_scope_routes ?? []).join("\n"),
    defaultScopeRedirectPath: operator.default_scope_redirect_path ?? "",
    expiresAtLocal: toDateTimeLocalValue(operator.expires_at),
    notes: operator.notes ?? ""
  };
}

function viewByActorId(
  operators: readonly OperatorReputationView[]
): ReadonlyMap<string, OperatorReputationView> {
  const map = new Map<string, OperatorReputationView>();
  for (const operator of operators) {
    map.set(operator.operator_actor_id, operator);
  }
  return map;
}

interface PutBody {
  readonly trust_tier: OperatorTrustTier;
  readonly status: OperatorReputationStatus;
  readonly reputation_score: number;
  readonly default_action: OperatorDefaultAction;
  readonly default_scope_routes: readonly string[];
  readonly default_scope_redirect_path?: string;
  readonly expires_at?: string | null;
  readonly notes?: string;
  readonly display_name?: string;
}

function buildPutBody(operator: OperatorReputationView, draft: DraftFields): PutBody | { readonly error: string } {
  const score = Number.parseInt(draft.reputationScore, 10);
  if (!Number.isInteger(score) || score < 0 || score > 100) {
    return { error: "Reputation score must be an integer between 0 and 100." };
  }
  const scopeRoutes = draft.defaultScopeRoutes
    .split(/[\n,]+/u)
    .map((route) => route.trim())
    .filter((route) => route.length > 0);
  const scopeRedirectPath = draft.defaultScopeRedirectPath.trim();
  const expiresAt = isoFromDateTimeLocal(draft.expiresAtLocal);
  if (expiresAt === undefined) {
    return { error: "Expiry must be empty or a valid date and time." };
  }
  const trimmedNotes = draft.notes.trim();
  return {
    trust_tier: draft.trustTier,
    status: draft.status,
    reputation_score: score,
    default_action: draft.defaultAction,
    default_scope_routes: scopeRoutes,
    ...(scopeRedirectPath.length === 0 ? {} : { default_scope_redirect_path: scopeRedirectPath }),
    expires_at: expiresAt,
    ...(trimmedNotes.length === 0 ? {} : { notes: trimmedNotes }),
    ...(operator.display_name === undefined ? {} : { display_name: operator.display_name })
  };
}

function operatorReputationDetailApiUrl(operatorActorId: string): string {
  return `${OPERATOR_REPUTATION_API_BASE}/${encodeURIComponent(operatorActorId)}`;
}

export function OperatorRegistryEditor({
  initialOperators
}: OperatorRegistryEditorProps) {
  const [operators, setOperators] = useState<readonly OperatorReputationView[]>(initialOperators);
  const [editing, setEditing] = useState<string | undefined>(undefined);
  const [drafts, setDrafts] = useState<ReadonlyMap<string, DraftFields>>(new Map());
  const [saveState, setSaveState] = useState<SaveState>({ status: "idle" });

  const operatorsByActorId = useMemo(() => viewByActorId(operators), [operators]);

  const beginEdit = useCallback(
    (operator: OperatorReputationView) => {
      setSaveState({ status: "idle" });
      setEditing(operator.operator_actor_id);
      setDrafts((current) => {
        const next = new Map(current);
        if (!next.has(operator.operator_actor_id)) {
          next.set(operator.operator_actor_id, draftFromOperator(operator));
        }
        return next;
      });
    },
    [setDrafts, setEditing, setSaveState]
  );

  const cancelEdit = useCallback(() => {
    setEditing(undefined);
    setSaveState({ status: "idle" });
  }, []);

  const updateDraft = useCallback(
    (operatorActorId: string, partial: Partial<DraftFields>) => {
      setDrafts((current) => {
        const next = new Map(current);
        const existing = next.get(operatorActorId);
        if (existing === undefined) {
          return current;
        }
        next.set(operatorActorId, { ...existing, ...partial });
        return next;
      });
    },
    []
  );

  const submit = useCallback(
    async (operator: OperatorReputationView) => {
      const draft = drafts.get(operator.operator_actor_id);
      if (draft === undefined) {
        return;
      }
      const body = buildPutBody(operator, draft);
      if ("error" in body) {
        setSaveState({ status: "error", message: body.error });
        return;
      }
      setSaveState({ status: "saving" });
      try {
        const response = await fetchWithDashboardMutationTimeout(
          operatorReputationDetailApiUrl(operator.operator_actor_id),
          {
            method: "PUT",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
          }
        );
        if (!response.ok) {
          const text = await response.text();
          setSaveState({
            status: "error",
            message: `Save failed (HTTP ${response.status}): ${text || "no body"}`
          });
          return;
        }
        const payload = (await response.json()) as { operator?: OperatorReputationView };
        if (payload.operator === undefined) {
          setSaveState({ status: "error", message: "Save succeeded but response did not include the updated operator." });
          return;
        }
        const updated = payload.operator;
        setOperators((current) =>
          current.map((entry) =>
            entry.operator_actor_id === updated.operator_actor_id ? updated : entry
          )
        );
        setSaveState({ status: "saved" });
        setEditing(undefined);
      } catch (error) {
        setSaveState({
          status: "error",
          message: error instanceof Error ? error.message : "Save failed"
        });
      }
    },
    [drafts]
  );

  if (operators.length === 0) {
    return (
      <section className="panel">
        <div className="panel-heading">
          <h2>Operator Registry</h2>
        </div>
        <p className="empty-table-cell">
          No operators on file yet. Edits will appear here once the control plane has at least one operator reputation
          record.
        </p>
      </section>
    );
  }

  return (
    <section className="panel operator-registry-panel">
      <div className="panel-heading">
        <h2>Operator Registry</h2>
        <span aria-live="polite" className={`save-state save-state-${saveState.status}`}>
          {saveState.status === "saving" ? "Saving…" : saveState.message ?? null}
        </span>
      </div>
      <p className="operator-registry-subtitle">
        Allowed providers and their reputation. Saving an edit calls the control plane immediately and propagates to
        every active session.
      </p>
      <div className="operator-registry-table-wrap">
        <table className="operator-registry-table">
          <thead>
            <tr>
              <th scope="col">Operator</th>
              <th scope="col">Trust tier</th>
              <th scope="col">Status</th>
              <th scope="col">Default</th>
              <th scope="col">Score</th>
              <th scope="col">Notes</th>
              <th scope="col">Updated</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {operators.map((operator) => {
              const isEditing = editing === operator.operator_actor_id;
              const draft = drafts.get(operator.operator_actor_id) ?? draftFromOperator(operator);
              const view = operatorsByActorId.get(operator.operator_actor_id) ?? operator;
              return (
                <tr key={operator.operator_actor_id}>
                  <td>
                    <div className="operator-cell">
                      <strong>{view.display_name ?? view.operator_actor_id}</strong>
                      <small>{view.operator_actor_id}</small>
                    </div>
                  </td>
                  <td>
                    {isEditing ? (
                      <select
                        aria-label={`Trust tier for ${view.operator_actor_id}`}
                        value={draft.trustTier}
                        onChange={(event) =>
                          updateDraft(view.operator_actor_id, {
                            trustTier: (event.currentTarget as unknown as FormControlWithValue).value as OperatorTrustTier
                          })
                        }
                      >
                        {TRUST_TIERS.map((tier) => (
                          <option key={tier} value={tier}>
                            {TRUST_TIER_LABELS[tier]}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <span className={`trust-pill trust-pill-${view.trust_tier}`}>
                        {TRUST_TIER_LABELS[view.trust_tier]}
                      </span>
                    )}
                  </td>
                  <td>
                    {isEditing ? (
                      <>
                        <select
                          aria-label={`Status for ${view.operator_actor_id}`}
                          value={draft.status}
                          onChange={(event) =>
                            updateDraft(view.operator_actor_id, {
                              status: (event.currentTarget as unknown as FormControlWithValue).value as OperatorReputationStatus
                            })
                          }
                        >
                          {STATUSES.map((status) => (
                            <option key={status} value={status}>
                              {STATUS_LABELS[status]}
                            </option>
                          ))}
                        </select>
                        <small className="status-hint">{ALLOWLIST_GUIDANCE[draft.status]}</small>
                      </>
                    ) : (
                      <span className={`status-pill status-pill-${view.status}`}>{STATUS_LABELS[view.status]}</span>
                    )}
                  </td>
                  <td>
                    {isEditing ? (
                      <>
                        <select
                          aria-label={`Default action for ${view.operator_actor_id}`}
                          value={draft.defaultAction}
                          onChange={(event) =>
                            updateDraft(view.operator_actor_id, {
                              defaultAction: (event.currentTarget as unknown as FormControlWithValue).value as OperatorDefaultAction
                            })
                          }
                        >
                          {DECISION_ACTIONS.map((action) => (
                            <option key={action} value={action}>
                              {DECISION_LABELS[action]}
                            </option>
                          ))}
                        </select>
                        <textarea
                          aria-label={`Default scope routes for ${view.operator_actor_id}`}
                          maxLength={2048}
                          onChange={(event) =>
                            updateDraft(view.operator_actor_id, {
                              defaultScopeRoutes: (event.currentTarget as unknown as FormControlWithValue).value
                            })
                          }
                          placeholder={"/docs\n/pricing/*"}
                          rows={2}
                          value={draft.defaultScopeRoutes}
                        />
                        <input
                          aria-label={`Scope redirect path for ${view.operator_actor_id}`}
                          maxLength={256}
                          onChange={(event) =>
                            updateDraft(view.operator_actor_id, {
                              defaultScopeRedirectPath: (event.currentTarget as unknown as FormControlWithValue).value
                            })
                          }
                          placeholder="/agent-access"
                          type="text"
                          value={draft.defaultScopeRedirectPath}
                        />
                        <input
                          aria-label={`Expiry for ${view.operator_actor_id}`}
                          onChange={(event) =>
                            updateDraft(view.operator_actor_id, {
                              expiresAtLocal: (event.currentTarget as unknown as FormControlWithValue).value
                            })
                          }
                          type="datetime-local"
                          value={draft.expiresAtLocal}
                        />
                      </>
                    ) : (
                      <div className="operator-cell">
                        <span className={`status-pill status-pill-${view.status}`}>{DECISION_LABELS[view.default_action ?? "allow"]}</span>
                        <small>{(view.default_scope_routes ?? []).length === 0 ? "All routes" : (view.default_scope_routes ?? []).join(", ")}</small>
                        <small>{view.expires_at === undefined ? "Permanent" : `Expires ${new Date(view.expires_at).toLocaleString()}`}</small>
                      </div>
                    )}
                  </td>
                  <td>
                    {isEditing ? (
                      <input
                        aria-label={`Reputation score for ${view.operator_actor_id}`}
                        max={100}
                        min={0}
                        onChange={(event) =>
                          updateDraft(view.operator_actor_id, {
                            reputationScore: (event.currentTarget as unknown as FormControlWithValue).value
                          })
                        }
                        type="number"
                        value={draft.reputationScore}
                      />
                    ) : (
                      <strong>{view.reputation_score}</strong>
                    )}
                  </td>
                  <td>
                    {isEditing ? (
                      <textarea
                        aria-label={`Notes for ${view.operator_actor_id}`}
                        maxLength={1024}
                        onChange={(event) =>
                          updateDraft(view.operator_actor_id, {
                            notes: (event.currentTarget as unknown as FormControlWithValue).value
                          })
                        }
                        rows={2}
                        value={draft.notes}
                      />
                    ) : (
                      <span className="operator-notes">{view.notes ?? "—"}</span>
                    )}
                  </td>
                  <td>
                    <small>{new Date(view.updated_at).toLocaleString()}</small>
                  </td>
                  <td>
                    {isEditing ? (
                      <div className="operator-actions">
                        <button
                          className="action-button"
                          disabled={saveState.status === "saving"}
                          onClick={() => void submit(view)}
                          type="button"
                        >
                          Save
                        </button>
                        <button
                          className="text-link-button"
                          onClick={cancelEdit}
                          type="button"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button className="text-link-button" onClick={() => beginEdit(view)} type="button">
                        Edit
                      </button>
                    )}
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
