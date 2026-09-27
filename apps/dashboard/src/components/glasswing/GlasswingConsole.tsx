"use client";

import { useCallback, useEffect, useState } from "react";

import { ActorBadge } from "../ActorBadge.js";
import { DecisionPill } from "../DecisionPill.js";
import { ensureGlasswingSession, GlasswingApiError, glasswingGet, glasswingPost, glasswingRun } from "../../glasswing/client.js";
import { describeJev, expiryLabel, reviewDecisionLogText, reviewStatusLabel, summarizeRun } from "../../glasswing/model.js";
import {
  GLASSWING_TASKS,
  type GlasswingAgent,
  type GlasswingGrant,
  type GlasswingReview,
  type GlasswingRevocation,
  type GlasswingRunResult,
  type GlasswingTask
} from "../../glasswing/types.js";
import styles from "./GlasswingConsole.module.css";

type SessionState = "checking" | "ready" | "login_required" | "unavailable";

interface TimelineEntry {
  readonly id: number;
  readonly at: string;
  readonly kind: "mint" | "grant" | "run" | "revoke" | "review";
  readonly text: string;
  readonly run?: GlasswingRunResult | undefined;
}

interface GrantWithAgent extends GlasswingGrant {
  readonly agentId: string;
  readonly revoked: boolean;
}

/** One permission per grant: the protected site binds each grant to exactly one route. */
const GRANT_SCOPES: readonly { readonly permission: string; readonly label: string }[] = [
  { permission: "catalog:read", label: "catalog:read — read the catalog" },
  { permission: "items:reserve", label: "items:reserve — reserve an item" },
  { permission: "customers:export", label: "customers:export — export customers (policy denies this route)" },
  { permission: "reports:bulk", label: "reports:bulk — bulk report (purpose required, Jev review)" }
];
const DEFAULT_PERMISSION = "catalog:read";

// The dashboard compiles without the DOM lib (see LiveStream); read form values through a
// minimal shape instead of relying on HTMLInputElement typings.
type InputWithValue = { readonly value: string };
const inputValue = (event: { readonly target: unknown }): string => (event.target as InputWithValue).value;

function errorText(error: unknown): string {
  if (error instanceof GlasswingApiError) return error.message;
  return error instanceof Error ? error.message : String(error);
}

export function GlasswingConsole() {
  const [session, setSession] = useState<SessionState>("checking");
  const [agents, setAgents] = useState<readonly GlasswingAgent[]>([]);
  const [grants, setGrants] = useState<readonly GrantWithAgent[]>([]);
  const [reviews, setReviews] = useState<readonly GlasswingReview[]>([]);
  const [timeline, setTimeline] = useState<readonly TimelineEntry[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<string>("");
  const [selectedGrant, setSelectedGrant] = useState<string>("");
  const [permission, setPermission] = useState(DEFAULT_PERMISSION);
  const [ttlMinutes, setTtlMinutes] = useState(10);
  const [task, setTask] = useState<GlasswingTask>("catalog");
  const [purpose, setPurpose] = useState("Compare prices of the three cheapest laptops for the customer.");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const log = useCallback((entry: Omit<TimelineEntry, "id" | "at">) => {
    setTimeline((current) => [{ id: Date.now() + Math.random(), at: new Date().toISOString(), ...entry }, ...current].slice(0, 50));
  }, []);

  const refreshReviews = useCallback(async () => {
    const body = await glasswingGet<{ reviews: readonly GlasswingReview[] }>("reviews");
    setReviews(body.reviews);
  }, []);

  useEffect(() => {
    let disposed = false;
    (async () => {
      try {
        const outcome = await ensureGlasswingSession();
        if (disposed) return;
        setSession(outcome.state);
        if (outcome.state !== "ready") {
          if (outcome.detail !== undefined) setError(outcome.detail);
          return;
        }
        const body = await glasswingGet<{ agents: readonly GlasswingAgent[] }>("agents");
        if (disposed) return;
        setAgents(body.agents);
        await refreshReviews();
      } catch (e) {
        if (!disposed) {
          setSession("unavailable");
          setError(errorText(e));
        }
      }
    })();
    return () => {
      disposed = true;
    };
  }, [refreshReviews]);

  async function guarded(label: string, action: () => Promise<void>): Promise<void> {
    setBusy(label);
    setError(null);
    try {
      await action();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(null);
    }
  }

  const mint = () =>
    guarded("mint", async () => {
      const body = await glasswingPost<{ agent: GlasswingAgent }>("agents", {});
      setAgents((current) => [...current, body.agent]);
      setSelectedAgent(body.agent.id);
      log({ kind: "mint", text: `Minted ${body.agent.id} (key ${body.agent.keyId}, thumbprint ${body.agent.thumbprint.slice(0, 12)}…)` });
    });

  const issueGrant = () =>
    guarded("grant", async () => {
      if (!selectedAgent) throw new Error("Select an agent first.");
      const body = await glasswingPost<{ grant: GlasswingGrant }>("grants", { agentId: selectedAgent, permissions: [permission], expiresInSeconds: Math.max(60, ttlMinutes * 60) });
      const grant: GrantWithAgent = { ...body.grant, agentId: selectedAgent, revoked: false };
      setGrants((current) => [grant, ...current]);
      setSelectedGrant(grant.id);
      log({ kind: "grant", text: `Grant ${grant.id} to ${selectedAgent}: ${grant.permissions.join(", ")} on ${grant.resource}, ${expiryLabel(grant.expiresAt)}` });
    });

  const run = () =>
    guarded("run", async () => {
      if (!selectedAgent || !selectedGrant) throw new Error("Select an agent and a grant first.");
      const result = await glasswingRun(selectedAgent, { grantId: selectedGrant, task, purpose: task === "bulk-report" ? purpose : undefined });
      const summary = summarizeRun(result);
      log({ kind: "run", text: `${task}: ${summary.headline}`, run: result });
      if (result.jev?.obligation === "review_required") {
        await refreshReviews();
      }
    });

  const revoke = (grant: GrantWithAgent) =>
    guarded("revoke", async () => {
      const body = await glasswingPost<{ revocation: GlasswingRevocation }>("revoke", { chainId: grant.chainId, reason: "owner_revoked_from_glasswing" });
      setGrants((current) => current.map((g) => (g.chainId === grant.chainId ? { ...g, revoked: true } : g)));
      log({ kind: "revoke", text: `Revoked chain ${grant.chainId}: epoch ${body.revocation.epoch}. The next request by ${grant.agentId} on this grant is refused.` });
    });

  const decideReview = (review: GlasswingReview, decision: "approve" | "deny") =>
    guarded("review", async () => {
      const body = await glasswingPost<{ review: GlasswingReview }>(`reviews/${review.id}`, { decision });
      setReviews((current) => current.map((r) => (r.id === review.id ? body.review : r)));
      log({ kind: "review", text: reviewDecisionLogText(decision, body.review) });
    });

  if (session === "checking") {
    return <p className="status-hint">Connecting to the protected site…</p>;
  }
  if (session === "login_required") {
    return (
      <div className={styles.banner}>
        Login is required on this dashboard, so the local dev session used by this console is disabled. Run the loopback profile (pnpm dev) for the demo.
      </div>
    );
  }
  if (session === "unavailable") {
    return (
      <div className={styles.banner}>
        The Glasswing operator API is not reachable: {error ?? "AIDENID_PROTECTED_SITE_URL, AIDENID_OPERATOR_TOKEN and AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN must be configured (pnpm dev sets them)."}
      </div>
    );
  }

  const pendingReviews = reviews.filter((r) => r.status === "pending");

  return (
    <div className={styles.grid}>
      <div className={styles.stack}>
        <section className="panel" aria-labelledby="gw-agents">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">1 · Mint</p>
              <h2 id="gw-agents">Agents</h2>
            </div>
            <button className="action-button" type="button" onClick={mint} disabled={busy !== null}>
              {busy === "mint" ? "Minting…" : "Mint agent"}
            </button>
          </div>
          {agents.length === 0 ? (
            <p className="empty-state">No agents yet. Minting creates an Ed25519 key held by the demo runner and registers its public key with the site.</p>
          ) : (
            <div className={styles.list}>
              {agents.map((agent) => (
                <button
                  type="button"
                  key={agent.id}
                  className={`${styles.row} ${selectedAgent === agent.id ? styles.selected : ""}`}
                  onClick={() => setSelectedAgent(agent.id)}
                  aria-pressed={selectedAgent === agent.id}
                >
                  <div className={styles.rowMain}>
                    <strong className="mono">{agent.id}</strong>
                    <span className={styles.muted}>key {agent.keyId} · jkt {agent.thumbprint.slice(0, 16)}…</span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </section>

        <section className="panel" aria-labelledby="gw-grants">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">2 · Assign scoped work</p>
              <h2 id="gw-grants">Grants</h2>
            </div>
          </div>
          <div className={styles.form}>
            <label>
              Scope (one permission per grant)
              <select value={permission} onChange={(e) => setPermission(inputValue(e))}>
                {GRANT_SCOPES.map((scope) => (
                  <option key={scope.permission} value={scope.permission}>
                    {scope.label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Expires in (minutes)
              <input type="number" min={1} max={120} value={ttlMinutes} onChange={(e) => setTtlMinutes(Number(inputValue(e)) || 10)} />
            </label>
            <div className="button-row">
              <button className="action-button" type="button" onClick={issueGrant} disabled={busy !== null || !selectedAgent}>
                {busy === "grant" ? "Issuing…" : "Issue grant"}
              </button>
            </div>
          </div>
          {grants.length > 0 && (
            <div className={styles.list}>
              {grants.map((grant) => (
                <div key={grant.id} className={`${styles.row} ${selectedGrant === grant.id ? styles.selected : ""}`}>
                  <div className={styles.rowMain}>
                    <button type="button" className="text-link-button" onClick={() => setSelectedGrant(grant.id)} aria-pressed={selectedGrant === grant.id}>
                      <strong className="mono">{grant.id}</strong>
                    </button>
                    <span className={styles.muted}>
                      {grant.agentId} · {grant.permissions.join(", ")} · chain {grant.chainId} · {grant.revoked ? "revoked" : expiryLabel(grant.expiresAt)}
                    </span>
                  </div>
                  <button className="icon-button danger" type="button" onClick={() => revoke(grant)} disabled={busy !== null || grant.revoked} aria-label={`Revoke ${grant.chainId}`}>
                    {grant.revoked ? "Revoked" : "Revoke"}
                  </button>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="panel" aria-labelledby="gw-run">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">3 · Agent acts</p>
              <h2 id="gw-run">Run a task</h2>
            </div>
          </div>
          <div className={styles.form}>
            <label>
              Task
              <select value={task} onChange={(e) => setTask(inputValue(e) as GlasswingTask)}>
                {GLASSWING_TASKS.map((t) => (
                  <option key={t.task} value={t.task}>
                    {t.label} — {t.hint}
                  </option>
                ))}
              </select>
            </label>
            {task === "bulk-report" && (
              <label>
                Stated purpose (untrusted text the agent supplies; Jev reads it as data)
                <textarea rows={3} value={purpose} onChange={(e) => setPurpose(inputValue(e))} />
              </label>
            )}
            <div className="button-row">
              <button className="action-button" type="button" onClick={run} disabled={busy !== null || !selectedAgent || !selectedGrant}>
                {busy === "run" ? "Running…" : "Run signed request"}
              </button>
            </div>
          </div>
        </section>
      </div>

      <div className={styles.stack}>
        {error && <div className={styles.banner} role="alert">{error}</div>}

        <section className="panel" aria-labelledby="gw-reviews">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Human escalation</p>
              <h2 id="gw-reviews">Review queue ({pendingReviews.length})</h2>
            </div>
          </div>
          {reviews.length === 0 ? (
            <p className="empty-state">Nothing to review. Ambiguous actions land here when Jev cannot clear them, times out, or is unavailable.</p>
          ) : (
            <div className={styles.list}>
              {reviews.map((review) => (
                <div key={review.id} className={styles.row}>
                  <div className={styles.rowMain}>
                    <strong>
                      {review.task} by {review.agentId}
                    </strong>
                    <span className={styles.muted}>Purpose: {review.purpose || "(none)"}</span>
                    <span className={styles.muted}>{describeJev(review.assessment)}</span>
                    <span className={styles.muted}>{reviewStatusLabel(review.status)}</span>
                  </div>
                  {review.status === "pending" && (
                    <div className="button-row">
                      <button className="action-button" type="button" onClick={() => decideReview(review, "approve")} disabled={busy !== null}>
                        Approve
                      </button>
                      <button className="icon-button danger" type="button" onClick={() => decideReview(review, "deny")} disabled={busy !== null}>
                        Deny
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="panel" aria-labelledby="gw-timeline">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Evidence</p>
              <h2 id="gw-timeline">What happened</h2>
            </div>
          </div>
          {timeline.length === 0 ? (
            <p className="empty-state">Every mint, grant, request, review and revocation is listed here with the server-recorded outcome. The full decision stream with signed receipts is on the main dashboard.</p>
          ) : (
            <div className={styles.timeline}>
              {timeline.map((entry) => {
                const summary = entry.run ? summarizeRun(entry.run) : null;
                return (
                  <div key={entry.id} className={`${styles.outcome} ${summary ? styles[`outcome-${summary.tone}`] : ""}`}>
                    <span className={styles.muted}>{entry.at.slice(11, 19)} · {entry.kind}</span>
                    <strong>{entry.text}</strong>
                    {entry.run && summary && (
                      <>
                        <span className={styles.muted}>{summary.detail}</span>
                        <span>
                          {entry.run.decision && (
                            <>
                              <DecisionPill decision={entry.run.decision.action} /> <ActorBadge actorClass={entry.run.decision.actorClass} />{" "}
                              <span className="mono">{entry.run.decision.requestId}</span>
                            </>
                          )}
                        </span>
                        {entry.run.jev && <span className={styles.muted}>{describeJev(entry.run.jev)}</span>}
                      </>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
