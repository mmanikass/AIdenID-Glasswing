"use client";

import { useEffect, useRef, useState } from "react";
import { FileDiff, LoaderCircle, RotateCcw } from "lucide-react";

import type { PolicyDiffLine, PolicyPreviewResponse, PolicyPreviewSuggestion } from "../policyPreview.js";

type PreviewStatus = "idle" | "loading" | "ready" | "error";
type TextAreaWithValue = { readonly value: string };

function statusLabel(status: PreviewStatus, changedLineCount: number | undefined): string {
  if (status === "loading") {
    return "Previewing";
  }
  if (status === "error") {
    return "Preview failed";
  }
  if (status === "ready") {
    return changedLineCount === 0 ? "No policy changes" : `${changedLineCount} changed lines`;
  }
  return "Draft ready";
}

function lineClass(line: PolicyDiffLine): string {
  return `policy-diff-row policy-diff-${line.status}`;
}

function SuggestionSummary({ suggestion }: { readonly suggestion: PolicyPreviewSuggestion | undefined }) {
  if (suggestion === undefined) {
    return <p className="preview-muted">No Policy Copilot suggestions returned for this draft. The side-by-side diff remains read-only.</p>;
  }

  return (
    <div className="preview-suggestion">
      <div>
        <span className="drawer-label">Policy Copilot</span>
        <strong>{suggestion.label}</strong>
      </div>
      <div>
        <span className="drawer-label">Status</span>
        <strong>{suggestion.approvalStatus}</strong>
      </div>
      <div>
        <span className="drawer-label">Risk</span>
        <strong>{suggestion.riskLevel}</strong>
      </div>
      <div>
        <span className="drawer-label">Ops</span>
        <strong>{suggestion.operationCount}</strong>
      </div>
      <p>{suggestion.outputSummary.length === 0 ? suggestion.rationale : suggestion.outputSummary}</p>
    </div>
  );
}

export function PolicyDiffPreview({ currentPolicyYaml }: { readonly currentPolicyYaml: string }) {
  const [draftPolicyYaml, setDraftPolicyYaml] = useState(currentPolicyYaml);
  const [debouncedDraftPolicyYaml, setDebouncedDraftPolicyYaml] = useState(currentPolicyYaml);
  const [preview, setPreview] = useState<PolicyPreviewResponse | undefined>();
  const [status, setStatus] = useState<PreviewStatus>("idle");
  const [error, setError] = useState<string | undefined>();
  const abortRef = useRef<AbortController | undefined>(undefined);

  useEffect(() => {
    const timeout = setTimeout(() => setDebouncedDraftPolicyYaml(draftPolicyYaml), 220);
    return () => clearTimeout(timeout);
  }, [draftPolicyYaml]);

  useEffect(
    () => () => {
      abortRef.current?.abort();
    },
    []
  );

  const previewDiff = async () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setStatus("loading");
    setError(undefined);

    try {
      const response = await fetch("/api/policy/preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          current_policy_yaml: currentPolicyYaml,
          proposed_policy_yaml: draftPolicyYaml,
          prompt: "dashboard read-only policy diff preview"
        }),
        signal: controller.signal
      });
      const payload = (await response.json()) as PolicyPreviewResponse | { readonly message?: string; readonly error?: string };
      if (!response.ok) {
        throw new Error("message" in payload && typeof payload.message === "string" ? payload.message : "policy preview failed");
      }
      setPreview(payload as PolicyPreviewResponse);
      setStatus("ready");
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === "AbortError") {
        return;
      }
      setStatus("error");
      setError(caught instanceof Error ? caught.message : "policy preview failed");
    }
  };

  const resetDraft = () => {
    abortRef.current?.abort();
    setDraftPolicyYaml(currentPolicyYaml);
    setDebouncedDraftPolicyYaml(currentPolicyYaml);
    setPreview(undefined);
    setStatus("idle");
    setError(undefined);
  };

  const isSettling = draftPolicyYaml !== debouncedDraftPolicyYaml;
  const changedLineCount = preview?.changedLineCount;

  return (
    <section className="panel policy-preview-panel" aria-labelledby="policy-preview-heading">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Policy</p>
          <h2 id="policy-preview-heading">Diff Preview</h2>
        </div>
        <div className="button-row">
          <button className="action-button" type="button" title="Reset draft" onClick={resetDraft}>
            <RotateCcw size={16} />
            <span>Reset</span>
          </button>
          <button className="action-button primary" type="button" title="Preview diff" disabled={status === "loading"} onClick={() => void previewDiff()}>
            {status === "loading" ? <LoaderCircle className="spin-icon" size={16} /> : <FileDiff size={16} />}
            <span>Preview Diff</span>
          </button>
        </div>
      </div>

      <div className="policy-preview-grid">
        <label className="policy-source">
          <span>Current policy</span>
          <pre className="policy-text-view">{currentPolicyYaml}</pre>
        </label>
        <label className="policy-source">
          <span>Draft policy</span>
          <textarea
            aria-label="Proposed policy YAML"
            spellCheck={false}
            value={draftPolicyYaml}
            onChange={(event) => setDraftPolicyYaml((event.currentTarget as unknown as TextAreaWithValue).value)}
          />
        </label>
      </div>

      <div className="preview-state-row">
        <span className={`preview-state preview-state-${status}`}>{statusLabel(status, changedLineCount)}</span>
        {isSettling ? <span className="preview-muted">Draft debounce active</span> : <span className="preview-muted">Read-only; no policy is saved</span>}
      </div>
      {error === undefined ? null : <strong className="operator-action-error">{error}</strong>}

      {preview === undefined ? null : (
        <div className="policy-diff-output">
          <SuggestionSummary suggestion={preview.suggestions[0]} />
          <div className="policy-diff-table" role="table" aria-label="Policy YAML diff">
            <div className="policy-diff-header" role="row">
              <span role="columnheader">Current</span>
              <span role="columnheader">Draft</span>
            </div>
            {preview.diffLines.map((line) => (
              <div key={line.index} className={lineClass(line)} role="row">
                <pre role="cell">
                  <span>{line.currentLineNumber ?? ""}</span>
                  {line.current}
                </pre>
                <pre role="cell">
                  <span>{line.proposedLineNumber ?? ""}</span>
                  {line.proposed}
                </pre>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
