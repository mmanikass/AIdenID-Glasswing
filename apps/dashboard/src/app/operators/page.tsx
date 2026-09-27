import { headers } from "next/headers";

import { IdentityChallengeQueue } from "../../components/IdentityChallengeQueue.js";
import { IdentityReviewNotifications } from "../../components/IdentityReviewNotifications.js";
import { OperatorRegistryEditor } from "../../components/OperatorRegistryEditor.js";
import {
  fetchAuthorizedIdentityChallengeSubmissions,
  type IdentityChallengeFetchOutcome
} from "../../identityChallengeServer.js";
import {
  fetchAuthorizedIdentityReviewNotifications,
  type IdentityReviewNotificationFetchOutcome
} from "../../identityReviewNotificationServer.js";
import {
  fetchAuthorizedOperatorRegistry,
  type OperatorRegistryFetchOutcome
} from "../../operatorRegistryServer.js";

export const dynamic = "force-dynamic";

type OperatorRegistryUnavailableStatus = Exclude<OperatorRegistryFetchOutcome["status"], "live">;
type IdentityChallengeUnavailableStatus = Exclude<IdentityChallengeFetchOutcome["status"], "live">;
type IdentityReviewNotificationUnavailableStatus = Exclude<IdentityReviewNotificationFetchOutcome["status"], "live">;

const EMPTY_BANNER_TEXT: Record<OperatorRegistryUnavailableStatus, string> = {
  control_plane_unconfigured:
    "Live control plane is not configured. Set AIDENID_CONTROL_PLANE_URL to load the operator registry.",
  operator_token_missing:
    "Operator token is not configured. Set AIDENID_OPERATOR_TOKEN to load the operator registry.",
  fetch_failed:
    "The dashboard could not load the operator registry from the control plane.",
  operator_auth_not_configured:
    "Dashboard operator auth is not configured. Set AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN before loading the registry.",
  operator_auth_required:
    "Operator credentials are required before the live registry can be displayed.",
  invalid_operator_token:
    "Operator credentials were rejected. Refresh credentials before loading the registry.",
  operator_auth_shares_upstream_credential:
    "Dashboard operator auth is misconfigured: AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN is set to the same value as the upstream control-plane credential. Set a distinct secret before loading the registry."
};

const CHALLENGE_BANNER_TEXT: Record<IdentityChallengeUnavailableStatus, string> = {
  control_plane_unconfigured:
    "Live control plane is not configured. Pending identity challenges cannot be loaded.",
  operator_token_missing:
    "Operator token is not configured. Pending identity challenges cannot be loaded.",
  fetch_failed:
    "The dashboard could not load identity challenge submissions from the control plane.",
  operator_auth_not_configured:
    "Dashboard operator auth is not configured. Identity challenge review is unavailable.",
  operator_auth_required:
    "Operator credentials are required before identity challenge submissions can be displayed.",
  invalid_operator_token:
    "Operator credentials were rejected. Refresh credentials before loading identity challenges.",
  operator_auth_shares_upstream_credential:
    "Dashboard operator auth is misconfigured: the inbound token matches the upstream control-plane credential. Set a distinct secret before reviewing identity challenges."
};

const NOTIFICATION_BANNER_TEXT: Record<IdentityReviewNotificationUnavailableStatus, string> = {
  control_plane_unconfigured:
    "Live control plane is not configured. Review notifications cannot be loaded.",
  operator_token_missing:
    "Operator token is not configured. Review notifications cannot be loaded.",
  fetch_failed:
    "The dashboard could not load review notifications from the control plane.",
  operator_auth_not_configured:
    "Dashboard operator auth is not configured. Review notifications are unavailable.",
  operator_auth_required:
    "Operator credentials are required before review notifications can be displayed.",
  invalid_operator_token:
    "Operator credentials were rejected. Refresh credentials before loading review notifications.",
  operator_auth_shares_upstream_credential:
    "Dashboard operator auth is misconfigured: the inbound token matches the upstream control-plane credential. Set a distinct secret before loading review notifications."
};

export default async function OperatorsPage() {
  const requestHeaders = await headers();
  const [outcome, challengeOutcome, notificationOutcome] = await Promise.all([
    fetchAuthorizedOperatorRegistry(requestHeaders, process.env),
    fetchAuthorizedIdentityChallengeSubmissions(requestHeaders, process.env),
    fetchAuthorizedIdentityReviewNotifications(requestHeaders, process.env)
  ]);
  const operators = outcome.status === "live" ? outcome.operators : [];
  const submissions = challengeOutcome.status === "live" ? challengeOutcome.submissions : [];
  const notifications = notificationOutcome.status === "live" ? notificationOutcome.notifications : [];
  const offlineMessage =
    outcome.status === "live"
      ? undefined
      : outcome.status === "fetch_failed"
        ? `${EMPTY_BANNER_TEXT.fetch_failed} (${outcome.message})`
        : EMPTY_BANNER_TEXT[outcome.status] ?? "Operator registry unavailable.";
  const challengeMessage =
    challengeOutcome.status === "live"
      ? undefined
      : challengeOutcome.status === "fetch_failed"
        ? `${CHALLENGE_BANNER_TEXT.fetch_failed} (${challengeOutcome.message})`
        : CHALLENGE_BANNER_TEXT[challengeOutcome.status] ?? "Identity challenge submissions unavailable.";
  const notificationMessage =
    notificationOutcome.status === "live"
      ? undefined
      : notificationOutcome.status === "fetch_failed"
        ? `${NOTIFICATION_BANNER_TEXT.fetch_failed} (${notificationOutcome.message})`
        : NOTIFICATION_BANNER_TEXT[notificationOutcome.status] ?? "Review notifications unavailable.";

  return (
    <main className="dashboard-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">AIdenID</p>
          <h1>Operator Registry</h1>
          <p className={`runtime-pill runtime-${outcome.status === "live" ? "live_control_plane" : "sample_data"}`}>
            {outcome.status === "live" ? "Live control plane" : "Operator registry offline"}
          </p>
        </div>
      </header>
      {offlineMessage === undefined ? null : (
        <div className="data-provenance-banner data-provenance-sample_data" role="status">
          {offlineMessage}
        </div>
      )}
      {challengeMessage === undefined ? null : (
        <div className="data-provenance-banner data-provenance-sample_data" role="status">
          {challengeMessage}
        </div>
      )}
      {notificationMessage === undefined ? null : (
        <div className="data-provenance-banner data-provenance-sample_data" role="status">
          {notificationMessage}
        </div>
      )}
      <IdentityReviewNotifications notifications={notifications} />
      <IdentityChallengeQueue submissions={submissions} />
      <OperatorRegistryEditor initialOperators={operators} />
    </main>
  );
}
