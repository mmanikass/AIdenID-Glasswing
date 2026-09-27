import type { AgentIdentityReviewNotificationView } from "../dashboardIdentityReviewNotifications.js";

interface IdentityReviewNotificationsProps {
  readonly notifications: readonly AgentIdentityReviewNotificationView[];
}

const DECISION_LABELS: Record<AgentIdentityReviewNotificationView["review_decision"], string> = {
  approve: "Approved",
  reject: "Rejected"
};

function fallbackReason(notification: AgentIdentityReviewNotificationView): string {
  return notification.review_reason ?? "No reason provided";
}

export function IdentityReviewNotifications({ notifications }: IdentityReviewNotificationsProps) {
  if (notifications.length === 0) {
    return (
      <section className="panel">
        <div className="panel-heading">
          <h2>Review Notifications</h2>
        </div>
        <p className="empty-table-cell">No unread review notifications.</p>
      </section>
    );
  }

  return (
    <section className="panel operator-registry-panel">
      <div className="panel-heading">
        <h2>Review Notifications</h2>
        <span aria-live="polite" className="save-state save-state-idle">
          {notifications.length} unread
        </span>
      </div>
      <div className="operator-registry-table-wrap">
        <table className="operator-registry-table identity-notification-table">
          <thead>
            <tr>
              <th scope="col">Decision</th>
              <th scope="col">Provider</th>
              <th scope="col">Reason</th>
              <th scope="col">Reviewed</th>
            </tr>
          </thead>
          <tbody>
            {notifications.map((notification) => (
              <tr key={notification.id}>
                <td>
                  <span className={`decision-pill decision-${notification.review_decision === "approve" ? "allow" : "deny"}`}>
                    {DECISION_LABELS[notification.review_decision]}
                  </span>
                  <small className="status-hint">{notification.submission_id}</small>
                </td>
                <td>
                  <div className="operator-cell">
                    <strong>{notification.provider_name}</strong>
                    {notification.operator_actor_id === undefined ? null : <small>{notification.operator_actor_id}</small>}
                    <small>{notification.contact_url}</small>
                  </div>
                </td>
                <td>
                  <small className="operator-notes">{fallbackReason(notification)}</small>
                </td>
                <td>
                  <small>{new Date(notification.created_at).toLocaleString()}</small>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
