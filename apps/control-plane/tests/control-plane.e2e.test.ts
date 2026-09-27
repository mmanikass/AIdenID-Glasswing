import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHmac, generateKeyPairSync } from "node:crypto";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { decodeCompactJwt, verifyCompactJws } from "@aidenid/crypto";
import type { RedisStreamsClient } from "@aidenid/eventing";
import { describe, expect, it } from "vitest";

import {
  controlPlaneDatabaseUrlFromEnvironment,
  createControlPlaneRuntime,
  DECISION_OUTBOX_GENESIS_HASH,
  decisionOutboxEntryHash,
  InMemoryControlPlaneStore,
  LocalDecisionReceiptIssuer,
  localDecisionReceiptIssuerFromEnvironment,
  PostgresControlPlaneStore,
  RegistryBackedDecisionReceiptIssuer,
  runControlPlaneMigrations,
  StaticWebhookSecretResolver,
  type SqlClient,
  type SqlLease,
  type SqlNotification,
  type SqlQueryResult
} from "../src/index.js";

function rowsAs<Row extends Record<string, unknown>>(rows: Record<string, unknown>[]): Row[] {
  return rows as unknown as Row[];
}

async function delay(ms: number): Promise<void> {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });
}

const TEST_OPERATOR_TOKEN = "test_operator_token_ciso_123456";
const TEST_VIEWER_TOKEN = "test_operator_token_viewer_123456";
const TEST_REPUTATION_TOKEN = "test_operator_token_reputation_123456";
const TEST_ADMIN_TOKEN = "test_operator_token_admin_123456";
const TEST_OPERATOR_AUTH = {
  entries: [
    { actorId: "ciso_demo", token: TEST_OPERATOR_TOKEN, roles: ["decision_operator"] },
    { actorId: "read_only_analyst", token: TEST_VIEWER_TOKEN, roles: ["decision_search"] },
    { actorId: "risk_ops", token: TEST_REPUTATION_TOKEN, roles: ["operator_reputation"] },
    { actorId: "platform_admin", token: TEST_ADMIN_TOKEN, roles: ["admin"] }
  ]
} as const;

function bearerHeader(value: string): string {
  return ["Bearer", value].join(" ");
}

const TEST_OPERATOR_HEADERS = { Authorization: bearerHeader(TEST_OPERATOR_TOKEN) };
const TEST_VIEWER_HEADERS = { Authorization: bearerHeader(TEST_VIEWER_TOKEN) };
const TEST_REPUTATION_HEADERS = { Authorization: bearerHeader(TEST_REPUTATION_TOKEN) };
const TEST_ADMIN_HEADERS = { Authorization: bearerHeader(TEST_ADMIN_TOKEN) };

class RecordingRedisStreamsClient implements RedisStreamsClient {
  readonly writes: Array<{ stream: string; id: string; fields: string[] }> = [];
  failWith: Error | undefined;

  async xadd(stream: string, id: "*", ...fieldValues: string[]): Promise<string> {
    if (this.failWith !== undefined) {
      throw this.failWith;
    }
    this.writes.push({ stream, id, fields: fieldValues });
    return `1730000000000-${this.writes.length - 1}`;
  }
}

class AdoptionSqlClient implements SqlClient {
  readonly sql: string[] = [];
  leases = 0;
  releases = 0;
  readonly #tenantQuotas = new Map<string, Record<string, unknown>>();
  readonly #decisions: Record<string, unknown>[] = [];
  readonly #decisionOutbox: Record<string, unknown>[] = [];
  readonly #privacyErasures: Record<string, unknown>[] = [];
  readonly #webhookEndpoints = new Map<string, Record<string, unknown>>();
  readonly #quarantinePins: Record<string, unknown>[] = [];
  readonly #operatorReputations = new Map<string, Record<string, unknown>>();
  readonly #decisionReceiptKeys = new Map<string, Record<string, unknown>>();
  readonly #pendingDecisions: Record<string, unknown>[] = [];
  readonly #pendingDecisionOutbox: Record<string, unknown>[] = [];
  readonly #pendingQuarantinePins: Record<string, unknown>[] = [];
  #decisionOutboxSeq = 1;
  #inTransaction = false;
  readonly #tenantPricingPlans = new Map<string, Record<string, unknown>>();
  readonly #billingRollups = new Map<string, Record<string, unknown>>();
  readonly #billingExports = new Map<string, Record<string, unknown>>();

  constructor(readonly options: { readonly failDecisionOutbox?: boolean } = {}) {}

  async connect(): Promise<SqlLease> {
    this.leases += 1;
    return {
      query: this.query.bind(this),
      release: () => {
        this.releases += 1;
      }
    };
  }

  async query<Row extends Record<string, unknown> = Record<string, unknown>>(text: string, values: readonly unknown[] = []): Promise<SqlQueryResult<Row>> {
    this.sql.push(text);
    const statement = text.trim();
    if (statement === "BEGIN") {
      this.#inTransaction = true;
      this.#pendingDecisions.length = 0;
      this.#pendingDecisionOutbox.length = 0;
      this.#pendingQuarantinePins.length = 0;
      return { rows: [], rowCount: 0 };
    }
    if (statement === "COMMIT") {
      this.#decisions.unshift(...this.#pendingDecisions);
      this.#decisionOutbox.push(...this.#pendingDecisionOutbox);
      this.#quarantinePins.unshift(...this.#pendingQuarantinePins);
      this.#pendingDecisions.length = 0;
      this.#pendingDecisionOutbox.length = 0;
      this.#pendingQuarantinePins.length = 0;
      this.#inTransaction = false;
      return { rows: [], rowCount: 0 };
    }
    if (statement === "ROLLBACK") {
      this.#pendingDecisions.length = 0;
      this.#pendingDecisionOutbox.length = 0;
      this.#pendingQuarantinePins.length = 0;
      this.#inTransaction = false;
      return { rows: [], rowCount: 0 };
    }
    if (text.includes("pg_notify")) {
      return { rows: [], rowCount: 1 };
    }
    if (statement === "LOCK TABLE decision_outbox IN EXCLUSIVE MODE") {
      return { rows: [], rowCount: 0 };
    }
    if (statement === "LISTEN aidenid_decision_outbox" || statement === "UNLISTEN aidenid_decision_outbox") {
      return { rows: [], rowCount: 0 };
    }
    if (text.includes("INSERT INTO tenant_quotas")) {
      const row = {
        tenant_id: values[0],
        monthly_decision_limit: values[1],
        stored_decision_limit: values[2],
        target_limit: values[3],
        updated_at: values[4]
      };
      this.#tenantQuotas.set(String(values[0]), row);
      return { rows: rowsAs<Row>([row]), rowCount: 1 };
    }
    if (text.includes("FROM tenant_quotas")) {
      const row = this.#tenantQuotas.get(String(values[0]));
      return { rows: row === undefined ? [] : rowsAs<Row>([row]), rowCount: row === undefined ? 0 : 1 };
    }
    if (text.includes("INSERT INTO tenant_pricing_plans")) {
      const row = {
        tenant_id: values[0],
        plan_tier: values[1],
        currency: values[2],
        unit_price_usd: values[3],
        included_monthly_cleared_decisions: values[4],
        effective_from: values[5],
        updated_at: values[6]
      };
      this.#tenantPricingPlans.set(String(values[0]), row);
      return { rows: rowsAs<Row>([row]), rowCount: 1 };
    }
    if (text.includes("FROM tenant_pricing_plans")) {
      const row = this.#tenantPricingPlans.get(String(values[0]));
      return { rows: row === undefined ? [] : rowsAs<Row>([row]), rowCount: row === undefined ? 0 : 1 };
    }
    if (text.includes("INSERT INTO decision_receipt_keys")) {
      const existing = this.#decisionReceiptKeys.get(String(values[0]));
      const row = {
        kid: values[0],
        issuer: values[1],
        alg: values[2],
        public_jwk: JSON.parse(String(values[3])) as Record<string, unknown>,
        jwk_thumbprint_sha256: values[4],
        state: values[5],
        activated_at: values[6],
        retire_after: values[7],
        retired_at: values[8],
        rotation_reason: values[9],
        created_at: existing?.created_at ?? values[10],
        updated_at: values[10]
      };
      this.#decisionReceiptKeys.set(String(values[0]), row);
      return { rows: rowsAs<Row>([row]), rowCount: 1 };
    }
    if (text.includes("UPDATE decision_receipt_keys")) {
      const existing = this.#decisionReceiptKeys.get(String(values[0]));
      if (existing === undefined) {
        return { rows: [], rowCount: 0 };
      }
      const row = {
        ...existing,
        state: "retired",
        retired_at: values[1],
        rotation_reason: values[2] ?? existing.rotation_reason,
        updated_at: values[1]
      };
      this.#decisionReceiptKeys.set(String(values[0]), row);
      return { rows: rowsAs<Row>([row]), rowCount: 1 };
    }
    if (text.includes("FROM decision_receipt_keys")) {
      if (text.includes("WHERE kid = $1")) {
        const row = this.#decisionReceiptKeys.get(String(values[0]));
        return { rows: row === undefined ? [] : rowsAs<Row>([row]), rowCount: row === undefined ? 0 : 1 };
      }
      if (text.includes("WHERE issuer = $1")) {
        const now = String(values[1]);
        const row = [...this.#decisionReceiptKeys.values()]
          .filter((record) => record.issuer === values[0] && record.state === "active")
          .filter((record) => record.retire_after === null || record.retire_after === undefined || String(record.retire_after) > now)
          .sort((left, right) => String(right.activated_at).localeCompare(String(left.activated_at)))
          .at(0);
        return { rows: row === undefined ? [] : rowsAs<Row>([row]), rowCount: row === undefined ? 0 : 1 };
      }
      const limit = Number(values[0] ?? 100);
      const rows = [...this.#decisionReceiptKeys.values()]
        .sort((left, right) => String(right.activated_at).localeCompare(String(left.activated_at)))
        .slice(0, limit);
      return { rows: rowsAs<Row>(rows), rowCount: rows.length };
    }
    if (text.includes("INSERT INTO billing_period_rollups")) {
      const row = {
        id: values[0],
        tenant_id: values[1],
        period_start: values[2],
        period_end: values[3],
        plan_tier: values[4],
        currency: values[5],
        unit_price_usd: values[6],
        included_cleared_decisions: values[7],
        cleared_decision_count: values[8],
        billable_cleared_decision_count: values[9],
        overage_cleared_decision_count: values[10],
        estimated_cost_usd: values[11],
        price_required_gross_usd: values[12],
        invoice_line_item_id: values[13],
        export_idempotency_key: values[14],
        generated_at: values[15]
      };
      this.#billingRollups.set(`${String(values[1])}\0${String(values[2])}\0${String(values[3])}`, row);
      return { rows: rowsAs<Row>([row]), rowCount: 1 };
    }
    if (text.includes("INSERT INTO billing_exports")) {
      const existing = this.#billingExports.get(String(values[0]));
      const row = {
        id: values[0],
        rollup_id: values[1],
        tenant_id: values[2],
        period_start: values[3],
        period_end: values[4],
        provider: values[5],
        destination_ref: values[6],
        idempotency_key: values[7],
        payload_sha256: values[8],
        payload: JSON.parse(String(values[9])) as Record<string, unknown>,
        status: existing?.status === "delivered" ? existing.status : values[10],
        created_at: existing?.created_at ?? values[11],
        updated_at: values[11],
        delivered_at: existing?.delivered_at ?? values[12],
        provider_receipt_id: existing?.provider_receipt_id ?? values[13],
        provider_receipt_status: existing?.provider_receipt_status ?? values[14],
        provider_receipt_payload_sha256: existing?.provider_receipt_payload_sha256 ?? values[15],
        provider_receipt_recorded_at: existing?.provider_receipt_recorded_at ?? values[16]
      };
      this.#billingExports.set(String(values[0]), row);
      return { rows: rowsAs<Row>([row]), rowCount: 1 };
    }
    if (text.includes("UPDATE billing_exports") && text.includes("provider_receipt_id")) {
      const existing = this.#billingExports.get(String(values[0]));
      if (existing === undefined) {
        return { rows: [], rowCount: 0 };
      }
      const row = {
        ...existing,
        status: "delivered",
        delivered_at: values[1],
        provider_receipt_id: values[2],
        provider_receipt_status: values[3],
        provider_receipt_payload_sha256: values[4],
        provider_receipt_recorded_at: values[5],
        updated_at: values[5]
      };
      this.#billingExports.set(String(values[0]), row);
      return { rows: rowsAs<Row>([row]), rowCount: 1 };
    }
    if (text.includes("FROM billing_exports")) {
      if (text.includes("WHERE id = $1")) {
        const row = this.#billingExports.get(String(values[0]));
        return { rows: row === undefined ? [] : rowsAs<Row>([row]), rowCount: row === undefined ? 0 : 1 };
      }
      let valueIndex = 0;
      let rows = [...this.#billingExports.values()];
      if (text.includes("tenant_id = $")) {
        const tenantId = String(values[valueIndex]);
        valueIndex += 1;
        rows = rows.filter((record) => record.tenant_id === tenantId);
      }
      if (text.includes("provider = $")) {
        const provider = String(values[valueIndex]);
        valueIndex += 1;
        rows = rows.filter((record) => record.provider === provider);
      }
      if (text.includes("status = $")) {
        const status = String(values[valueIndex]);
        valueIndex += 1;
        rows = rows.filter((record) => record.status === status);
      }
      if (text.includes("period_start = $")) {
        const periodStart = String(values[valueIndex]);
        valueIndex += 1;
        rows = rows.filter((record) => record.period_start === periodStart);
      }
      if (text.includes("period_end = $")) {
        const periodEnd = String(values[valueIndex]);
        valueIndex += 1;
        rows = rows.filter((record) => record.period_end === periodEnd);
      }
      const limit = Number(values.at(-1));
      rows = rows.sort((left, right) => String(right.created_at).localeCompare(String(left.created_at))).slice(0, limit);
      return { rows: rowsAs<Row>(rows), rowCount: rows.length };
    }
    if (text.includes("FROM billing_period_rollups")) {
      const row = this.#billingRollups.get(`${String(values[0])}\0${String(values[1])}\0${String(values[2])}`);
      return { rows: row === undefined ? [] : rowsAs<Row>([row]), rowCount: row === undefined ? 0 : 1 };
    }
    if (text.includes("WHERE tenant_id = $1 AND occurred_at >= $2 AND occurred_at < $3")) {
      const rows = this.#decisions
        .filter(
          (decision) =>
            decision.tenant_id === values[0] && String(decision.occurred_at) >= String(values[1]) && String(decision.occurred_at) < String(values[2])
        )
        .sort((left, right) => String(right.occurred_at).localeCompare(String(left.occurred_at)))
        .slice(0, Number(values[3]));
      return { rows: rowsAs<Row>(rows), rowCount: rows.length };
    }
    if (text.includes("SELECT count(*) AS count FROM decisions WHERE tenant_id = $1")) {
      const count = [...this.#decisions, ...this.#pendingDecisions].filter((decision) => decision.tenant_id === values[0]).length;
      return { rows: rowsAs<Row>([{ count }]), rowCount: 1 };
    }
    if (text.includes("INSERT INTO decisions")) {
      const row = {
        id: values[0],
        tenant_id: values[1],
        site_id: values[2],
        request_id: values[3],
        actor_class: values[4],
        decision: values[5],
        recommended_decision: values[6],
        route_template: values[7],
        method: values[8],
        occurred_at: values[9],
        latency_us: values[10],
        subject_handle: values[11],
        issuer: values[12],
        llm_brand: values[13],
        purpose: values[14],
        price_usd: values[15],
        suspicion_score: values[16],
        reason_codes: values[17],
        cascade_trace: values[18],
        receipt_jws: values[19],
        receipt_key_id: values[20],
        receipt_public_jwk: values[21],
        receipt_payload_sha256: values[22],
        receipt_jws_sha256: values[23],
        transparency_leaf_hash: values[24],
        transparency_leaf_index: values[25],
        transparency_checkpoint: values[26],
        transparency_inclusion_proof: values[27],
        operator_action: values[28],
        operator_action_actor_id: values[29],
        operator_action_reason: values[30],
        operator_action_at: values[31],
        operator_action_effective_decision: values[32],
        operator_action_expires_at: values[33],
        operator_action_effects: values[34]
      };
      if (this.#inTransaction) {
        this.#pendingDecisions.push(row);
      } else {
        this.#decisions.unshift(row);
      }
      return { rows: [], rowCount: 1 };
    }
    if (text.includes("UPDATE decisions")) {
      const row = this.#decisions.find((decision) => decision.id === values[0]);
      if (row === undefined) {
        return { rows: [], rowCount: 0 };
      }
      row.operator_action = values[1];
      row.operator_action_actor_id = values[2];
      row.operator_action_reason = values[3];
      row.operator_action_at = values[4];
      row.operator_action_effective_decision = values[5];
      row.operator_action_expires_at = values[6];
      row.operator_action_effects = values[7];
      return { rows: rowsAs<Row>([row]), rowCount: 1 };
    }
    if (text.includes("INSERT INTO quarantine_pins")) {
      const row = {
        id: values[0],
        decision_id: values[1],
        site_id: values[2],
        actor_class: values[3],
        issuer: values[4],
        subject_handle: values[5],
        request_id: values[6],
        operator_actor_id: values[7],
        reason: values[8],
        expires_at: values[9],
        created_at: values[10]
      };
      const existingIndex = this.#quarantinePins.findIndex((pin) => pin.decision_id === row.decision_id);
      if (existingIndex >= 0) {
        this.#quarantinePins[existingIndex] = row;
      } else if (this.#inTransaction) {
        this.#pendingQuarantinePins.push(row);
      } else {
        this.#quarantinePins.unshift(row);
      }
      return { rows: [], rowCount: 1 };
    }
    if (text.includes("INSERT INTO decision_outbox")) {
      if (this.options.failDecisionOutbox === true) {
        throw new Error("forced decision outbox failure");
      }
      const row = {
        seq: this.#decisionOutboxSeq,
        decision_id: values[0],
        occurred_at: "2026-04-25T00:00:00.000Z",
        event_type: values[1],
        payload: JSON.parse(String(values[2])) as Record<string, unknown>,
        previous_hash: values[3],
        entry_hash: values[4]
      };
      this.#decisionOutboxSeq += 1;
      if (this.#inTransaction) {
        this.#pendingDecisionOutbox.push(row);
      } else {
        this.#decisionOutbox.push(row);
      }
      return { rows: rowsAs<Row>([row]), rowCount: 1 };
    }
    if (text.includes("COALESCE(MAX(seq)")) {
      return { rows: rowsAs<Row>([{ seq: this.#decisionOutboxSeq - 1 }]), rowCount: 1 };
    }
    if (text.includes("SELECT entry_hash") && text.includes("FROM decision_outbox")) {
      const row = [...this.#decisionOutbox].sort((left, right) => Number(right.seq) - Number(left.seq)).find((event) => event.entry_hash !== null && event.entry_hash !== undefined);
      return { rows: row === undefined ? [] : rowsAs<Row>([{ entry_hash: row.entry_hash }]), rowCount: row === undefined ? 0 : 1 };
    }
    if (text.includes("FROM decision_outbox")) {
      const afterSeq = Number(values[0] ?? 0);
      const limit = Number(values[1] ?? 100);
      const rows = this.#decisionOutbox.filter((row) => Number(row.seq) > afterSeq).sort((left, right) => Number(left.seq) - Number(right.seq)).slice(0, limit);
      return { rows: rowsAs<Row>(rows), rowCount: rows.length };
    }
    if (text.includes("DELETE FROM decision_outbox")) {
      const before = this.#decisionOutbox.length;
      for (let index = this.#decisionOutbox.length - 1; index >= 0; index -= 1) {
        const row = this.#decisionOutbox[index];
        if (row !== undefined && String(row.occurred_at) < String(values[0])) {
          this.#decisionOutbox.splice(index, 1);
        }
      }
      return { rows: [], rowCount: before - this.#decisionOutbox.length };
    }
    if (text.includes("DELETE FROM decisions")) {
      const before = this.#decisions.length;
      for (let index = this.#decisions.length - 1; index >= 0; index -= 1) {
        const row = this.#decisions[index];
        if (row !== undefined && row.site_id === values[0] && row.subject_handle === values[1]) {
          this.#decisions.splice(index, 1);
        }
      }
      return { rows: [], rowCount: before - this.#decisions.length };
    }
    if (text.includes("FROM decisions")) {
      if (text.includes("WHERE id = $1")) {
        const row = this.#decisions.find((decision) => decision.id === values[0]);
        return { rows: row === undefined ? [] : rowsAs<Row>([row]), rowCount: row === undefined ? 0 : 1 };
      }
      const hasSiteFilter = text.includes("WHERE site_id = $1");
      const siteId = String(values[0]);
      const limit = Number(hasSiteFilter ? (values[1] ?? 100) : (values[0] ?? 100));
      const rows = (hasSiteFilter ? this.#decisions.filter((row) => row.site_id === siteId) : this.#decisions).slice(0, limit);
      return { rows: rowsAs<Row>(rows), rowCount: rows.length };
    }
    if (text.includes("FROM quarantine_pins")) {
      const hasSiteFilter = text.includes("WHERE site_id = $1");
      const siteId = String(values[0]);
      const limit = Number(hasSiteFilter ? (values[1] ?? 100) : (values[0] ?? 100));
      const rows = (hasSiteFilter ? this.#quarantinePins.filter((row) => row.site_id === siteId) : this.#quarantinePins).slice(0, limit);
      return { rows: rowsAs<Row>(rows), rowCount: rows.length };
    }
    if (text.includes("INSERT INTO privacy_erasure_requests")) {
      const row = {
        id: values[0],
        site_id: values[1],
        subject_handle: values[2],
        reason: values[3],
        actor_id: values[4],
        erased_decision_count: values[5],
        occurred_at: values[6]
      };
      this.#privacyErasures.unshift(row);
      return { rows: rowsAs<Row>([row]), rowCount: 1 };
    }
    if (text.includes("FROM privacy_erasure_requests")) {
      const rows = this.#privacyErasures.filter((row) => row.site_id === values[0]).slice(0, Number(values[1] ?? 100));
      return { rows: rowsAs<Row>(rows), rowCount: rows.length };
    }
    if (text.includes("INSERT INTO webhook_endpoints")) {
      const existing = [...this.#webhookEndpoints.values()].find((row) => row.tenant_id === values[1] && row.url === values[2]);
      const row = {
        id: existing?.id ?? values[0],
        tenant_id: values[1],
        url: values[2],
        event_types: values[3],
        signing_secret_ref: values[4],
        created_at: existing?.created_at ?? values[5],
        updated_at: values[5]
      };
      this.#webhookEndpoints.set(String(row.id), row);
      return { rows: rowsAs<Row>([row]), rowCount: 1 };
    }
    if (text.includes("FROM webhook_endpoints")) {
      const rows = [...this.#webhookEndpoints.values()].filter((row) => row.tenant_id === values[0]);
      return { rows: rowsAs<Row>(rows), rowCount: rows.length };
    }
    if (text.includes("UPDATE operator_reputation") && text.includes("status = 'expired'")) {
      const siteId = values.length > 1 ? values[0] : undefined;
      const now = String(values.length > 1 ? values[1] : values[0]);
      for (const [key, row] of this.#operatorReputations.entries()) {
        const expiresAt = row.expires_at === undefined || row.expires_at === null ? undefined : Date.parse(String(row.expires_at));
        if (
          (siteId === undefined || row.site_id === siteId) &&
          expiresAt !== undefined &&
          expiresAt <= Date.parse(now) &&
          row.status !== "expired"
        ) {
          this.#operatorReputations.set(key, { ...row, status: "expired", updated_at: now });
        }
      }
      return { rows: rowsAs<Row>([]), rowCount: 0 };
    }
    if (text.includes("INSERT INTO operator_reputation")) {
      const key = `${String(values[1])}\0${String(values[2])}`;
      const existing = this.#operatorReputations.get(key);
      const row = {
        id: existing?.id ?? values[0],
        site_id: values[1],
        operator_actor_id: values[2],
        display_name: values[3],
        trust_tier: values[4],
        status: values[5],
        reputation_score: values[6],
        default_action: values[7],
        default_scope_routes: values[8],
        default_scope_redirect_path: values[9],
        notes: values[10],
        last_reviewed_at: values[11],
        expires_at: values[12],
        updated_by: values[13],
        created_at: existing?.created_at ?? values[14],
        updated_at: values[14]
      };
      this.#operatorReputations.set(key, row);
      return { rows: rowsAs<Row>([row]), rowCount: 1 };
    }
    if (text.includes("FROM operator_reputation")) {
      const rows = [...this.#operatorReputations.values()].filter((row) => {
        if (row.site_id !== values[0]) return false;
        if (text.includes("operator_actor_id = $2")) return row.operator_actor_id === values[1];
        if (text.includes("status = $2") && row.status !== values[1]) return false;
        if (text.includes("trust_tier = $2") && row.trust_tier !== values[1]) return false;
        if (text.includes("trust_tier = $3") && row.trust_tier !== values[2]) return false;
        return true;
      });
      const limit = Number(values[values.length - 1] ?? 100);
      return { rows: rowsAs<Row>(rows.slice(0, Number.isFinite(limit) ? limit : 100)), rowCount: rows.length };
    }
    throw new Error(`unexpected SQL in test client: ${text}`);
  }
}

class NotificationSqlClient implements SqlClient {
  readonly sql: string[] = [];
  notificationListener: ((message: SqlNotification) => void) | undefined;
  notificationsDelivered = 0;
  releases = 0;

  constructor(readonly options: { readonly notifyDuringOutboxRead?: boolean } = {}) {}

  async connect(): Promise<SqlLease> {
    return {
      query: this.query.bind(this),
      on: (event: "notification" | "error", listener: ((message: SqlNotification) => void) | ((error: Error) => void)) => {
        if (event === "notification") {
          this.notificationListener = listener as (message: SqlNotification) => void;
        }
      },
      off: (event: "notification" | "error") => {
        if (event === "notification") {
          this.notificationListener = undefined;
        }
      },
      release: () => {
        this.releases += 1;
      }
    };
  }

  async query<Row extends Record<string, unknown> = Record<string, unknown>>(text: string): Promise<SqlQueryResult<Row>> {
    this.sql.push(text);
    if (this.options.notifyDuringOutboxRead === true && text.includes("FROM decision_outbox") && this.notificationListener !== undefined) {
      this.notificationsDelivered += 1;
      this.notificationListener({ channel: "aidenid_decision_outbox", payload: "42" });
    }
    return { rows: [], rowCount: 0 };
  }
}

class PollingWaitSqlClient implements SqlClient {
  readonly sql: string[] = [];
  outboxReads = 0;
  releases = 0;

  async connect(): Promise<SqlLease> {
    return {
      query: this.query.bind(this),
      release: () => {
        this.releases += 1;
      }
    };
  }

  async query<Row extends Record<string, unknown> = Record<string, unknown>>(text: string): Promise<SqlQueryResult<Row>> {
    this.sql.push(text);
    if (text.includes("FROM decision_outbox")) {
      this.outboxReads += 1;
      const rows =
        this.outboxReads < 2
          ? []
          : rowsAs<Row>([
              {
                seq: 42,
                decision_id: "dec_polling_wait_1",
                occurred_at: "2026-04-25T00:00:00.000Z",
                event_type: "recorded",
                payload: { request_id: "req_polling_wait_1" }
              }
            ]);
      return { rows, rowCount: rows.length };
    }
    return { rows: [], rowCount: 0 };
  }
}

function createSlowDecisionOutboxStore() {
  const store = new InMemoryControlPlaneStore();
  const stats = { activeReads: 0, maxConcurrentReads: 0, reads: 0 };
  const listDecisionOutboxAfter = store.listDecisionOutboxAfter.bind(store);
  const overrides = store as unknown as {
    listDecisionOutboxAfter(seq: number, limit?: number): Promise<ReturnType<InMemoryControlPlaneStore["listDecisionOutboxAfter"]>>;
    waitForDecisionOutboxAfter(seq: number, timeoutMs: number): Promise<void>;
  };
  overrides.listDecisionOutboxAfter = async (seq: number, limit = 100) => {
    stats.reads += 1;
    stats.activeReads += 1;
    stats.maxConcurrentReads = Math.max(stats.maxConcurrentReads, stats.activeReads);
    try {
      await delay(275);
      return listDecisionOutboxAfter(seq, limit);
    } finally {
      stats.activeReads -= 1;
    }
  };
  overrides.waitForDecisionOutboxAfter = async () => {
    await delay(5);
  };
  return { store, stats };
}

const decisionForTest = (id: string): Parameters<PostgresControlPlaneStore["recordDecisionWithOutbox"]>[0] => ({
  id,
  siteId: "sit_pg",
  requestId: `req_${id}`,
  actorClass: "unknown",
  decision: "deny",
  routeTemplate: "/benefits/PHI/*",
  method: "GET",
  occurredAt: "2026-04-25T00:00:00.000Z"
});

class MigrationTestClient implements SqlClient {
  readonly sql: Array<{ readonly text: string; readonly values: readonly unknown[] }> = [];
  readonly migrations = new Map<string, string>();
  releases = 0;

  async connect(): Promise<SqlLease> {
    return {
      query: this.query.bind(this),
      release: () => {
        this.releases += 1;
      }
    };
  }

  async query<Row extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values: readonly unknown[] = []
  ): Promise<SqlQueryResult<Row>> {
    this.sql.push({ text, values });
    const statement = text.trim();
    if (statement.startsWith("SELECT filename, checksum_sha256 FROM schema_migrations")) {
      const filename = String(values[0]);
      const checksum = this.migrations.get(filename);
      return {
        rows:
          checksum === undefined
            ? []
            : rowsAs<Row>([
                {
                  filename,
                  checksum_sha256: checksum
                }
              ]),
        rowCount: checksum === undefined ? 0 : 1
      };
    }
    if (statement.startsWith("INSERT INTO schema_migrations")) {
      this.migrations.set(String(values[0]), String(values[1]));
      return { rows: [], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  }
}

describe("control plane API", () => {
  it("fails closed on production startup without a persistent control-plane store", async () => {
    const previous = {
      nodeEnv: process.env.NODE_ENV,
      databaseUrl: process.env.DATABASE_URL,
      controlPlaneDatabaseUrl: process.env.AIDENID_CONTROL_PLANE_DATABASE_URL,
      controlPlaneDatabaseHost: process.env.AIDENID_CONTROL_PLANE_DATABASE_HOST,
      controlPlaneDatabasePassword: process.env.AIDENID_CONTROL_PLANE_DATABASE_PASSWORD,
      allowEphemeralStore: process.env.AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE,
      allowInMemoryOutbox: process.env.AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX,
      allowEphemeralDecisionReceiptKey: process.env.AIDENID_ALLOW_EPHEMERAL_DECISION_RECEIPT_KEY,
      redisHost: process.env.AIDENID_REDIS_HOST,
      redisAuthToken: process.env.AIDENID_REDIS_AUTH_TOKEN
    };
    try {
      process.env.NODE_ENV = "production";
      delete process.env.DATABASE_URL;
      delete process.env.AIDENID_CONTROL_PLANE_DATABASE_URL;
      delete process.env.AIDENID_CONTROL_PLANE_DATABASE_HOST;
      delete process.env.AIDENID_CONTROL_PLANE_DATABASE_PASSWORD;
      delete process.env.AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE;
      delete process.env.AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX;
      delete process.env.AIDENID_REDIS_HOST;
      delete process.env.AIDENID_REDIS_AUTH_TOKEN;

      await expect(createControlPlaneRuntime()).rejects.toThrow(/DATABASE_URL.*split AIDENID_CONTROL_PLANE_DATABASE_\*/);

      process.env.AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE = "true";
      process.env.AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX = "true";
      process.env.AIDENID_ALLOW_EPHEMERAL_DECISION_RECEIPT_KEY = "true";
      const runtime = await createControlPlaneRuntime();
      expect(runtime.services.store).toBeDefined();
      await runtime.app.close();
    } finally {
      if (previous.nodeEnv === undefined) {
        delete process.env.NODE_ENV;
      } else {
        process.env.NODE_ENV = previous.nodeEnv;
      }
      if (previous.databaseUrl === undefined) {
        delete process.env.DATABASE_URL;
      } else {
        process.env.DATABASE_URL = previous.databaseUrl;
      }
      if (previous.controlPlaneDatabaseUrl === undefined) {
        delete process.env.AIDENID_CONTROL_PLANE_DATABASE_URL;
      } else {
        process.env.AIDENID_CONTROL_PLANE_DATABASE_URL = previous.controlPlaneDatabaseUrl;
      }
      if (previous.controlPlaneDatabaseHost === undefined) {
        delete process.env.AIDENID_CONTROL_PLANE_DATABASE_HOST;
      } else {
        process.env.AIDENID_CONTROL_PLANE_DATABASE_HOST = previous.controlPlaneDatabaseHost;
      }
      if (previous.controlPlaneDatabasePassword === undefined) {
        delete process.env.AIDENID_CONTROL_PLANE_DATABASE_PASSWORD;
      } else {
        process.env.AIDENID_CONTROL_PLANE_DATABASE_PASSWORD = previous.controlPlaneDatabasePassword;
      }
      if (previous.allowEphemeralStore === undefined) {
        delete process.env.AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE;
      } else {
        process.env.AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE = previous.allowEphemeralStore;
      }
      if (previous.allowInMemoryOutbox === undefined) {
        delete process.env.AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX;
      } else {
        process.env.AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX = previous.allowInMemoryOutbox;
      }
      if (previous.allowEphemeralDecisionReceiptKey === undefined) {
        delete process.env.AIDENID_ALLOW_EPHEMERAL_DECISION_RECEIPT_KEY;
      } else {
        process.env.AIDENID_ALLOW_EPHEMERAL_DECISION_RECEIPT_KEY = previous.allowEphemeralDecisionReceiptKey;
      }
      if (previous.redisHost === undefined) {
        delete process.env.AIDENID_REDIS_HOST;
      } else {
        process.env.AIDENID_REDIS_HOST = previous.redisHost;
      }
      if (previous.redisAuthToken === undefined) {
        delete process.env.AIDENID_REDIS_AUTH_TOKEN;
      } else {
        process.env.AIDENID_REDIS_AUTH_TOKEN = previous.redisAuthToken;
      }
    }
  });

  it("fails closed on production startup without a durable generic outbox", async () => {
    const previous = {
      nodeEnv: process.env.NODE_ENV,
      allowEphemeralStore: process.env.AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE,
      allowInMemoryOutbox: process.env.AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX,
      redisHost: process.env.AIDENID_REDIS_HOST,
      redisAuthToken: process.env.AIDENID_REDIS_AUTH_TOKEN
    };
    try {
      process.env.NODE_ENV = "production";
      process.env.AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE = "true";
      delete process.env.AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX;
      delete process.env.AIDENID_REDIS_HOST;
      delete process.env.AIDENID_REDIS_AUTH_TOKEN;

      await expect(createControlPlaneRuntime()).rejects.toThrow(/AIDENID_REDIS_HOST.*control-plane outbox/);

      process.env.AIDENID_REDIS_HOST = "redis.example.test";
      await expect(createControlPlaneRuntime()).rejects.toThrow(/AIDENID_REDIS_AUTH_TOKEN.*production/);
    } finally {
      if (previous.nodeEnv === undefined) {
        delete process.env.NODE_ENV;
      } else {
        process.env.NODE_ENV = previous.nodeEnv;
      }
      if (previous.allowEphemeralStore === undefined) {
        delete process.env.AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE;
      } else {
        process.env.AIDENID_ALLOW_EPHEMERAL_CONTROL_PLANE_STORE = previous.allowEphemeralStore;
      }
      if (previous.allowInMemoryOutbox === undefined) {
        delete process.env.AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX;
      } else {
        process.env.AIDENID_ALLOW_IN_MEMORY_CONTROL_PLANE_OUTBOX = previous.allowInMemoryOutbox;
      }
      if (previous.redisHost === undefined) {
        delete process.env.AIDENID_REDIS_HOST;
      } else {
        process.env.AIDENID_REDIS_HOST = previous.redisHost;
      }
      if (previous.redisAuthToken === undefined) {
        delete process.env.AIDENID_REDIS_AUTH_TOKEN;
      } else {
        process.env.AIDENID_REDIS_AUTH_TOKEN = previous.redisAuthToken;
      }
    }
  });

  it("builds a Postgres URL from split control-plane database environment", () => {
    expect(
      controlPlaneDatabaseUrlFromEnvironment({
        AIDENID_CONTROL_PLANE_DATABASE_HOST: "postgres.internal",
        AIDENID_CONTROL_PLANE_DATABASE_PORT: "6543",
        AIDENID_CONTROL_PLANE_DATABASE_NAME: "aidenid_clearance",
        AIDENID_CONTROL_PLANE_DATABASE_USER: "aidenid",
        AIDENID_CONTROL_PLANE_DATABASE_PASSWORD: "p@ss word",
        AIDENID_CONTROL_PLANE_DATABASE_SSLMODE: "verify-full",
        AIDENID_CONTROL_PLANE_DATABASE_SSLROOTCERT: "/app/certs/rds-global-bundle.pem"
      })
    ).toBe(
      "postgresql://aidenid:p%40ss%20word@postgres.internal:6543/aidenid_clearance?sslmode=verify-full&sslrootcert=%2Fapp%2Fcerts%2Frds-global-bundle.pem"
    );
    expect(
      controlPlaneDatabaseUrlFromEnvironment({
        AIDENID_CONTROL_PLANE_DATABASE_URL: "postgresql://explicit",
        AIDENID_CONTROL_PLANE_DATABASE_HOST: "ignored"
      })
    ).toBe("postgresql://explicit");
    expect(() => controlPlaneDatabaseUrlFromEnvironment({ AIDENID_CONTROL_PLANE_DATABASE_HOST: "postgres.internal" })).toThrow(
      /requires AIDENID_CONTROL_PLANE_DATABASE_HOST and _PASSWORD/
    );
  });

  it("runs control-plane migrations under an advisory lock and records checksums", async () => {
    const dir = mkdtempSync(join(tmpdir(), "aidenid-control-plane-migrations-"));
    try {
      writeFileSync(join(dir, "0002_second.sql"), "CREATE TABLE second(id text PRIMARY KEY);\n", "utf8");
      writeFileSync(join(dir, "0001_first.sql"), "CREATE TABLE first(id text PRIMARY KEY);\n", "utf8");
      const client = new MigrationTestClient();

      const first = await runControlPlaneMigrations(client, { migrationsDirectory: dir });
      const second = await runControlPlaneMigrations(client, { migrationsDirectory: dir });

      expect(first).toEqual({ applied: ["0001_first", "0002_second"], skipped: [] });
      expect(second).toEqual({ applied: [], skipped: ["0001_first", "0002_second"] });
      expect(client.migrations.size).toBe(2);
      expect([...client.migrations.values()]).toEqual([
        expect.stringMatching(/^[a-f0-9]{64}$/),
        expect.stringMatching(/^[a-f0-9]{64}$/)
      ]);
      expect(client.releases).toBe(2);
      const statements = client.sql.map((entry) => entry.text.trim());
      const schemaTableStatement = statements.find((statement) =>
        statement.startsWith("CREATE TABLE IF NOT EXISTS schema_migrations")
      );
      expect(schemaTableStatement).toBeDefined();
      expect(schemaTableStatement).toContain("id bigserial PRIMARY KEY");
      expect(schemaTableStatement).toContain("filename text NOT NULL UNIQUE");
      expect(schemaTableStatement).toContain("applied_by text NOT NULL");
      expect(statements).toContain("SELECT set_config('lock_timeout', $1, false)");
      expect(statements).toContain("SELECT set_config('lock_timeout', '0', false)");
      expect(statements).toContain("SELECT pg_advisory_lock($1, $2)");
      expect(statements).toContain("SELECT pg_advisory_unlock($1, $2)");
      expect(statements.indexOf("SELECT pg_advisory_lock($1, $2)")).toBeLessThan(
        statements.indexOf(schemaTableStatement ?? "")
      );
      expect(statements.indexOf(schemaTableStatement ?? "")).toBeLessThan(
        statements.indexOf("CREATE TABLE first(id text PRIMARY KEY);")
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses to run a changed control-plane migration after checksum drift", async () => {
    const dir = mkdtempSync(join(tmpdir(), "aidenid-control-plane-migrations-"));
    try {
      writeFileSync(join(dir, "0001_first.sql"), "CREATE TABLE first(id text PRIMARY KEY);\n", "utf8");
      const client = new MigrationTestClient();
      client.migrations.set("0001_first.sql", "0".repeat(64));

      await expect(runControlPlaneMigrations(client, { migrationsDirectory: dir })).rejects.toThrow(
        /migration checksum mismatch/
      );
      const statements = client.sql.map((entry) => entry.text.trim());
      expect(statements).toContain("SELECT pg_advisory_unlock($1, $2)");
      expect(client.releases).toBe(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("adds request ids to explicit and default API error envelopes", async () => {
    // Authenticated on purpose: this asserts the APPLICATION error envelope
    // (invalid_target) carries the request id, so the request has to get past the
    // operator gate to reach body validation at all.
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });
    const explicit = await runtime.app.inject({
      method: "POST",
      url: "/v1/targets",
      headers: { "x-request-id": "req_external_1", ...TEST_ADMIN_HEADERS },
      payload: {}
    });
    expect(explicit.statusCode).toBe(400);
    expect(explicit.headers["x-request-id"]).toBe("req_external_1");
    expect(explicit.json()).toMatchObject({
      error: "invalid_target",
      request_id: "req_external_1",
      requestId: "req_external_1"
    });

    const missing = await runtime.app.inject({
      method: "GET",
      url: "/v1/not-found"
    });
    expect(missing.statusCode).toBe(404);
    const missingBody = missing.json<{ request_id: string; requestId: string }>();
    expect(missingBody.request_id).toMatch(/^trc_/);
    expect(missingBody.requestId).toBe(missingBody.request_id);
    expect(missing.headers["x-request-id"]).toBe(missingBody.request_id);
    await runtime.app.close();
  });

  it("registers a target, grants delegation, issues a downscoped session, and revokes the chain", async () => {
    const runtime = await createControlPlaneRuntime({ sessionTtlSeconds: 60, operatorAuth: TEST_OPERATOR_AUTH });
    const targetResponse = await runtime.app.inject({
      method: "POST",
      url: "/v1/targets",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        tenant_id: "ten_demo",
        site_id: "sit_demo",
        name: "Demo Shop",
        origin: "https://shop.example.com"
      }
    });
    expect(targetResponse.statusCode).toBe(201);
    const target = targetResponse.json<{ id: string; site_id: string; origin: string }>();

    const grantResponse = await runtime.app.inject({
      method: "POST",
      url: "/v1/grants",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        target_id: target.id,
        subject: "user_123",
        resource: target.origin,
        permissions: ["checkout:create", "orders:read"],
        expires_in_seconds: 600
      }
    });
    expect(grantResponse.statusCode).toBe(201);
    const grant = grantResponse.json<{ id: string; chain_id: string; permissions: string[] }>();

    const sessionResponse = await runtime.app.inject({
      method: "POST",
      url: "/v1/sessions/exchange",
      payload: {
        grant_id: grant.id,
        audience: target.site_id,
        resource: target.origin,
        proof_jkt: "proof-thumbprint-demo",
        requested_permissions: ["checkout:create"],
        llm_brand: "openai"
      }
    });
    expect(sessionResponse.statusCode).toBe(201);
    const session = sessionResponse.json<{ access_token: string; token_type: string; expires_in: number; revocation_epoch: number }>();
    const decoded = decodeCompactJwt(session.access_token);
    expect(session).toMatchObject({ token_type: "DPoP", expires_in: 60, revocation_epoch: 0 });
    expect(decoded.payload).toMatchObject({
      aud: "sit_demo",
      resource: "https://shop.example.com",
      grant_id: grant.id,
      chain_id: grant.chain_id,
      permissions: ["checkout:create"],
      llm_brand: "openai",
      cnf: { jkt: "proof-thumbprint-demo" }
    });

    const revokeResponse = await runtime.app.inject({
      method: "POST",
      url: "/v1/revoke",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        chain_id: grant.chain_id,
        reason: "user_revoked",
        actor_id: "platform_admin"
      }
    });
    expect(revokeResponse.statusCode).toBe(202);
    expect(revokeResponse.json()).toMatchObject({ chain_id: grant.chain_id, revocation_epoch: 1 });

    const outboxTypes = runtime.outboxStore.all().map((event) => event.type);
    expect(outboxTypes).toEqual(
      expect.arrayContaining(["GRANT_ISSUED_HASH", "SESSION_ISSUED_HASH", "REVOCATION_EPOCH_BUMP", "PERSONA_AUDIT_REQUESTED"])
    );
    expect(runtime.services.personaAudit.list()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          triggerType: "revocation_epoch",
          tool: "create-sentinelayer",
          siteId: target.site_id,
          chainId: grant.chain_id,
          revocationEpoch: 1
        })
      ])
    );
    expect(runtime.services.personaAudit.list(target.site_id)).toHaveLength(1);

    await runtime.app.close();
  });

  it("rejects token exchange that exceeds the grant or changes resource", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });
    const target = (
      await runtime.app.inject({
        method: "POST",
        url: "/v1/targets",
        headers: TEST_ADMIN_HEADERS,
        payload: {
          site_id: "sit_reject",
          name: "Reject Shop",
          origin: "https://reject.example.com"
        }
      })
    ).json<{ id: string; site_id: string; origin: string }>();
    const grant = (
      await runtime.app.inject({
        method: "POST",
        url: "/v1/grants",
        headers: TEST_ADMIN_HEADERS,
        payload: {
          target_id: target.id,
          subject: "user_123",
          permissions: ["orders:read"]
        }
      })
    ).json<{ id: string }>();

    const response = await runtime.app.inject({
      method: "POST",
      url: "/v1/sessions/exchange",
      payload: {
        grant_id: grant.id,
        audience: target.site_id,
        resource: "https://other.example.com",
        proof_jkt: "proof-thumbprint-demo",
        requested_permissions: ["orders:write"]
      }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({ error: "audience_or_resource_mismatch" });
    await runtime.app.close();
  });

  it("requires an admin operator to register a target", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });
    const payload = {
      site_id: "sit_target_gate",
      name: "Target Gate Shop",
      origin: "https://target-gate.example.com"
    };

    const anonymous = await runtime.app.inject({ method: "POST", url: "/v1/targets", payload });
    expect(anonymous.statusCode, "POST /v1/targets must reject anonymous callers").toBe(401);
    expect(anonymous.json()).toMatchObject({ error: "operator_auth_required" });

    // A viewer authenticates but holds only decision_search, so this proves the gate checks
    // the ROLE and is not merely checking that some token was presented.
    const viewer = await runtime.app.inject({
      method: "POST",
      url: "/v1/targets",
      headers: TEST_VIEWER_HEADERS,
      payload
    });
    expect(viewer.statusCode, "POST /v1/targets must reject a non-admin operator").toBe(403);
    expect(viewer.json()).toMatchObject({ error: "operator_forbidden", required_role: "admin" });

    // Nothing above may have registered a site. A status code alone does not prove that.
    expect(await runtime.services.store.countTargets()).toBe(0);

    const admin = await runtime.app.inject({
      method: "POST",
      url: "/v1/targets",
      headers: TEST_ADMIN_HEADERS,
      payload
    });
    expect(admin.statusCode).toBe(201);
    expect(admin.json()).toMatchObject({ site_id: "sit_target_gate" });
    expect(await runtime.services.store.countTargets()).toBe(1);
    await runtime.app.close();

    // Fail closed: with no operator registry configured, target registration is
    // UNAVAILABLE, not open.
    const unconfigured = await createControlPlaneRuntime();
    const denied = await unconfigured.app.inject({ method: "POST", url: "/v1/targets", payload });
    expect(denied.statusCode).toBe(503);
    expect(denied.json()).toMatchObject({ error: "operator_auth_not_configured" });
    await unconfigured.app.close();
  });

  it("binds the issuing operator onto the grant and does not let the caller choose it", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });
    const target = (
      await runtime.app.inject({
        method: "POST",
        url: "/v1/targets",
        headers: TEST_ADMIN_HEADERS,
        payload: {
          site_id: "sit_issuer_bind",
          name: "Issuer Bind Shop",
          origin: "https://issuer-bind.example.com"
        }
      })
    ).json<{ id: string }>();

    const issued = await runtime.app.inject({
      method: "POST",
      url: "/v1/grants",
      headers: TEST_ADMIN_HEADERS,
      payload: { target_id: target.id, subject: "user_123", permissions: ["orders:read"] }
    });
    expect(issued.statusCode).toBe(201);
    // Bound to the AUTHENTICATED principal, not to anything the caller sent.
    expect(issued.json()).toMatchObject({ issuer_actor_id: "platform_admin" });

    // Persisted, not merely echoed in the response.
    const stored = await runtime.services.store.getGrant(issued.json<{ id: string }>().id);
    expect(stored?.issuerActorId).toBe("platform_admin");

    // The transparency record carries the issuer too — an unattributable authority event is
    // weaker evidence than an attributable one.
    const issuedEvents = runtime.outboxStore
      .all()
      .filter((event) => event.type === "GRANT_ISSUED_HASH");
    expect(issuedEvents).toHaveLength(1);
    expect(issuedEvents[0]?.payload).toMatchObject({ issuer_actor_id: "platform_admin" });

    // The caller cannot propose an issuer: the request schema is .strict(), so an attempt to
    // supply one is rejected outright rather than silently ignored. Silently ignoring it
    // would let a caller believe it had attributed the grant to someone else.
    const spoofed = await runtime.app.inject({
      method: "POST",
      url: "/v1/grants",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        target_id: target.id,
        subject: "user_123",
        permissions: ["orders:read"],
        issuer_actor_id: "someone_else"
      }
    });
    expect(spoofed.statusCode, "a caller-supplied issuer must be rejected, not ignored").toBe(400);
    expect(spoofed.json()).toMatchObject({ error: "invalid_grant" });

    await runtime.app.close();
  });

  it("persists the grant issuer through the Postgres store contract", async () => {
    // The in-memory store spreads its input, so it reports an issuer even when the Postgres
    // implementation does not persist one. Every other test in this file runs in memory and
    // would stay green with the SQL path missing entirely — that gap is real: while writing
    // this change I briefly reverted store.ts and the whole 619-test suite still passed.
    // This asserts the SQL the Postgres store actually emits.
    const statements: { text: string; values: readonly unknown[] }[] = [];
    const client: SqlClient = {
      query: async <Row extends Record<string, unknown> = Record<string, unknown>>(
        text: string,
        values: readonly unknown[] = []
      ) => {
        statements.push({ text, values });
        return {
          rows: (text.includes("RETURNING")
            ? ([
                {
                  id: "grt_pg",
                  target_id: "tgt_pg",
                  site_id: "sit_pg",
                  subject: "user_pg",
                  chain_id: "chn_pg",
                  resource: "https://pg.example.com",
                  permissions: ["orders:read"],
                  expires_at: "2026-04-25T01:00:00.000Z",
                  created_at: "2026-04-25T00:00:00.000Z",
                  revoked_at: null,
                  issuer_actor_id: "platform_admin"
                }
              ] as unknown)
            : []) as Row[],
          rowCount: text.includes("RETURNING") ? 1 : 0
        };
      }
    };

    const store = new PostgresControlPlaneStore(client);
    const grant = await store.createGrant({
      targetId: "tgt_pg",
      siteId: "sit_pg",
      subject: "user_pg",
      resource: "https://pg.example.com",
      permissions: ["orders:read"],
      expiresAt: "2026-04-25T01:00:00.000Z",
      issuerActorId: "platform_admin"
    });

    const insert = statements.find((statement) => statement.text.includes("INSERT INTO delegation_grants"));
    expect(insert, "createGrant must issue an INSERT into delegation_grants").toBeDefined();
    expect(
      insert?.text,
      "the INSERT must carry issuer_actor_id, or the issuer is dropped on the way to Postgres"
    ).toContain("issuer_actor_id");
    expect(
      insert?.values,
      "the authenticated actor must be bound as a parameter, not interpolated or omitted"
    ).toContain("platform_admin");
    expect(insert?.text, "the row must be returned with its issuer so reads are consistent").toContain(
      "RETURNING"
    );
    expect(grant.issuerActorId).toBe("platform_admin");
  });

  it("requires an admin operator to create a delegation grant", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });
    const target = (
      await runtime.app.inject({
        method: "POST",
        url: "/v1/targets",
        headers: TEST_ADMIN_HEADERS,
        payload: {
          site_id: "sit_grant_gate",
          name: "Grant Gate Shop",
          origin: "https://grant-gate.example.com"
        }
      })
    ).json<{ id: string }>();
    const payload = {
      target_id: target.id,
      subject: "user_123",
      permissions: ["orders:read"]
    };

    const anonymous = await runtime.app.inject({ method: "POST", url: "/v1/grants", payload });
    expect(anonymous.statusCode, "POST /v1/grants must reject anonymous callers").toBe(401);
    expect(anonymous.json()).toMatchObject({ error: "operator_auth_required" });

    // A viewer token authenticates but holds only decision_search, so this proves the gate
    // checks the role and is not merely checking that some token was presented.
    const viewer = await runtime.app.inject({ method: "POST", url: "/v1/grants", headers: TEST_VIEWER_HEADERS, payload });
    expect(viewer.statusCode, "POST /v1/grants must reject a non-admin operator").toBe(403);
    expect(viewer.json()).toMatchObject({ error: "operator_forbidden", required_role: "admin" });

    // Nothing above may have minted delegation authority.
    expect(runtime.outboxStore.all().map((event) => event.type)).not.toContain("GRANT_ISSUED_HASH");

    const admin = await runtime.app.inject({ method: "POST", url: "/v1/grants", headers: TEST_ADMIN_HEADERS, payload });
    expect(admin.statusCode).toBe(201);
    expect(admin.json()).toMatchObject({ target_id: target.id, subject: "user_123", permissions: ["orders:read"] });
    await runtime.app.close();

    // Fail closed: with no operator registry configured, grant minting is unavailable, not open.
    const unconfigured = await createControlPlaneRuntime();
    const denied = await unconfigured.app.inject({ method: "POST", url: "/v1/grants", payload });
    expect(denied.statusCode).toBe(503);
    expect(denied.json()).toMatchObject({ error: "operator_auth_not_configured" });
    await unconfigured.app.close();
  });

  it("requires an admin operator to read or change the kill switch and to revoke a chain", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });

    const mutations = [
      {
        method: "POST" as const,
        url: "/v1/kill-switch",
        // The specific fields that make this a full enforcement bypass if left anonymous.
        payload: { active: true, reason: "unauthorized", actor_id: "platform_admin", global_enforcement_pause: true }
      },
      {
        method: "DELETE" as const,
        url: "/v1/kill-switch",
        payload: { reason: "unauthorized", actor_id: "platform_admin" }
      },
      {
        method: "POST" as const,
        url: "/v1/revoke",
        payload: { chain_id: "chn_victim", reason: "unauthorized", actor_id: "platform_admin" }
      }
    ];

    for (const route of mutations) {
      const anonymous = await runtime.app.inject({ method: route.method, url: route.url, payload: route.payload });
      expect(anonymous.statusCode, `${route.method} ${route.url} must reject anonymous callers`).toBe(401);
      expect(anonymous.json()).toMatchObject({ error: "operator_auth_required" });

      const viewer = await runtime.app.inject({
        method: route.method,
        url: route.url,
        headers: TEST_VIEWER_HEADERS,
        payload: route.payload
      });
      expect(viewer.statusCode, `${route.method} ${route.url} must reject a non-admin operator`).toBe(403);
      expect(viewer.json()).toMatchObject({ error: "operator_forbidden", required_role: "admin" });
    }

    // The enforcement posture is itself sensitive — it maps where enforcement is weakest.
    const anonymousRead = await runtime.app.inject({ method: "GET", url: "/v1/kill-switch" });
    expect(anonymousRead.statusCode).toBe(401);
    const viewerRead = await runtime.app.inject({ method: "GET", url: "/v1/kill-switch", headers: TEST_VIEWER_HEADERS });
    expect(viewerRead.statusCode).toBe(200);

    // Nothing above may have taken effect.
    expect(runtime.services.killSwitch.current().active).toBe(false);
    expect(runtime.services.killSwitch.current().globalEnforcementPause).toBe(false);

    await runtime.app.close();
  });

  it("binds kill-switch and revocation actors to the authenticated operator", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });

    const impersonating = await runtime.app.inject({
      method: "POST",
      url: "/v1/kill-switch",
      headers: TEST_ADMIN_HEADERS,
      payload: { active: true, reason: "canary", actor_id: "someone_else" }
    });
    expect(impersonating.statusCode).toBe(400);
    expect(impersonating.json()).toMatchObject({ error: "actor_id_mismatch", expected_actor_id: "platform_admin" });
    expect(runtime.services.killSwitch.current().active).toBe(false);

    const honest = await runtime.app.inject({
      method: "POST",
      url: "/v1/kill-switch",
      headers: TEST_ADMIN_HEADERS,
      payload: { active: true, reason: "canary", actor_id: "platform_admin" }
    });
    expect(honest.statusCode).toBe(200);
    expect(honest.json()).toMatchObject({ active: true, actor_id: "platform_admin" });

    await runtime.app.close();
  });

  it("denies all new sessions while the kill switch is active until cleared", async () => {
    const runtime = await createControlPlaneRuntime({ sessionTtlSeconds: 60, operatorAuth: TEST_OPERATOR_AUTH });
    const target = (
      await runtime.app.inject({
        method: "POST",
        url: "/v1/targets",
        headers: TEST_ADMIN_HEADERS,
        payload: {
          site_id: "sit_kill",
          name: "Kill Switch Shop",
          origin: "https://kill.example.com"
        }
      })
    ).json<{ id: string; site_id: string; origin: string }>();
    const grant = (
      await runtime.app.inject({
        method: "POST",
        url: "/v1/grants",
        headers: TEST_ADMIN_HEADERS,
        payload: {
          target_id: target.id,
          subject: "user_123",
          permissions: ["checkout:create"]
        }
      })
    ).json<{ id: string }>();

    const tripped = await runtime.app.inject({
      method: "POST",
      url: "/v1/kill-switch",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        active: true,
        reason: "rollback canary",
        actor_id: "platform_admin",
        deny_new_sessions: true,
        global_enforcement_pause: true,
        route_mode_overrides: { "/checkout": "observe" },
        crypto_path_rollout: "shadow",
        min_revocation_epoch: 99
      }
    });
    expect(tripped.statusCode).toBe(200);
    expect(tripped.json()).toMatchObject({ active: true, deny_new_sessions: true, min_revocation_epoch: 99 });

    const denied = await runtime.app.inject({
      method: "POST",
      url: "/v1/sessions/exchange",
      payload: {
        grant_id: grant.id,
        audience: target.site_id,
        resource: target.origin,
        proof_jkt: "proof-thumbprint-demo",
        requested_permissions: ["checkout:create"]
      }
    });
    expect(denied.statusCode).toBe(403);
    expect(denied.json()).toMatchObject({ error: "kill_switch_active" });

    const cleared = await runtime.app.inject({
      method: "DELETE",
      url: "/v1/kill-switch",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        reason: "rollback cleared",
        actor_id: "platform_admin"
      }
    });
    expect(cleared.statusCode).toBe(200);
    expect(cleared.json()).toMatchObject({ active: false, deny_new_sessions: false });

    const issued = await runtime.app.inject({
      method: "POST",
      url: "/v1/sessions/exchange",
      payload: {
        grant_id: grant.id,
        audience: target.site_id,
        resource: target.origin,
        proof_jkt: "proof-thumbprint-demo",
        requested_permissions: ["checkout:create"]
      }
    });
    expect(issued.statusCode).toBe(201);
    await runtime.app.close();
  });

  it("requires decision_search auth and searches decisions with composite filters", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });
    const seed = async (overrides: {
      id: string;
      requestId: string;
      decision: string;
      occurredAt: string;
      issuer?: string;
      subjectHandle?: string;
      actorClass?: string;
      routeTemplate?: string;
      purpose?: string;
    }): Promise<void> => {
      await runtime.services.store.recordDecision({
        id: overrides.id,
        siteId: "sit_search",
        requestId: overrides.requestId,
        actorClass: overrides.actorClass ?? "verified_agent",
        decision: overrides.decision,
        routeTemplate: overrides.routeTemplate ?? "/checkout",
        method: "POST",
        occurredAt: overrides.occurredAt,
        issuer: overrides.issuer,
        subjectHandle: overrides.subjectHandle,
        purpose: overrides.purpose,
        reasonCodes: ["matched_policy"]
      });
    };
    await seed({ id: "dec_s1", requestId: "req_s1", decision: "allow", occurredAt: "2026-04-01T00:00:00.000Z", issuer: "https://issuer-a.example" });
    await seed({ id: "dec_s2", requestId: "req_s2", decision: "deny", occurredAt: "2026-04-02T00:00:00.000Z", issuer: "https://issuer-b.example", subjectHandle: "sub_handle_xyz" });
    await seed({ id: "dec_s3", requestId: "req_s3", decision: "deny", occurredAt: "2026-04-03T00:00:00.000Z", issuer: "https://issuer-a.example" });
    await seed({ id: "dec_s4", requestId: "req_s4", decision: "price_required", occurredAt: "2026-04-04T00:00:00.000Z", actorClass: "signed_agent", purpose: "research" });

    await runtime.services.store.applyDecisionOperatorAction({
      decisionId: "dec_s2",
      action: "deny",
      actorId: "ops_alice",
      occurredAt: "2026-04-02T01:00:00.000Z"
    });
    await runtime.services.store.applyDecisionOperatorAction({
      decisionId: "dec_s3",
      action: "deny",
      actorId: "ops_bob",
      occurredAt: "2026-04-03T01:00:00.000Z"
    });

    const missingToken = await runtime.app.inject({ method: "GET", url: "/v1/decisions/search?site_id=sit_search" });
    expect(missingToken.statusCode).toBe(401);
    expect(missingToken.json()).toMatchObject({ error: "operator_auth_required" });

    const wrongRole = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions/search?site_id=sit_search",
      headers: TEST_OPERATOR_HEADERS
    });
    expect(wrongRole.statusCode).toBe(403);
    expect(wrongRole.json()).toMatchObject({ error: "operator_forbidden", required_role: "decision_search" });

    const missingSite = await runtime.app.inject({ method: "GET", url: "/v1/decisions/search", headers: TEST_VIEWER_HEADERS });
    expect(missingSite.statusCode).toBe(400);
    expect(missingSite.json()).toMatchObject({ error: "invalid_decision_search_query" });

    const empty = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions/search?site_id=sit_search&decision=allow&issuer=https%3A%2F%2Fnobody.example",
      headers: TEST_VIEWER_HEADERS
    });
    expect(empty.statusCode).toBe(200);
    expect(empty.json()).toMatchObject({ decisions: [] });

    const denied = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions/search?site_id=sit_search&decision=deny",
      headers: TEST_VIEWER_HEADERS
    });
    expect(denied.statusCode).toBe(200);
    const deniedRows = (denied.json() as { decisions: Array<{ id: string }> }).decisions;
    expect(deniedRows.map((row) => row.id)).toEqual(["dec_s3", "dec_s2"]);

    const byOperator = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions/search?site_id=sit_search&operator_actor_id=ops_alice",
      headers: TEST_VIEWER_HEADERS
    });
    expect((byOperator.json() as { decisions: Array<{ id: string }> }).decisions.map((row) => row.id)).toEqual(["dec_s2"]);

    const window = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions/search?site_id=sit_search&since=2026-04-02T00:00:00.000Z&until=2026-04-03T23:59:59.999Z",
      headers: TEST_VIEWER_HEADERS
    });
    expect((window.json() as { decisions: Array<{ id: string }> }).decisions.map((row) => row.id)).toEqual(["dec_s3", "dec_s2"]);

    const limited = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions/search?site_id=sit_search&limit=2",
      headers: TEST_VIEWER_HEADERS
    });
    expect((limited.json() as { decisions: Array<{ id: string }> }).decisions).toHaveLength(2);

    const subject = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions/search?site_id=sit_search&subject_handle=sub_handle_xyz",
      headers: TEST_VIEWER_HEADERS
    });
    expect((subject.json() as { decisions: Array<{ id: string }> }).decisions.map((row) => row.id)).toEqual(["dec_s2"]);

    const actor = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions/search?site_id=sit_search&actor_class=signed_agent",
      headers: TEST_VIEWER_HEADERS
    });
    expect((actor.json() as { decisions: Array<{ id: string }> }).decisions.map((row) => row.id)).toEqual(["dec_s4"]);

    const purpose = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions/search?site_id=sit_search&purpose=research",
      headers: TEST_VIEWER_HEADERS
    });
    expect((purpose.json() as { decisions: Array<{ id: string; purpose?: string }> }).decisions).toEqual([
      expect.objectContaining({ id: "dec_s4", purpose: "research" })
    ]);

    const badEnum = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions/search?site_id=sit_search&decision=not_a_decision",
      headers: TEST_VIEWER_HEADERS
    });
    expect(badEnum.statusCode).toBe(400);
    await runtime.app.close();
  });

  it("lists decisions and exposes a resumable SSE stream", async () => {
    const runtime = await createControlPlaneRuntime({
      operatorAuth: TEST_OPERATOR_AUTH,
      webhookSecrets: new StaticWebhookSecretResolver({ "aws-sm://aidenid/webhook/demo": "resolved-demo-webhook-secret" })
    });
    await runtime.services.store.recordDecision({
      id: "dec_demo",
      siteId: "sit_demo",
      requestId: "req_1",
      actorClass: "verified_agent",
      decision: "allow",
      routeTemplate: "/checkout",
      method: "POST",
      occurredAt: new Date(0).toISOString(),
      purpose: "research",
      cascadeTrace: [
        { ordinal: 1, layer: "crypto_identity", status: "pass", reason: "http_signature_dpop_verified", latency_us: 400 },
        { ordinal: 2, layer: "delegation_authorization", status: "pass", reason: "proof_bound_session_verified", latency_us: 400 },
        { ordinal: 3, layer: "fingerprint_sidecar", status: "not_configured", reason: "fingerprint_provider_missing", latency_us: 0 },
        { ordinal: 4, layer: "operator_reputation", status: "not_configured", reason: "operator_reputation_provider_missing", latency_us: 0 }
      ]
    });

    const decisions = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions?site_id=sit_demo",
      headers: TEST_VIEWER_HEADERS
    });
    expect(decisions.statusCode).toBe(200);
    expect(decisions.json()).toMatchObject({
      decisions: [
        {
          id: "dec_demo",
          route_template: "/checkout",
          purpose: "research",
          cascade_trace: expect.arrayContaining([
            expect.objectContaining({ layer: "crypto_identity", status: "pass" }),
            expect.objectContaining({ layer: "delegation_authorization", status: "pass" })
          ])
        }
      ]
    });

    const stream = await runtime.app.inject({ method: "GET", url: "/v1/decisions/stream?site_id=sit_demo&once=true", headers: TEST_VIEWER_HEADERS });
    expect(stream.headers["content-type"]).toContain("text/event-stream");
    expect(stream.body).toContain("id: 1");
    expect(stream.body).toContain("event: recorded");
    expect(stream.body).toContain('"request_id":"req_1"');
    expect(stream.body).toContain('"purpose":"research"');
    expect(stream.body).toContain('"cascade_trace"');
    expect(stream.body).toContain('"fingerprint_provider_missing"');
    expect(stream.body).toContain('"decision_outbox_chain"');
    expect(stream.body).toContain(`"previous_hash":"${DECISION_OUTBOX_GENESIS_HASH}"`);

    await runtime.services.store.recordDecision({
      id: "dec_demo_2",
      siteId: "sit_demo",
      requestId: "req_2",
      actorClass: "unknown",
      decision: "throttle",
      routeTemplate: "/checkout",
      method: "POST",
      occurredAt: new Date(1).toISOString()
    });
    const resumed = await runtime.app.inject({ method: "GET", url: "/v1/decisions/stream?site_id=sit_demo&once=true", headers: { ...TEST_VIEWER_HEADERS, "last-event-id": "1" } });
    expect(resumed.body).not.toContain('"request_id":"req_1"');
    expect(resumed.body).toContain('"request_id":"req_2"');
    await runtime.app.close();
  });

  it("requires decision_search auth and isolates the decision stream by tenant site", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });
    await runtime.services.store.recordDecision({
      id: "dec_tenant_a",
      siteId: "sit_tenant_a",
      requestId: "req_tenant_a",
      actorClass: "verified_agent",
      decision: "allow",
      routeTemplate: "/checkout",
      method: "POST",
      occurredAt: new Date(0).toISOString(),
      reasonCodes: ["matched_policy"]
    });
    await runtime.services.store.recordDecision({
      id: "dec_tenant_b",
      siteId: "sit_tenant_b",
      requestId: "req_tenant_b",
      actorClass: "verified_agent",
      decision: "deny",
      routeTemplate: "/checkout",
      method: "POST",
      occurredAt: new Date(1).toISOString(),
      reasonCodes: ["matched_policy"]
    });

    // Anonymous subscribers are rejected before any tenant data is read.
    const anon = await runtime.app.inject({ method: "GET", url: "/v1/decisions/stream?site_id=sit_tenant_a&once=true" });
    expect(anon.statusCode).toBe(401);
    expect(anon.json()).toMatchObject({ error: "operator_auth_required" });

    // A token without the decision_search role is forbidden.
    const wrongRole = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions/stream?site_id=sit_tenant_a&once=true",
      headers: TEST_OPERATOR_HEADERS
    });
    expect(wrongRole.statusCode).toBe(403);
    expect(wrongRole.json()).toMatchObject({ error: "operator_forbidden", required_role: "decision_search" });

    // The site scope is required; an unscoped stream is rejected rather than leaking all tenants.
    const missingSite = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions/stream?once=true",
      headers: TEST_VIEWER_HEADERS
    });
    expect(missingSite.statusCode).toBe(400);
    expect(missingSite.json()).toMatchObject({ error: "invalid_decision_stream_query" });

    // An authorized operator scoped to site A sees only site A decisions, never site B's.
    const scoped = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions/stream?site_id=sit_tenant_a&once=true",
      headers: TEST_VIEWER_HEADERS
    });
    expect(scoped.statusCode).toBe(200);
    expect(scoped.body).toContain('"request_id":"req_tenant_a"');
    expect(scoped.body).toContain('"site_id":"sit_tenant_a"');
    expect(scoped.body).not.toContain("req_tenant_b");
    expect(scoped.body).not.toContain("sit_tenant_b");
    await runtime.app.close();
  });

  it("requires decision_search auth for a decision receipt", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });
    await runtime.services.store.recordDecision({
      id: "dec_receipt_authz",
      siteId: "sit_tenant_a",
      requestId: "req_receipt_authz",
      actorClass: "verified_agent",
      decision: "allow",
      routeTemplate: "/checkout",
      method: "POST",
      occurredAt: new Date(0).toISOString(),
      reasonCodes: ["matched_policy"]
    });

    // Anonymous callers are rejected before the decision is read, so a guessed or
    // observed decision id no longer discloses another tenant's receipt.
    const anon = await runtime.app.inject({ method: "GET", url: "/v1/decisions/dec_receipt_authz/receipt" });
    expect(anon.statusCode).toBe(401);
    expect(anon.json()).toMatchObject({ error: "operator_auth_required" });

    // A token without the decision_search role is forbidden.
    const wrongRole = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions/dec_receipt_authz/receipt",
      headers: TEST_OPERATOR_HEADERS
    });
    expect(wrongRole.statusCode).toBe(403);
    expect(wrongRole.json()).toMatchObject({ error: "operator_forbidden", required_role: "decision_search" });

    // An authorized operator reaches the handler (this decision carries no receipt yet).
    const authorized = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions/dec_receipt_authz/receipt",
      headers: TEST_VIEWER_HEADERS
    });
    expect(authorized.statusCode).toBe(404);
    expect(authorized.json()).toMatchObject({ error: "decision_receipt_not_found" });
  });

  it("requires decision_search auth for quarantine pins", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });

    // site_id is caller-supplied, so without auth any site's pins were readable anonymously.
    const anon = await runtime.app.inject({ method: "GET", url: "/v1/quarantine/pins?site_id=sit_tenant_a" });
    expect(anon.statusCode).toBe(401);
    expect(anon.json()).toMatchObject({ error: "operator_auth_required" });

    const wrongRole = await runtime.app.inject({
      method: "GET",
      url: "/v1/quarantine/pins?site_id=sit_tenant_a",
      headers: TEST_OPERATOR_HEADERS
    });
    expect(wrongRole.statusCode).toBe(403);
    expect(wrongRole.json()).toMatchObject({ error: "operator_forbidden", required_role: "decision_search" });

    const authorized = await runtime.app.inject({
      method: "GET",
      url: "/v1/quarantine/pins?site_id=sit_tenant_a",
      headers: TEST_VIEWER_HEADERS
    });
    expect(authorized.statusCode).toBe(200);
    expect(authorized.json()).toMatchObject({ pins: [] });
  });
  it("closes decision stream once requests with a stream_error when the initial outbox read fails", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });
    const store = runtime.services.store as unknown as {
      listDecisionOutboxAfter(
        seq: number,
        limit?: number
      ): Promise<ReturnType<InMemoryControlPlaneStore["listDecisionOutboxAfter"]>>;
    };
    store.listDecisionOutboxAfter = async () => {
      throw new Error("decision_outbox_unavailable");
    };

    const stream = await runtime.app.inject({ method: "GET", url: "/v1/decisions/stream?site_id=sit_demo&once=true", headers: TEST_VIEWER_HEADERS });

    expect(stream.statusCode).toBe(200);
    expect(stream.headers["content-type"]).toContain("text/event-stream");
    expect(stream.body).toContain("event: stream_error");
    expect(stream.body).toContain("decision_stream_unavailable");
    expect(stream.body).not.toContain("decision_outbox_unavailable");
    await runtime.app.close();
  });

  it("reports ready when the decision outbox dependency is readable", async () => {
    const runtime = await createControlPlaneRuntime();

    const response = await runtime.app.inject({ method: "GET", url: "/readyz" });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      ok: true,
      service: "aidenid-control-plane",
      decisionOutboxAvailable: true
    });
    await runtime.app.close();
  });

  it("fails readiness when the decision outbox dependency is unavailable", async () => {
    const runtime = await createControlPlaneRuntime();
    const store = runtime.services.store as unknown as {
      latestDecisionOutboxSeq(): Promise<number>;
      listDecisionOutboxAfter(
        seq: number,
        limit?: number
      ): Promise<ReturnType<InMemoryControlPlaneStore["listDecisionOutboxAfter"]>>;
    };
    store.latestDecisionOutboxSeq = async () => 0;
    store.listDecisionOutboxAfter = async () => {
      throw new Error("stale_database_secret");
    };

    const response = await runtime.app.inject({ method: "GET", url: "/readyz" });

    expect(response.statusCode).toBe(503);
    expect(response.json()).toMatchObject({
      ok: false,
      service: "aidenid-control-plane",
      error: "decision_outbox_unavailable"
    });
    expect(response.body).not.toContain("stale_database_secret");
    await runtime.app.close();
  });

  it("hash-chains decision outbox events with canonical payload hashes", () => {
    const store = new InMemoryControlPlaneStore();
    const first = store.recordDecisionWithOutbox({
      id: "dec_chain_1",
      siteId: "sit_chain",
      requestId: "req_chain_1",
      actorClass: "verified_agent",
      decision: "allow",
      routeTemplate: "/checkout",
      method: "POST",
      occurredAt: "2026-04-25T00:00:00.000Z"
    });
    const second = store.recordDecisionWithOutbox({
      id: "dec_chain_2",
      siteId: "sit_chain",
      requestId: "req_chain_2",
      actorClass: "unknown",
      decision: "deny",
      routeTemplate: "/checkout",
      method: "POST",
      occurredAt: "2026-04-25T00:00:01.000Z"
    });

    expect(first.previousHash).toBe(DECISION_OUTBOX_GENESIS_HASH);
    expect(first.entryHash).toBe(
      decisionOutboxEntryHash({
        previousHash: DECISION_OUTBOX_GENESIS_HASH,
        decisionId: first.decisionId,
        eventType: first.eventType,
        payload: first.payload
      })
    );
    expect(second.previousHash).toBe(first.entryHash);
    expect(second.entryHash).toBe(
      decisionOutboxEntryHash({
        previousHash: first.entryHash,
        decisionId: second.decisionId,
        eventType: second.eventType,
        payload: second.payload
      })
    );
    expect(store.listDecisionOutboxAfter(0, 10).map((event) => event.entryHash)).toEqual([first.entryHash, second.entryHash]);
  });

  it("serves operator-verifiable decision outbox chain segments", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });
    const first = await runtime.services.store.recordDecisionWithOutbox({
      id: "dec_chain_segment_1",
      siteId: "sit_chain_segment",
      requestId: "req_chain_segment_1",
      actorClass: "verified_agent",
      decision: "allow",
      routeTemplate: "/checkout",
      method: "POST",
      occurredAt: "2026-04-25T00:00:00.000Z"
    });
    const second = await runtime.services.store.recordDecisionWithOutbox({
      id: "dec_chain_segment_2",
      siteId: "sit_chain_segment",
      requestId: "req_chain_segment_2",
      actorClass: "suspicious_automation",
      decision: "deny",
      routeTemplate: "/checkout",
      method: "POST",
      occurredAt: "2026-04-25T00:00:01.000Z"
    });

    const unauthorized = await runtime.app.inject({ method: "GET", url: "/v1/decisions/chain-segment" });
    expect(unauthorized.statusCode).toBe(401);

    const response = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions/chain-segment?from_seq=1&limit=10",
      headers: TEST_VIEWER_HEADERS
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      chain: {
        version: "aidenid.decision_outbox.v1",
        genesis_hash: DECISION_OUTBOX_GENESIS_HASH,
        from_seq: 1,
        to_seq: 2,
        count: 2,
        valid: true,
        anchor_previous_hash: DECISION_OUTBOX_GENESIS_HASH,
        terminal_entry_hash: second.entryHash,
        findings: []
      },
      events: [
        expect.objectContaining({ seq: 1, previous_hash: DECISION_OUTBOX_GENESIS_HASH, entry_hash: first.entryHash }),
        expect.objectContaining({ seq: 2, previous_hash: first.entryHash, entry_hash: second.entryHash })
      ]
    });

    const mismatch = await runtime.app.inject({
      method: "GET",
      url: `/v1/decisions/chain-segment?from_seq=2&expected_previous_hash=${DECISION_OUTBOX_GENESIS_HASH}`,
      headers: TEST_VIEWER_HEADERS
    });
    expect(mismatch.statusCode).toBe(200);
    expect(mismatch.json()).toMatchObject({
      chain: {
        valid: false,
        findings: [expect.objectContaining({ seq: 2, code: "expected_previous_hash_mismatch" })]
      }
    });
    await runtime.app.close();
  });

  it("serves 1000 concurrent decision-stream subscribers from the same outbox cursor", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });
    await runtime.services.store.recordDecisionWithOutbox({
      id: "dec_stream_stress_1",
      siteId: "sit_demo",
      requestId: "req_stream_stress_1",
      actorClass: "verified_agent",
      decision: "allow",
      routeTemplate: "/checkout",
      method: "POST",
      occurredAt: new Date(0).toISOString()
    });

    const subscribers = await Promise.all(
      Array.from({ length: 1_000 }, () => runtime.app.inject({ method: "GET", url: "/v1/decisions/stream?site_id=sit_demo&once=true", headers: TEST_VIEWER_HEADERS }))
    );

    expect(subscribers).toHaveLength(1_000);
    expect(subscribers.every((response) => response.statusCode === 200)).toBe(true);
    expect(subscribers.every((response) => String(response.headers["content-type"]).includes("text/event-stream"))).toBe(true);
    expect(subscribers.every((response) => response.body.includes('"request_id":"req_stream_stress_1"'))).toBe(true);
    await runtime.app.close();
  });

  it("wakes in-memory decision stream waiters when new outbox events arrive", async () => {
    const runtime = await createControlPlaneRuntime();
    const waiter = runtime.services.store.waitForDecisionOutboxAfter(0, 500);
    await runtime.services.store.recordDecisionWithOutbox({
      id: "dec_waiter_1",
      siteId: "sit_demo",
      requestId: "req_waiter_1",
      actorClass: "verified_agent",
      decision: "allow",
      routeTemplate: "/checkout",
      method: "POST",
      occurredAt: new Date(0).toISOString()
    });
    await expect(Promise.resolve(waiter)).resolves.toBeUndefined();
    await runtime.app.close();
  });

  it("runs decision outbox retention once at startup", async () => {
    const store = new InMemoryControlPlaneStore();
    const cutoffs: string[] = [];
    const pruneDecisionOutboxBefore = store.pruneDecisionOutboxBefore.bind(store);
    const overrides = store as unknown as { pruneDecisionOutboxBefore(olderThan: string): number };
    overrides.pruneDecisionOutboxBefore = (olderThan: string) => {
      cutoffs.push(olderThan);
      return pruneDecisionOutboxBefore(olderThan);
    };
    const runtime = await createControlPlaneRuntime({
      store,
      decisionOutboxRetentionDays: 1,
      decisionOutboxRetentionIntervalMs: 60_000
    });
    expect(cutoffs).toHaveLength(1);
    await runtime.app.close();
  });

  it("serializes slow decision stream reads without overlapping outbox polls", async () => {
    const { store, stats } = createSlowDecisionOutboxStore();
    await store.recordDecisionWithOutbox({
      id: "dec_slow_stream_1",
      siteId: "sit_demo",
      requestId: "req_slow_stream_1",
      actorClass: "verified_agent",
      decision: "allow",
      routeTemplate: "/checkout",
      method: "POST",
      occurredAt: new Date(0).toISOString()
    });
    const runtime = await createControlPlaneRuntime({ store, decisionOutboxRetentionDays: 0, operatorAuth: TEST_OPERATOR_AUTH });
    await runtime.app.listen({ host: "127.0.0.1", port: 0 });
    const address = runtime.app.server.address() as AddressInfo;
    const controller = new AbortController();
    const response = await fetch(`http://127.0.0.1:${address.port}/v1/decisions/stream?site_id=sit_demo`, { signal: controller.signal, headers: TEST_VIEWER_HEADERS });
    expect(response.status).toBe(200);
    for (let index = 0; index < 30 && stats.reads < 3; index += 1) {
      await delay(50);
    }
    controller.abort();
    await response.body?.cancel().catch(() => undefined);
    await runtime.app.close();
    expect(stats.reads).toBeGreaterThanOrEqual(3);
    expect(stats.maxConcurrentReads).toBe(1);
  });

  it("queues persona audit handoff when suspicion breaches threshold", async () => {
    const runtime = await createControlPlaneRuntime();
    const response = await runtime.app.inject({
      method: "POST",
      url: "/v1/decisions",
      payload: {
        site_id: "sit_audit",
        request_id: "req_suspicion_1",
        actor_class: "suspicious_automation",
        decision: "sandbox",
        route_template: "/comments/:id",
        method: "POST",
        reason_codes: ["sandbox_policy"],
        suspicion_score: 0.91,
        cascade_trace: [
          { ordinal: 1, layer: "crypto_identity", status: "skipped", reason: "actor_class_not_signed_agent", latency_us: 0 },
          { ordinal: 2, layer: "delegation_authorization", status: "skipped", reason: "depends_on_crypto_identity", latency_us: 0 },
          { ordinal: 3, layer: "fingerprint_sidecar", status: "not_configured", reason: "fingerprint_provider_missing", latency_us: 0 },
          { ordinal: 4, layer: "operator_reputation", status: "not_configured", reason: "operator_reputation_provider_missing", latency_us: 0 }
        ],
        occurred_at: "2026-04-24T13:40:00.000Z"
      }
    });

    expect(response.statusCode).toBe(201);
    expect(response.json()).toMatchObject({
      decision: {
        request_id: "req_suspicion_1",
        suspicion_score: 0.91,
        reason_codes: ["sandbox_policy"],
        cascade_trace: expect.arrayContaining([
          expect.objectContaining({ layer: "crypto_identity", status: "skipped" }),
          expect.objectContaining({ layer: "delegation_authorization", status: "skipped" })
        ])
      },
      persona_audit: { status: "queued" }
    });
    expect(runtime.outboxStore.all()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "PERSONA_AUDIT_REQUESTED",
          payload: expect.objectContaining({
            tool: "create-sentinelayer",
            trigger_type: "suspicion_threshold",
            no_token_passthrough: true,
            oauth_resource: "sentinelayer://persona-audit",
            audience: "create-sentinelayer"
          })
        })
      ])
    );

    const incidents = await runtime.app.inject({ method: "GET", url: "/v1/persona-audits?site_id=sit_audit" });
    expect(incidents.statusCode).toBe(200);
    expect(incidents.json()).toMatchObject({
      incidents: [
        {
          trigger_type: "suspicion_threshold",
          tool: "create-sentinelayer",
          request_id: "req_suspicion_1",
          narrative: {
            title: "Suspicion spike audit queued",
            evidence_refs: ["decision_stream:sit_audit", "request:req_suspicion_1"]
          }
        }
      ]
    });
    await runtime.app.close();
  });

  it("issues signed decision receipts with transparency inclusion evidence", async () => {
    const runtime = await createControlPlaneRuntime({
      issuer: "https://api.aidenid.test",
      operatorAuth: TEST_OPERATOR_AUTH
    });
    const response = await runtime.app.inject({
      method: "POST",
      url: "/v1/decisions",
      payload: {
        site_id: "sit_receipt",
        request_id: "req_receipt_1",
        actor_class: "verified_agent",
        decision: "allow",
        recommended_decision: "allow",
        route_template: "/checkout",
        method: "POST",
        purpose: "research",
        reason_codes: ["matched_policy"],
        occurred_at: "2026-05-03T09:00:00.000Z"
      }
    });

    expect(response.statusCode).toBe(201);
    const recorded = response.json<{
      decision: {
        readonly id: string;
        readonly purpose: string;
        readonly receipt: {
          readonly key_id: string;
          readonly payload_sha256: string;
          readonly jws_sha256: string;
          readonly transparency_leaf_hash: string;
          readonly transparency_leaf_index: number;
          readonly transparency_checkpoint: Record<string, unknown>;
          readonly transparency_inclusion_proof: Record<string, unknown>;
        };
      };
    }>();
    expect(recorded.decision.purpose).toBe("research");
    expect(recorded.decision.receipt).toMatchObject({
      key_id: expect.stringContaining("decision-receipt"),
      payload_sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
      jws_sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
      transparency_leaf_hash: expect.stringMatching(/^[a-f0-9]{64}$/),
      transparency_leaf_index: 0,
      transparency_checkpoint: expect.objectContaining({ treeSize: 1 }),
      transparency_inclusion_proof: expect.objectContaining({ treeSize: 1 })
    });

    const receipt = await runtime.app.inject({
      method: "GET",
      url: `/v1/decisions/${recorded.decision.id}/receipt`,
      headers: TEST_VIEWER_HEADERS
    });

    expect(receipt.statusCode).toBe(200);
    const body = receipt.json<{
      readonly receipt_jws: string;
      readonly receipt_key_id: string;
      readonly receipt_public_jwk: Record<string, unknown>;
      readonly receipt_payload_sha256: string;
      readonly receipt_jws_sha256: string;
      readonly transparency: {
        readonly leaf_hash: string;
        readonly leaf_index: number;
        readonly checkpoint: { readonly rootHash: string; readonly treeSize: number };
        readonly inclusion_proof: { readonly rootHash: string; readonly treeSize: number };
      };
      readonly verified: boolean;
    }>();
    const verified = verifyCompactJws(body.receipt_jws, body.receipt_public_jwk, "EdDSA");
    expect(verified.header).toMatchObject({
      kid: body.receipt_key_id,
      typ: "aidenid.decision_receipt.v1"
    });
    expect(verified.payload).toMatchObject({
      iss: "https://api.aidenid.test",
      aud: "aidenid.decision_receipt",
      typ: "aidenid.decision_receipt.v1",
      decision_id: recorded.decision.id,
      request_id: "req_receipt_1",
      purpose: "research",
      receipt_key_id: body.receipt_key_id,
      decision_payload_sha256: body.receipt_payload_sha256
    });
    expect(body.receipt_jws_sha256).toBe(recorded.decision.receipt.jws_sha256);
    expect(body.transparency.leaf_hash).toBe(recorded.decision.receipt.transparency_leaf_hash);
    expect(body.transparency.leaf_index).toBe(0);
    expect(body.transparency.inclusion_proof.rootHash).toBe(body.transparency.checkpoint.rootHash);
    expect(body.transparency.inclusion_proof.treeSize).toBe(body.transparency.checkpoint.treeSize);
    expect(body.verified).toBe(true);
    expect(await runtime.services.store.listDecisionReceiptKeys(10)).toEqual([
      expect.objectContaining({
        kid: body.receipt_key_id,
        issuer: "https://api.aidenid.test",
        state: "active",
        jwkThumbprintSha256: expect.stringMatching(/^[a-f0-9]{64}$/)
      })
    ]);
    const persistedDecision = await runtime.services.store.getDecision(recorded.decision.id);
    expect(persistedDecision).toBeDefined();
    expect(await runtime.services.decisionReceipts.verify({ ...persistedDecision!, requestId: "req_tampered" })).toBe(false);
    expect(await runtime.services.decisionReceipts.verify({ ...persistedDecision!, receiptJws: `${body.receipt_jws.slice(0, -1)}x` })).toBe(false);
    const decisionOutbox = await runtime.services.store.listDecisionOutboxAfter(0, 10);
    expect(decisionOutbox[0]?.payload).toEqual(
      expect.objectContaining({
        purpose: "research",
        receipt: expect.objectContaining({
          jws_sha256: recorded.decision.receipt.jws_sha256,
          transparency_leaf_hash: recorded.decision.receipt.transparency_leaf_hash,
          transparency_checkpoint: expect.objectContaining({ treeSize: 1 }),
          transparency_inclusion_proof: expect.objectContaining({ treeSize: 1 })
        })
      })
    );
    expect(decisionOutbox[0]?.payload).not.toHaveProperty("transparency");
    expect(runtime.outboxStore.all()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "DECISION_RECORDED",
          payload: expect.objectContaining({
            decision_id: recorded.decision.id,
            purpose: "research",
            receipt_jws_sha256: recorded.decision.receipt.jws_sha256,
            transparency_leaf_hash: recorded.decision.receipt.transparency_leaf_hash
          })
        })
      ])
    );
    await runtime.app.close();
  });

  it("publishes generic decision outbox requests to a configured Redis stream", async () => {
    const redis = new RecordingRedisStreamsClient();
    const runtime = await createControlPlaneRuntime({
      outboxRedisClient: redis,
      outboxRedisStreamName: "aidenid:test:outbox"
    });
    const response = await runtime.app.inject({
      method: "POST",
      url: "/v1/decisions",
      payload: {
        site_id: "sit_outbox_redis",
        request_id: "req_outbox_redis_1",
        actor_class: "verified_agent",
        decision: "allow",
        recommended_decision: "allow",
        route_template: "/checkout",
        method: "POST",
        reason_codes: ["matched_policy"],
        occurred_at: "2026-04-25T00:00:00.000Z"
      }
    });

    expect(response.statusCode).toBe(201);
    await runtime.services.outbox.flush();

    const streamTypes = redis.writes.map((write) => write.fields.at(write.fields.indexOf("type") + 1));
    expect(redis.writes.map((write) => write.stream)).toEqual(["aidenid:test:outbox"]);
    expect(streamTypes).toEqual(["DECISION_RECORDED"]);
    expect(redis.writes[0]?.fields).toContain("payload");
    expect(runtime.outboxStore.pending()).toHaveLength(0);
    expect(runtime.outboxStore.all()).toEqual(expect.arrayContaining([expect.objectContaining({ publishedAt: expect.any(String) })]));
    await runtime.app.close();
  });

  it("fails closed when Redis stream publication fails after startup", async () => {
    const redis = new RecordingRedisStreamsClient();
    const runtime = await createControlPlaneRuntime({
      outboxRedisClient: redis,
      outboxRedisStreamName: "aidenid:test:outbox"
    });
    redis.failWith = new Error("redis unavailable after startup");

    const response = await runtime.app.inject({
      method: "POST",
      url: "/v1/decisions",
      payload: {
        site_id: "sit_outbox_redis_down",
        request_id: "req_outbox_redis_down_1",
        actor_class: "verified_agent",
        decision: "allow",
        recommended_decision: "allow",
        route_template: "/checkout",
        method: "POST",
        reason_codes: ["matched_policy"],
        occurred_at: "2026-04-25T00:00:00.000Z"
      }
    });

    expect(response.statusCode).toBe(500);
    expect(redis.writes).toHaveLength(0);
    expect(runtime.outboxStore.pending()).toEqual([expect.objectContaining({ type: "DECISION_RECORDED" })]);
    await runtime.app.close();
  });

  it("enforces stored decision quota across tenant sites before issuing receipts", async () => {
    const signer = new LocalDecisionReceiptIssuer({ issuer: "https://api.aidenid.test" });
    let issuedReceipts = 0;
    const runtime = await createControlPlaneRuntime({
      issuer: "https://api.aidenid.test",
      operatorAuth: TEST_OPERATOR_AUTH,
      decisionReceipts: {
        issue(decision) {
          issuedReceipts += 1;
          return signer.issue(decision);
        },
        verify(decision) {
          return signer.verify(decision);
        }
      }
    });

    await runtime.app.inject({
      method: "PUT",
      url: "/v1/tenants/ten_decision_quota/quota",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        monthly_decision_limit: 10,
        stored_decision_limit: 1,
        target_limit: 2
      }
    });
    for (const siteId of ["sit_quota_a", "sit_quota_b"]) {
      const target = await runtime.app.inject({
        method: "POST",
        url: "/v1/targets",
        headers: TEST_ADMIN_HEADERS,
        payload: {
          tenant_id: "ten_decision_quota",
          site_id: siteId,
          name: siteId,
          origin: `https://${siteId}.example.com`
        }
      });
      expect(target.statusCode).toBe(201);
    }

    const first = await runtime.app.inject({
      method: "POST",
      url: "/v1/decisions",
      payload: {
        site_id: "sit_quota_a",
        request_id: "req_quota_a",
        actor_class: "verified_agent",
        decision: "allow",
        route_template: "/checkout",
        method: "POST",
        occurred_at: "2026-05-03T10:00:00.000Z"
      }
    });
    expect(first.statusCode).toBe(201);

    const second = await runtime.app.inject({
      method: "POST",
      url: "/v1/decisions",
      payload: {
        site_id: "sit_quota_b",
        request_id: "req_quota_b",
        actor_class: "verified_agent",
        decision: "allow",
        route_template: "/checkout",
        method: "POST",
        occurred_at: "2026-05-03T10:01:00.000Z"
      }
    });

    expect(second.statusCode).toBe(429);
    expect(second.json()).toMatchObject({ error: "tenant_decision_storage_quota_exceeded", stored_decision_limit: 1 });
    expect(issuedReceipts).toBe(1);
    expect(await runtime.services.store.listDecisions(undefined, 10)).toEqual([
      expect.objectContaining({ siteId: "sit_quota_a", requestId: "req_quota_a", tenantId: "ten_decision_quota" })
    ]);
    expect(await runtime.services.store.listDecisionOutboxAfter(0, 10)).toHaveLength(1);
    await runtime.app.close();
  });

  it("serializes in-memory stored decision quota while receipt issuance is pending", async () => {
    const signer = new LocalDecisionReceiptIssuer({ issuer: "https://api.aidenid.test" });
    let issuedReceipts = 0;
    let releaseFirstReceipt: (() => void) | undefined;
    const firstReceiptGate = new Promise<void>((resolve) => {
      releaseFirstReceipt = resolve;
    });
    const runtime = await createControlPlaneRuntime({
      issuer: "https://api.aidenid.test",
      operatorAuth: TEST_OPERATOR_AUTH,
      decisionReceipts: {
        async issue(decision) {
          issuedReceipts += 1;
          if (issuedReceipts === 1) {
            await firstReceiptGate;
          }
          return signer.issue(decision);
        },
        verify(decision) {
          return signer.verify(decision);
        }
      }
    });

    await runtime.app.inject({
      method: "PUT",
      url: "/v1/tenants/ten_decision_quota_lock/quota",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        monthly_decision_limit: 10,
        stored_decision_limit: 1,
        target_limit: 2
      }
    });
    for (const siteId of ["sit_quota_lock_a", "sit_quota_lock_b"]) {
      const target = await runtime.app.inject({
        method: "POST",
        url: "/v1/targets",
        headers: TEST_ADMIN_HEADERS,
        payload: {
          tenant_id: "ten_decision_quota_lock",
          site_id: siteId,
          name: siteId,
          origin: `https://${siteId}.example.com`
        }
      });
      expect(target.statusCode).toBe(201);
    }

    const firstPromise = runtime.app.inject({
      method: "POST",
      url: "/v1/decisions",
      payload: {
        site_id: "sit_quota_lock_a",
        request_id: "req_quota_lock_a",
        actor_class: "verified_agent",
        decision: "allow",
        route_template: "/checkout",
        method: "POST",
        occurred_at: "2026-05-03T10:02:00.000Z"
      }
    });

    for (let attempt = 0; attempt < 20 && issuedReceipts === 0; attempt += 1) {
      await delay(5);
    }
    expect(issuedReceipts).toBe(1);

    const secondPromise = runtime.app.inject({
      method: "POST",
      url: "/v1/decisions",
      payload: {
        site_id: "sit_quota_lock_b",
        request_id: "req_quota_lock_b",
        actor_class: "verified_agent",
        decision: "allow",
        route_template: "/checkout",
        method: "POST",
        occurred_at: "2026-05-03T10:03:00.000Z"
      }
    });

    await delay(25);
    expect(issuedReceipts).toBe(1);
    releaseFirstReceipt?.();
    const [first, second] = await Promise.all([firstPromise, secondPromise]);

    expect(first.statusCode).toBe(201);
    expect(second.statusCode).toBe(429);
    expect(second.json()).toMatchObject({ error: "tenant_decision_storage_quota_exceeded", stored_decision_limit: 1 });
    expect(issuedReceipts).toBe(1);
    expect(await runtime.services.store.listDecisions(undefined, 10)).toEqual([
      expect.objectContaining({ siteId: "sit_quota_lock_a", requestId: "req_quota_lock_a", tenantId: "ten_decision_quota_lock" })
    ]);
    expect(await runtime.services.store.listDecisionOutboxAfter(0, 10)).toHaveLength(1);
    await runtime.app.close();
  });

  it("fails closed when the receipt-key registry active key does not match the signer", async () => {
    const now = "2026-05-03T09:30:00.000Z";
    const store = new InMemoryControlPlaneStore();
    const registrySigner = new LocalDecisionReceiptIssuer({
      issuer: "https://api.aidenid.test",
      keyId: "decision-receipt-key-registry",
      now: () => new Date(now)
    });
    const localSigner = new LocalDecisionReceiptIssuer({
      issuer: "https://api.aidenid.test",
      keyId: "decision-receipt-key-local",
      now: () => new Date(now)
    });
    await store.upsertDecisionReceiptKey(registrySigner.currentKeyRecord({ activatedAt: now }), now);
    const issuer = new RegistryBackedDecisionReceiptIssuer({
      signer: localSigner,
      store,
      now: () => new Date(now)
    });

    await expect(
      issuer.issue({
        id: "dec_receipt_mismatch",
        siteId: "sit_receipt",
        requestId: "req_receipt_mismatch",
        actorClass: "verified_agent",
        decision: "allow",
        routeTemplate: "/checkout",
        method: "POST",
        occurredAt: now
      })
    ).rejects.toThrow("does not match signer kid");
  });

  it("rotates the active receipt-key registry record only when configured signer rotation is enabled", async () => {
    const now = "2026-05-03T09:35:00.000Z";
    const store = new InMemoryControlPlaneStore();
    const registrySigner = new LocalDecisionReceiptIssuer({
      issuer: "https://api.aidenid.test",
      keyId: "decision-receipt-key-registry",
      now: () => new Date(now)
    });
    const configuredSigner = new LocalDecisionReceiptIssuer({
      issuer: "https://api.aidenid.test",
      keyId: "decision-receipt-key-configured",
      now: () => new Date(now)
    });
    await store.upsertDecisionReceiptKey(registrySigner.currentKeyRecord({ activatedAt: now }), now);
    const issuer = new RegistryBackedDecisionReceiptIssuer({
      signer: configuredSigner,
      store,
      now: () => new Date(now),
      allowActiveKeyRotation: true
    });

    const issued = await issuer.issue({
      id: "dec_receipt_rotation",
      siteId: "sit_receipt",
      requestId: "req_receipt_rotation",
      actorClass: "verified_agent",
      decision: "allow",
      routeTemplate: "/checkout",
      method: "POST",
      occurredAt: now
    });

    expect(issued.receiptKeyId).toBe("decision-receipt-key-configured");
    expect(await store.getActiveDecisionReceiptKey("https://api.aidenid.test", now)).toEqual(
      expect.objectContaining({ kid: "decision-receipt-key-configured", state: "active" })
    );
    expect(await store.getDecisionReceiptKey("decision-receipt-key-registry")).toEqual(
      expect.objectContaining({
        state: "retired",
        rotationReason: "configured-signer-rotation:decision-receipt-key-configured"
      })
    );
  });

  it("builds stable decision receipt signers from configured Ed25519 private JWKs", () => {
    const now = "2026-05-03T09:45:00.000Z";
    const { privateKey } = generateKeyPairSync("ed25519");
    const secret = JSON.stringify({ private_jwk: privateKey.export({ format: "jwk" }) });
    const env = {
      NODE_ENV: "production",
      AIDENID_DECISION_RECEIPT_PRIVATE_JWK: secret
    };
    const first = localDecisionReceiptIssuerFromEnvironment({
      issuer: "https://api.aidenid.test",
      env,
      now: () => new Date(now)
    });
    const second = localDecisionReceiptIssuerFromEnvironment({
      issuer: "https://api.aidenid.test",
      env,
      now: () => new Date(now)
    });

    const firstRecord = first.currentKeyRecord({ activatedAt: now });
    const secondRecord = second.currentKeyRecord({ activatedAt: now });
    expect(firstRecord.kid).toBe(secondRecord.kid);
    expect(firstRecord.jwkThumbprintSha256).toBe(secondRecord.jwkThumbprintSha256);
    expect(firstRecord.kid).toMatch(/^aidenid-decision-receipt-ed25519-/);
  });

  it("requires configured decision receipt signing key material in production", () => {
    expect(() =>
      localDecisionReceiptIssuerFromEnvironment({
        issuer: "https://api.aidenid.test",
        env: { NODE_ENV: "production" }
      })
    ).toThrow(/AIDENID_DECISION_RECEIPT_PRIVATE_JWK is required in production/);

    expect(() =>
      localDecisionReceiptIssuerFromEnvironment({
        issuer: "https://api.aidenid.test",
        env: {
          NODE_ENV: "production",
          AIDENID_ALLOW_EPHEMERAL_DECISION_RECEIPT_KEY: "true"
        }
      }).currentKeyRecord({ activatedAt: "2026-05-03T09:46:00.000Z" })
    ).not.toThrow();
  });

  it("requires operator auth, rejects spoofed actors, and derives operator identity from the token", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });
    const record = await runtime.app.inject({
      method: "POST",
      url: "/v1/decisions",
      payload: {
        site_id: "sit_operator_auth",
        request_id: "req_operator_auth_1",
        actor_class: "signed_agent",
        decision: "queue",
        route_template: "/checkout",
        method: "POST",
        reason_codes: ["matched_policy"],
        occurred_at: "2026-04-29T01:00:00.000Z"
      }
    });
    expect(record.statusCode).toBe(201);
    const decisionId = record.json<{ decision: { id: string } }>().decision.id;

    const missing = await runtime.app.inject({
      method: "PATCH",
      url: `/v1/decisions/${decisionId}/operator-action`,
      payload: { operator_action: "deny", operator_reason: "missing token" }
    });
    expect(missing.statusCode).toBe(401);
    expect(missing.json()).toMatchObject({ error: "operator_auth_required" });

    const invalid = await runtime.app.inject({
      method: "PATCH",
      url: `/v1/decisions/${decisionId}/operator-action`,
      headers: { Authorization: bearerHeader("not_the_real_operator_token") },
      payload: { operator_action: "deny", operator_reason: "invalid token" }
    });
    expect(invalid.statusCode).toBe(401);
    expect(invalid.json()).toMatchObject({ error: "invalid_operator_token" });

    const forbidden = await runtime.app.inject({
      method: "PATCH",
      url: `/v1/decisions/${decisionId}/operator-action`,
      headers: TEST_VIEWER_HEADERS,
      payload: { operator_action: "deny", operator_reason: "viewer cannot override" }
    });
    expect(forbidden.statusCode).toBe(403);
    expect(forbidden.json()).toMatchObject({ error: "operator_forbidden", required_role: "decision_operator" });

    const spoofedActor = await runtime.app.inject({
      method: "PATCH",
      url: `/v1/decisions/${decisionId}/operator-action`,
      headers: TEST_OPERATOR_HEADERS,
      payload: {
        operator_action: "deny",
        operator_actor_id: "spoofed_admin",
        operator_reason: "client-supplied actor must be rejected"
      }
    });
    expect(spoofedActor.statusCode).toBe(400);
    expect(spoofedActor.json()).toMatchObject({ error: "invalid_operator_action" });

    const action = await runtime.app.inject({
      method: "PATCH",
      url: `/v1/decisions/${decisionId}/operator-action`,
      headers: { "x-aidenid-operator-token": TEST_OPERATOR_TOKEN },
      payload: { operator_action: "deny", operator_reason: "server-side actor binding" }
    });
    expect(action.statusCode).toBe(200);
    expect(action.json()).toMatchObject({
      decision: {
        id: decisionId,
        operator_action: "deny",
        operator_action_actor_id: "ciso_demo",
        operator_action_reason: "server-side actor binding"
      }
    });
    await runtime.app.close();
  });

  it("persists an authenticated operator reputation directory scoped by site", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });

    const missing = await runtime.app.inject({
      method: "GET",
      url: "/v1/operators/reputation?site_id=sit_operator_rep"
    });
    expect(missing.statusCode).toBe(401);
    expect(missing.json()).toMatchObject({ error: "operator_auth_required" });

    const forbidden = await runtime.app.inject({
      method: "GET",
      url: "/v1/operators/reputation?site_id=sit_operator_rep",
      headers: TEST_VIEWER_HEADERS
    });
    expect(forbidden.statusCode).toBe(403);
    expect(forbidden.json()).toMatchObject({ error: "operator_forbidden", required_role: "operator_reputation" });

    const create = await runtime.app.inject({
      method: "PUT",
      url: "/v1/operators/reputation/ops_alice",
      headers: TEST_REPUTATION_HEADERS,
      payload: {
        site_id: "sit_operator_rep",
        display_name: "Alice Ops",
        trust_tier: "trusted",
        status: "active",
        reputation_score: 92,
        notes: "cleared for customer-facing overrides",
        last_reviewed_at: "2026-05-02T00:00:00.000Z",
        updated_by: "spoofed"
      }
    });
    expect(create.statusCode).toBe(400);
    expect(create.json()).toMatchObject({ error: "invalid_operator_reputation" });

    const created = await runtime.app.inject({
      method: "PUT",
      url: "/v1/operators/reputation/ops_alice",
      headers: TEST_REPUTATION_HEADERS,
      payload: {
        site_id: "sit_operator_rep",
        display_name: "Alice Ops",
        trust_tier: "trusted",
        status: "active",
        reputation_score: 92,
        default_action: "queue",
        default_scope_routes: ["/docs", "/pricing/*"],
        default_scope_redirect_path: "/agent-access",
        notes: "cleared for customer-facing overrides",
        last_reviewed_at: "2026-05-02T00:00:00.000Z",
        expires_at: "2099-05-02T00:00:00.000Z"
      }
    });
    expect(created.statusCode).toBe(201);
    const firstOperator = created.json<{ operator: { id: string; created_at: string } }>().operator;
    expect(created.json()).toMatchObject({
      operator: {
        id: expect.stringMatching(/^opr_/),
        site_id: "sit_operator_rep",
        operator_actor_id: "ops_alice",
        display_name: "Alice Ops",
        trust_tier: "trusted",
        status: "active",
        reputation_score: 92,
        default_action: "queue",
        default_scope_routes: ["/docs", "/pricing/*"],
        default_scope_redirect_path: "/agent-access",
        notes: "cleared for customer-facing overrides",
        last_reviewed_at: "2026-05-02T00:00:00.000Z",
        expires_at: "2099-05-02T00:00:00.000Z",
        updated_by: "risk_ops"
      }
    });

    const update = await runtime.app.inject({
      method: "PUT",
      url: "/v1/operators/reputation/ops_alice",
      headers: TEST_REPUTATION_HEADERS,
      payload: {
        site_id: "sit_operator_rep",
        display_name: "Alice Ops",
        trust_tier: "restricted",
        status: "watchlist",
        reputation_score: 41,
        default_action: "deny",
        default_scope_routes: [],
        notes: "recent override reversal"
      }
    });
    expect(update.statusCode).toBe(200);
    expect(update.json()).toMatchObject({
      operator: {
        id: firstOperator.id,
        created_at: firstOperator.created_at,
        trust_tier: "restricted",
        status: "watchlist",
        reputation_score: 41,
        default_action: "deny",
        default_scope_routes: [],
        expires_at: "2099-05-02T00:00:00.000Z",
        updated_by: "risk_ops"
      }
    });

    const fetched = await runtime.app.inject({
      method: "GET",
      url: "/v1/operators/reputation/ops_alice?site_id=sit_operator_rep",
      headers: TEST_REPUTATION_HEADERS
    });
    expect(fetched.statusCode).toBe(200);
    expect(fetched.json()).toMatchObject({
      operator: {
        operator_actor_id: "ops_alice",
        status: "watchlist",
        default_action: "deny",
        default_scope_routes: [],
        expires_at: "2099-05-02T00:00:00.000Z"
      }
    });

    const expiredActiveUpdate = await runtime.app.inject({
      method: "PUT",
      url: "/v1/operators/reputation/ops_alice",
      headers: TEST_REPUTATION_HEADERS,
      payload: {
        site_id: "sit_operator_rep",
        trust_tier: "restricted",
        status: "active",
        reputation_score: 41,
        expires_at: "2000-01-01T00:00:00.000Z"
      }
    });
    expect(expiredActiveUpdate.statusCode).toBe(400);
    expect(expiredActiveUpdate.json()).toMatchObject({ error: "operator_reputation_expiry_expired" });

    const expiredBeforeCreatedUpdate = await runtime.app.inject({
      method: "PUT",
      url: "/v1/operators/reputation/ops_alice",
      headers: TEST_REPUTATION_HEADERS,
      payload: {
        site_id: "sit_operator_rep",
        trust_tier: "restricted",
        status: "expired",
        reputation_score: 41,
        expires_at: "2000-01-01T00:00:00.000Z"
      }
    });
    expect(expiredBeforeCreatedUpdate.statusCode).toBe(400);
    expect(expiredBeforeCreatedUpdate.json()).toMatchObject({ error: "operator_reputation_expiry_expired" });

    const missingSite = await runtime.app.inject({
      method: "GET",
      url: "/v1/operators/reputation/ops_alice?site_id=sit_other",
      headers: TEST_REPUTATION_HEADERS
    });
    expect(missingSite.statusCode).toBe(404);
    expect(missingSite.json()).toMatchObject({ error: "operator_reputation_not_found" });

    const listed = await runtime.app.inject({
      method: "GET",
      url: "/v1/operators/reputation?site_id=sit_operator_rep&status=watchlist&trust_tier=restricted",
      headers: TEST_REPUTATION_HEADERS
    });
    expect(listed.statusCode).toBe(200);
    expect(listed.json()).toMatchObject({
      operators: [expect.objectContaining({ operator_actor_id: "ops_alice", status: "watchlist", trust_tier: "restricted" })]
    });
    await runtime.app.close();
  });

  it("accepts agent identity challenge submissions and lists them for operator review", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });

    const invalid = await runtime.app.inject({
      method: "POST",
      url: "/v1/identities",
      payload: {
        site_id: "sit_identity",
        purpose: "Research",
        provider_name: "Example Agent Lab",
        cascade_attestation: ["crypto_identity"]
      }
    });
    expect(invalid.statusCode).toBe(400);
    expect(invalid.json()).toMatchObject({ error: "invalid_identity_challenge_submission" });

    const accepted = await runtime.app.inject({
      method: "POST",
      url: "/v1/identities",
      payload: {
        site_id: "sit_identity",
        request_id: "req_identity_1",
        purpose: "research",
        requested_access_duration_seconds: 3_600,
        provider_name: "Example Agent Lab",
        operator_actor_id: "operator:example-lab",
        contact_url: "https://example.com/security",
        jwks_url: "https://example.com/.well-known/aidenid-jwks.json",
        delegation_authority_jwk_thumbprint_sha256: "a".repeat(64),
        cascade_attestation: [
          "crypto_identity",
          "delegation_authorization",
          "fingerprint_sidecar",
          "operator_reputation"
        ],
        declaration: "We are requesting access for an agentic research workflow."
      }
    });
    expect(accepted.statusCode).toBe(202);
    const acceptedSubmission = accepted.json<{ submission: { id: string; requested_access_expires_at: string } }>().submission;
    const acceptedSubmissionId = acceptedSubmission.id;
    const shortenedApprovalExpiresAt = new Date(Date.parse(acceptedSubmission.requested_access_expires_at) - 600_000).toISOString();
    expect(accepted.json()).toMatchObject({
      submission: {
        id: expect.stringMatching(/^ais_/),
        site_id: "sit_identity",
        request_id: "req_identity_1",
        purpose: "research",
        requested_access_duration_seconds: 3_600,
        requested_access_expires_at: expect.any(String),
        provider_name: "Example Agent Lab",
        operator_actor_id: "operator:example-lab",
        delegation_authority_jwk_thumbprint_sha256: "a".repeat(64),
        status: "pending_review"
      },
      next_steps: expect.arrayContaining(["operator_review_required", "register_http_signature_jwks"])
    });

    const replayed = await runtime.app.inject({
      method: "POST",
      url: "/v1/identities",
      payload: {
        site_id: "sit_identity",
        request_id: "req_identity_1",
        purpose: "research",
        requested_access_duration_seconds: 3_600,
        provider_name: "Example Agent Lab",
        operator_actor_id: "operator:example-lab",
        contact_url: "https://example.com/security",
        jwks_url: "https://example.com/.well-known/aidenid-jwks.json",
        delegation_authority_jwk_thumbprint_sha256: "a".repeat(64),
        cascade_attestation: [
          "crypto_identity",
          "delegation_authorization",
          "fingerprint_sidecar",
          "operator_reputation"
        ],
        declaration: "We are requesting access for an agentic research workflow."
      }
    });
    expect(replayed.statusCode).toBe(429);
    expect(replayed.headers["retry-after"]).toBeDefined();
    expect(replayed.json()).toMatchObject({ error: "identity_submission_duplicate" });

    const claimCooldown = await runtime.app.inject({
      method: "POST",
      url: "/v1/identities",
      payload: {
        site_id: "sit_identity",
        request_id: "req_identity_2",
        purpose: "commercial_crawl",
        requested_access_duration_seconds: 1_800,
        provider_name: "Example Agent Lab",
        operator_actor_id: "operator:example-lab",
        contact_url: "https://example.com/security",
        cascade_attestation: [
          "crypto_identity",
          "delegation_authorization",
          "fingerprint_sidecar",
          "operator_reputation"
        ]
      }
    });
    expect(claimCooldown.statusCode).toBe(429);
    expect(claimCooldown.json()).toMatchObject({ error: "identity_operator_claim_cooldown" });

    const tooLarge = await runtime.app.inject({
      method: "POST",
      url: "/v1/identities",
      payload: {
        site_id: "sit_identity",
        purpose: "other",
        purpose_rationale: "x".repeat(17_000),
        provider_name: "Payload Too Large Lab",
        cascade_attestation: [
          "crypto_identity",
          "delegation_authorization",
          "fingerprint_sidecar",
          "operator_reputation"
        ]
      }
    });
    expect(tooLarge.statusCode).toBe(413);

    let rateLimitedStatus = 0;
    for (let index = 0; index < 11; index += 1) {
      const response = await runtime.app.inject({
        method: "POST",
        url: "/v1/identities",
        headers: { "x-forwarded-for": "198.51.100.55" },
        payload: {
          site_id: "sit_rate",
          request_id: `req_rate_${index}`,
          purpose: "monitoring_uptime",
          requested_access_duration_seconds: 900,
          provider_name: `Rate Test Lab ${index}`,
          operator_actor_id: `operator:rate-${index}`,
          contact_url: `https://example.com/rate-${index}`,
          cascade_attestation: [
            "crypto_identity",
            "delegation_authorization",
            "fingerprint_sidecar",
            "operator_reputation"
          ]
        }
      });
      rateLimitedStatus = response.statusCode;
    }
    expect(rateLimitedStatus).toBe(429);

    const missing = await runtime.app.inject({
      method: "GET",
      url: "/v1/identities/submissions?site_id=sit_identity"
    });
    expect(missing.statusCode).toBe(401);
    expect(missing.json()).toMatchObject({ error: "operator_auth_required" });

    const forbidden = await runtime.app.inject({
      method: "GET",
      url: "/v1/identities/submissions?site_id=sit_identity",
      headers: TEST_VIEWER_HEADERS
    });
    expect(forbidden.statusCode).toBe(403);
    expect(forbidden.json()).toMatchObject({ error: "operator_forbidden", required_role: "operator_reputation" });

    const listed = await runtime.app.inject({
      method: "GET",
      url: "/v1/identities/submissions?site_id=sit_identity&status=pending_review",
      headers: TEST_REPUTATION_HEADERS
    });
    expect(listed.statusCode).toBe(200);
    expect(listed.json()).toMatchObject({
      submissions: [
        expect.objectContaining({
          site_id: "sit_identity",
          provider_name: "Example Agent Lab",
          requested_access_duration_seconds: 3_600,
          requested_access_expires_at: expect.any(String),
          cascade_attestation: [
            "crypto_identity",
            "delegation_authorization",
            "fingerprint_sidecar",
            "operator_reputation"
          ]
        })
      ]
    });

    const missingReviewAuth = await runtime.app.inject({
      method: "PATCH",
      url: `/v1/identities/submissions/${acceptedSubmissionId}/review`,
      payload: { action: "approve" }
    });
    expect(missingReviewAuth.statusCode).toBe(401);

    const forbiddenReview = await runtime.app.inject({
      method: "PATCH",
      url: `/v1/identities/submissions/${acceptedSubmissionId}/review`,
      headers: TEST_VIEWER_HEADERS,
      payload: { action: "approve" }
    });
    expect(forbiddenReview.statusCode).toBe(403);
    expect(forbiddenReview.json()).toMatchObject({ error: "operator_forbidden", required_role: "operator_reputation" });

    const overlongApproval = await runtime.app.inject({
      method: "PATCH",
      url: `/v1/identities/submissions/${acceptedSubmissionId}/review`,
      headers: TEST_REPUTATION_HEADERS,
      payload: {
        action: "approve",
        approval_expires_at: new Date(Date.parse(acceptedSubmission.requested_access_expires_at) + 1_000).toISOString()
      }
    });
    expect(overlongApproval.statusCode).toBe(400);
    expect(overlongApproval.json()).toMatchObject({ error: "identity_review_expiry_exceeds_requested_access" });

    const approved = await runtime.app.inject({
      method: "PATCH",
      url: `/v1/identities/submissions/${acceptedSubmissionId}/review`,
      headers: TEST_REPUTATION_HEADERS,
      payload: {
        action: "approve",
        trust_tier: "trusted",
        operator_status: "active",
        reputation_score: 91,
        default_action: "sandbox",
        default_scope_routes: ["/research/*"],
        default_scope_redirect_path: "/agent-access",
        approval_expires_at: shortenedApprovalExpiresAt,
        review_reason: "security contact and JWKS verified"
      }
    });
    expect(approved.statusCode).toBe(200);
    expect(approved.json()).toMatchObject({
      submission: {
        id: acceptedSubmissionId,
        status: "approved",
        review_decision: "approve",
        reviewer_identity_hash_sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        review_reason: "security contact and JWKS verified",
        approved_operator_actor_id: "operator:example-lab",
        operator_reputation_id: expect.stringMatching(/^opr_/),
        assigned_trust_tier: "trusted",
        assigned_operator_status: "active",
        assigned_reputation_score: 91
      },
      operator: {
        site_id: "sit_identity",
        operator_actor_id: "operator:example-lab",
        display_name: "Example Agent Lab",
        trust_tier: "trusted",
        status: "active",
        reputation_score: 91,
        default_action: "sandbox",
        default_scope_routes: ["/research/*"],
        default_scope_redirect_path: "/agent-access",
        expires_at: shortenedApprovalExpiresAt,
        updated_by: expect.stringMatching(/^[a-f0-9]{64}$/)
      }
    });

    const approvalNotifications = await runtime.app.inject({
      method: "GET",
      url: "/v1/identities/review-notifications?site_id=sit_identity&status=unread",
      headers: TEST_REPUTATION_HEADERS
    });
    expect(approvalNotifications.statusCode).toBe(200);
    expect(approvalNotifications.json()).toMatchObject({
      notifications: [
        expect.objectContaining({
          id: expect.stringMatching(/^arn_/),
          site_id: "sit_identity",
          submission_id: acceptedSubmissionId,
          review_decision: "approve",
          provider_name: "Example Agent Lab",
          operator_actor_id: "operator:example-lab",
          contact_url: "https://example.com/security",
          reviewer_identity_hash_sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
          review_reason: "security contact and JWKS verified",
          status: "unread"
        })
      ]
    });
    const approvalNotificationId = approvalNotifications.json<{ notifications: { id: string }[] }>().notifications[0]!.id;
    const markedRead = await runtime.app.inject({
      method: "PATCH",
      url: `/v1/identities/review-notifications/${approvalNotificationId}`,
      headers: TEST_REPUTATION_HEADERS,
      payload: { status: "read" }
    });
    expect(markedRead.statusCode).toBe(200);
    expect(markedRead.json()).toMatchObject({
      notification: {
        id: approvalNotificationId,
        status: "read",
        read_at: expect.any(String)
      }
    });

    const promotedOperator = await runtime.app.inject({
      method: "GET",
      url: "/v1/operators/reputation/operator%3Aexample-lab?site_id=sit_identity",
      headers: TEST_REPUTATION_HEADERS
    });
    expect(promotedOperator.statusCode).toBe(200);
    expect(promotedOperator.json()).toMatchObject({
      operator: {
        operator_actor_id: "operator:example-lab",
        trust_tier: "trusted",
        status: "active"
      }
    });

    const repeatReview = await runtime.app.inject({
      method: "PATCH",
      url: `/v1/identities/submissions/${acceptedSubmissionId}/review`,
      headers: TEST_REPUTATION_HEADERS,
      payload: { action: "reject", review_reason: "late rejection must not overwrite approval" }
    });
    expect(repeatReview.statusCode).toBe(409);
    expect(repeatReview.json()).toMatchObject({
      error: "identity_submission_already_reviewed",
      submission: { status: "approved" }
    });

    const needsOperator = await runtime.app.inject({
      method: "POST",
      url: "/v1/identities",
      payload: {
        site_id: "sit_identity",
        request_id: "req_identity_needs_operator",
        purpose: "search_indexing",
        requested_access_duration_seconds: 7_200,
        provider_name: "Missing Operator Lab",
        contact_url: "https://missing-operator.example/security",
        cascade_attestation: [
          "crypto_identity",
          "delegation_authorization",
          "fingerprint_sidecar",
          "operator_reputation"
        ]
      }
    });
    expect(needsOperator.statusCode).toBe(202);
    const needsOperatorId = needsOperator.json<{ submission: { id: string } }>().submission.id;
    const missingOperatorApproval = await runtime.app.inject({
      method: "PATCH",
      url: `/v1/identities/submissions/${needsOperatorId}/review`,
      headers: TEST_REPUTATION_HEADERS,
      payload: { action: "approve" }
    });
    expect(missingOperatorApproval.statusCode).toBe(400);
    expect(missingOperatorApproval.json()).toMatchObject({ error: "identity_review_operator_actor_id_required" });

    const rejectable = await runtime.app.inject({
      method: "POST",
      url: "/v1/identities",
      payload: {
        site_id: "sit_identity",
        request_id: "req_identity_reject",
        purpose: "competitive_intelligence",
        requested_access_duration_seconds: 3_600,
        provider_name: "Reject Lab",
        operator_actor_id: "operator:reject-lab",
        contact_url: "https://reject.example/security",
        cascade_attestation: [
          "crypto_identity",
          "delegation_authorization",
          "fingerprint_sidecar",
          "operator_reputation"
        ]
      }
    });
    expect(rejectable.statusCode).toBe(202);
    const rejectableId = rejectable.json<{ submission: { id: string } }>().submission.id;
    const rejected = await runtime.app.inject({
      method: "PATCH",
      url: `/v1/identities/submissions/${rejectableId}/review`,
      headers: TEST_REPUTATION_HEADERS,
      payload: { action: "reject", review_reason: "purpose is disallowed for this site" }
    });
    expect(rejected.statusCode).toBe(200);
    expect(rejected.json()).toMatchObject({
      submission: {
        id: rejectableId,
        status: "rejected",
        review_decision: "reject",
        reviewer_identity_hash_sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        review_reason: "purpose is disallowed for this site"
      }
    });
    expect(rejected.json()).not.toHaveProperty("operator");

    const rejectionNotifications = await runtime.app.inject({
      method: "GET",
      url: "/v1/identities/review-notifications?site_id=sit_identity&status=unread",
      headers: TEST_REPUTATION_HEADERS
    });
    expect(rejectionNotifications.statusCode).toBe(200);
    expect(rejectionNotifications.json()).toMatchObject({
      notifications: [
        expect.objectContaining({
          submission_id: rejectableId,
          review_decision: "reject",
          provider_name: "Reject Lab",
          review_reason: "purpose is disallowed for this site",
          status: "unread"
        })
      ]
    });

    const rejectedOperator = await runtime.app.inject({
      method: "GET",
      url: "/v1/operators/reputation/operator%3Areject-lab?site_id=sit_identity",
      headers: TEST_REPUTATION_HEADERS
    });
    expect(rejectedOperator.statusCode).toBe(404);

    await runtime.app.close();
  });

  it("fails closed when operator auth is not configured", async () => {
    const runtime = await createControlPlaneRuntime();
    const record = await runtime.app.inject({
      method: "POST",
      url: "/v1/decisions",
      payload: {
        site_id: "sit_operator_auth_missing",
        request_id: "req_operator_auth_missing_1",
        actor_class: "signed_agent",
        decision: "queue",
        route_template: "/checkout",
        method: "POST",
        reason_codes: ["matched_policy"],
        occurred_at: "2026-04-29T01:00:00.000Z"
      }
    });
    expect(record.statusCode).toBe(201);
    const decisionId = record.json<{ decision: { id: string } }>().decision.id;
    const action = await runtime.app.inject({
      method: "PATCH",
      url: `/v1/decisions/${decisionId}/operator-action`,
      payload: { operator_action: "deny", operator_reason: "no auth configured" }
    });
    expect(action.statusCode).toBe(503);
    expect(action.json()).toMatchObject({ error: "operator_auth_not_configured" });
    await runtime.app.close();
  });

  it("loads operator auth from the JSON environment registry shape", async () => {
    const envToken = "test_env_operator_token_123456";
    const runtime = await createControlPlaneRuntime({
      operatorAuth: {
        env: JSON.stringify({
          env_ciso: { token: envToken, roles: ["decision_operator"] }
        })
      }
    });
    const record = await runtime.app.inject({
      method: "POST",
      url: "/v1/decisions",
      payload: {
        site_id: "sit_operator_env",
        request_id: "req_operator_env_1",
        actor_class: "verified_agent",
        decision: "queue",
        route_template: "/checkout",
        method: "POST",
        reason_codes: ["matched_policy"],
        occurred_at: "2026-04-29T01:00:00.000Z"
      }
    });
    expect(record.statusCode).toBe(201);
    const decisionId = record.json<{ decision: { id: string } }>().decision.id;
    const action = await runtime.app.inject({
      method: "PATCH",
      url: `/v1/decisions/${decisionId}/operator-action`,
      headers: { Authorization: bearerHeader(envToken) },
      payload: { operator_action: "deny", operator_reason: "environment registry" }
    });
    expect(action.statusCode).toBe(200);
    expect(action.json()).toMatchObject({
      decision: {
        operator_action: "deny",
        operator_action_actor_id: "env_ciso",
        operator_action_reason: "environment registry"
      }
    });
    await runtime.app.close();
  });

  it("records operator actions and wakes decision awaiters through the outbox", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });
    const record = await runtime.app.inject({
      method: "POST",
      url: "/v1/decisions",
      payload: {
        site_id: "sit_operator",
        request_id: "req_operator_1",
        actor_class: "signed_agent",
        decision: "queue",
        route_template: "/checkout",
        method: "POST",
        reason_codes: ["matched_policy"],
        occurred_at: "2026-04-29T01:00:00.000Z"
      }
    });
    expect(record.statusCode).toBe(201);
    const decisionId = record.json<{ decision: { id: string } }>().decision.id;

    const awaitingDecision = runtime.app.inject({
      method: "GET",
      url: `/v1/decisions/${decisionId}/await?timeout_ms=1000`,
      headers: TEST_VIEWER_HEADERS
    });
    await delay(20);
    const action = await runtime.app.inject({
      method: "PATCH",
      url: `/v1/decisions/${decisionId}/operator-action`,
      headers: TEST_OPERATOR_HEADERS,
      payload: {
        operator_action: "deny",
        operator_reason: "manual override during sit-down"
      }
    });
    expect(action.statusCode).toBe(200);
    expect(action.json()).toMatchObject({
      decision: {
        id: decisionId,
        operator_action: "deny",
        operator_action_actor_id: "ciso_demo",
        operator_action_reason: "manual override during sit-down"
      },
      outbox: { event_type: "updated" }
    });

    const awaited = await awaitingDecision;
    expect(awaited.statusCode).toBe(200);
    expect(awaited.json()).toMatchObject({
      status: "resolved",
      decision: {
        id: decisionId,
        operator_action: "deny",
        operator_action_actor_id: "ciso_demo"
      }
    });

    const events = await runtime.services.store.listDecisionOutboxAfter(0, 10);
    expect(events).toEqual([
      expect.objectContaining({ eventType: "recorded", decisionId }),
      expect.objectContaining({
        eventType: "updated",
        decisionId,
        payload: expect.objectContaining({ operator_action: "deny", operator_action_actor_id: "ciso_demo" })
      })
    ]);
    await runtime.app.close();
  });

  it("records quarantine as a composite operator action with actor-pin TTL evidence", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });
    const record = await runtime.app.inject({
      method: "POST",
      url: "/v1/decisions",
      payload: {
        site_id: "sit_quarantine",
        request_id: "req_quarantine_1",
        actor_class: "verified_agent",
        decision: "allow",
        route_template: "/benefits/PHI/*",
        method: "GET",
        reason_codes: ["matched_policy"],
        subject_handle: "sub_quarantine_subject",
        issuer: "https://partner-broker.example",
        occurred_at: "2026-04-29T01:00:00.000Z"
      }
    });
    expect(record.statusCode).toBe(201);
    const decisionId = record.json<{ decision: { id: string } }>().decision.id;

    const action = await runtime.app.inject({
      method: "PATCH",
      url: `/v1/decisions/${decisionId}/operator-action`,
      headers: TEST_OPERATOR_HEADERS,
      payload: {
        operator_action: "quarantine",
        operator_reason: "manual quarantine",
        operator_ttl_seconds: 120
      }
    });
    expect(action.statusCode).toBe(200);
    expect(action.json()).toMatchObject({
      decision: {
        id: decisionId,
        operator_action: "quarantine",
        operator_action_effective_decision: "deny",
        operator_action_effects: ["deny", "actor_pin", "ocsf_emit", "webhook_emit"]
      }
    });

    const pins = await runtime.app.inject({
      method: "GET",
      url: "/v1/quarantine/pins?site_id=sit_quarantine",
      headers: TEST_VIEWER_HEADERS
    });
    expect(pins.statusCode).toBe(200);
    expect(pins.json()).toMatchObject({
      pins: [
        {
          decision_id: decisionId,
          site_id: "sit_quarantine",
          issuer: "https://partner-broker.example",
          subject_handle: "sub_quarantine_subject",
          operator_actor_id: "ciso_demo"
        }
      ]
    });

    expect(runtime.outboxStore.all()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "DECISION_QUARANTINE_APPLIED",
          payload: expect.objectContaining({
            id: decisionId,
            operator_action: "quarantine",
            operator_action_effective_decision: "deny",
            operator_action_ttl_seconds: 120,
            decision_outbox_seq: expect.any(Number)
          })
        }),
        expect.objectContaining({
          type: "OCSF_DECISION_EMIT_REQUESTED",
          payload: expect.objectContaining({
            id: decisionId,
            operator_action: "quarantine",
            decision_outbox_seq: expect.any(Number)
          })
        }),
        expect.objectContaining({
          type: "WEBHOOK_DECISION_EMIT_REQUESTED",
          payload: expect.objectContaining({
            id: decisionId,
            operator_action: "quarantine",
            decision_outbox_seq: expect.any(Number)
          })
        })
      ])
    );
    await runtime.app.close();
  });

  it("returns pending from decision await when no operator action arrives before timeout", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });
    const record = await runtime.app.inject({
      method: "POST",
      url: "/v1/decisions",
      payload: {
        site_id: "sit_operator_timeout",
        request_id: "req_operator_timeout_1",
        actor_class: "unknown",
        decision: "throttle",
        route_template: "/checkout",
        method: "POST"
      }
    });
    const decisionId = record.json<{ decision: { id: string } }>().decision.id;
    const awaited = await runtime.app.inject({
      method: "GET",
      url: `/v1/decisions/${decisionId}/await?timeout_ms=1`,
      headers: TEST_VIEWER_HEADERS
    });

    expect(awaited.statusCode).toBe(202);
    expect(awaited.json()).toMatchObject({ status: "pending", decision: { id: decisionId, decision: "throttle" } });
    await runtime.app.close();
  });

  it("exposes adoption controls for billing, quotas, counterfactuals, privacy erase, webhooks, onboarding, and MCP roadmap", async () => {
    const runtime = await createControlPlaneRuntime({
      operatorAuth: TEST_OPERATOR_AUTH,
      webhookSecrets: new StaticWebhookSecretResolver({ "aws-sm://aidenid/webhook/demo": "resolved-demo-webhook-secret" })
    });
    const quota = await runtime.app.inject({
      method: "PUT",
      url: "/v1/tenants/ten_demo/quota",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        monthly_decision_limit: 10,
        stored_decision_limit: 100,
        target_limit: 3
      }
    });
    expect(quota.statusCode).toBe(200);
    expect(quota.json()).toMatchObject({ quota: { tenant_id: "ten_demo", monthly_decision_limit: 10 } });

    const pricingPlan = await runtime.app.inject({
      method: "PUT",
      url: "/v1/tenants/ten_demo/pricing-plan",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        plan_tier: "growth",
        unit_price_usd: 0.0002,
        included_monthly_cleared_decisions: 1,
        effective_from: "2026-04-01T00:00:00.000Z"
      }
    });
    expect(pricingPlan.statusCode).toBe(200);
    expect(pricingPlan.json()).toMatchObject({
      pricing_plan: {
        tenant_id: "ten_demo",
        plan_tier: "growth",
        unit_price_usd: 0.0002,
        included_monthly_cleared_decisions: 1
      }
    });

    await runtime.app.inject({
      method: "POST",
      url: "/v1/targets",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        tenant_id: "ten_demo",
        site_id: "sit_adopt",
        name: "Adoption Shop",
        origin: "https://adopt.example.com"
      }
    });

    for (const [index, recommendedDecision] of ["allow", "deny", "throttle"].entries()) {
      const response = await runtime.app.inject({
        method: "POST",
        url: "/v1/decisions",
        payload: {
          site_id: "sit_adopt",
          request_id: `req_adopt_${index}`,
          actor_class: index === 0 ? "verified_agent" : "suspicious_automation",
          decision: "allow",
          recommended_decision: recommendedDecision,
          route_template: "/checkout",
          method: "POST",
          occurred_at: `2026-04-01T00:00:0${index}.000Z`,
          latency_us: 100 + index,
          subject_handle: "sub_demo_subject"
        }
      });
      expect(response.statusCode).toBe(201);
    }
    const priceDecision = await runtime.app.inject({
      method: "POST",
      url: "/v1/decisions",
      payload: {
        site_id: "sit_adopt",
        request_id: "req_adopt_price_1",
        actor_class: "verified_agent",
        decision: "price_required",
        recommended_decision: "price_required",
        route_template: "/premium-content/*",
        method: "GET",
        occurred_at: "2026-04-01T00:00:03.000Z",
        latency_us: 90,
        issuer: "https://partner-broker.example",
        llm_brand: "openai",
        price_usd: 0.01,
        reason_codes: ["price_required"]
      }
    });
    expect(priceDecision.statusCode).toBe(201);
    expect(priceDecision.json()).toMatchObject({ decision: { llm_brand: "openai" } });

    const usage = await runtime.app.inject({
      method: "GET",
      url: "/v1/usage/meter?site_id=sit_adopt&tenant_id=ten_demo",
      headers: TEST_VIEWER_HEADERS
    });
    expect(usage.statusCode).toBe(200);
    expect(usage.json()).toMatchObject({
      usage: {
        site_id: "sit_adopt",
        tenant_id: "ten_demo",
        decision_count: 4,
        cleared_decision_count: 4,
        billable_cleared_decision_count: 4,
        included_cleared_decision_count: 1,
        overage_cleared_decision_count: 3,
        pricing_plan_tier: "growth",
        billing_unit_price_usd: 0.0002,
        estimated_cost_usd: 0.0006,
        price_required_gross_usd: 0.01,
        quota_status: "ok"
      }
    });

    const priced = await runtime.app.inject({
      method: "GET",
      url: "/v1/usage/price-required?site_id=sit_adopt&tenant_id=ten_demo",
      headers: TEST_VIEWER_HEADERS
    });
    expect(priced.statusCode).toBe(200);
    expect(priced.json()).toMatchObject({
      price_required_billing: {
        site_id: "sit_adopt",
        tenant_id: "ten_demo",
        decision_count: 1,
        priced_decision_count: 1,
        estimated_gross_usd: 0.01,
        by_issuer: [
          {
            issuer: "https://partner-broker.example",
            decision_count: 1,
            estimated_gross_usd: 0.01
          }
        ]
      }
    });

    const rollup = await runtime.app.inject({
      method: "POST",
      url: "/v1/billing/rollups",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        tenant_id: "ten_demo",
        period_start: "2026-04-01T00:00:00.000Z",
        period_end: "2026-04-02T00:00:00.000Z"
      }
    });
    expect(rollup.statusCode).toBe(201);
    const rollupBody = rollup.json<{
      billing_rollup: {
        id: string;
        invoice_line_item_id: string;
        export_idempotency_key: string;
      };
    }>();
    expect(rollupBody).toMatchObject({
      billing_rollup: {
        tenant_id: "ten_demo",
        period_start: "2026-04-01T00:00:00.000Z",
        period_end: "2026-04-02T00:00:00.000Z",
        plan_tier: "growth",
        cleared_decision_count: 4,
        billable_cleared_decision_count: 4,
        overage_cleared_decision_count: 3,
        estimated_cost_usd: 0.0006,
        price_required_gross_usd: 0.01
      }
    });
    expect(rollupBody.billing_rollup.id).toMatch(/^bil_[a-f0-9]{32}$/);
    expect(rollupBody.billing_rollup.invoice_line_item_id).toMatch(/^ili_[a-f0-9]{32}$/);
    expect(rollupBody.billing_rollup.export_idempotency_key).toMatch(/^[a-f0-9]{64}$/);
    const fetchedRollup = await runtime.app.inject({
      method: "GET",
      url: "/v1/billing/rollups?tenant_id=ten_demo&period_start=2026-04-01T00%3A00%3A00.000Z&period_end=2026-04-02T00%3A00%3A00.000Z",
      headers: TEST_VIEWER_HEADERS
    });
    expect(fetchedRollup.statusCode).toBe(200);
    expect(fetchedRollup.json()).toMatchObject({
      billing_rollup: {
        id: rollupBody.billing_rollup.id,
        invoice_line_item_id: rollupBody.billing_rollup.invoice_line_item_id,
        export_idempotency_key: rollupBody.billing_rollup.export_idempotency_key
      }
    });

    const stripeExport = await runtime.app.inject({
      method: "POST",
      url: "/v1/billing/exports",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        tenant_id: "ten_demo",
        period_start: "2026-04-01T00:00:00.000Z",
        period_end: "2026-04-02T00:00:00.000Z",
        provider: "stripe_meter_event",
        destination_ref: "cus_demo_123"
      }
    });
    expect(stripeExport.statusCode).toBe(201);
    const stripeExportBody = stripeExport.json<{
      billing_export: {
        id: string;
        provider: string;
        destination_ref: string;
        idempotency_key: string;
        payload_sha256: string;
        payload: {
          adapter: string;
          body: { identifier: string; payload: { stripe_customer_id: string; value: string } };
        };
      };
    }>();
    expect(stripeExportBody).toMatchObject({
      billing_export: {
        provider: "stripe_meter_event",
        destination_ref: "cus_demo_123",
        status: "prepared",
        payload: {
          adapter: "stripe_meter_event",
          method: "POST",
          path: "/v1/billing/meter_events",
          body: {
            event_name: "aidenid_cleared_agent_action",
            payload: {
              stripe_customer_id: "cus_demo_123",
              value: "4"
            }
          }
        }
      }
    });
    expect(stripeExportBody.billing_export.id).toMatch(/^bex_[a-f0-9]{32}$/);
    expect(stripeExportBody.billing_export.idempotency_key).toMatch(/^[a-f0-9]{64}$/);
    expect(stripeExportBody.billing_export.payload_sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(stripeExportBody.billing_export.payload.body.identifier).toBe(stripeExportBody.billing_export.idempotency_key);

    const quickBooksExport = await runtime.app.inject({
      method: "POST",
      url: "/v1/billing/exports",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        tenant_id: "ten_demo",
        period_start: "2026-04-01T00:00:00.000Z",
        period_end: "2026-04-02T00:00:00.000Z",
        provider: "quickbooks_invoice",
        destination_ref: "qbo_customer_456"
      }
    });
    expect(quickBooksExport.statusCode).toBe(201);
    expect(quickBooksExport.json()).toMatchObject({
      billing_export: {
        provider: "quickbooks_invoice",
        payload: {
          adapter: "quickbooks_invoice",
          method: "POST",
          path: "/v3/company/{realmId}/invoice",
          body: {
            DocNumber: rollupBody.billing_rollup.invoice_line_item_id,
            CustomerRef: { value: "qbo_customer_456" },
            Line: [
              {
                DetailType: "SalesItemLineDetail",
                Amount: 0.0006,
                SalesItemLineDetail: {
                  Qty: 3,
                  UnitPrice: 0.0002,
                  ItemRef: { value: "AIDENID_CLEARED_ACTION" }
                }
              }
            ]
          }
        }
      }
    });

    const exportsList = await runtime.app.inject({
      method: "GET",
      url:
        "/v1/billing/exports?tenant_id=ten_demo&provider=stripe_meter_event&status=prepared&period_start=2026-04-01T00%3A00%3A00.000Z&period_end=2026-04-02T00%3A00%3A00.000Z",
      headers: TEST_VIEWER_HEADERS
    });
    expect(exportsList.statusCode).toBe(200);
    const filteredExports = exportsList.json<{ billing_exports: Array<{ id: string; provider: string }> }>().billing_exports;
    expect(filteredExports).toHaveLength(1);
    expect(filteredExports[0]).toMatchObject({ id: stripeExportBody.billing_export.id, provider: "stripe_meter_event" });

    const deliveryReceipt = await runtime.app.inject({
      method: "POST",
      url: `/v1/billing/exports/${stripeExportBody.billing_export.id}/delivery-receipt`,
      headers: TEST_ADMIN_HEADERS,
      payload: {
        provider_receipt_id: "mtr_evt_123",
        provider_receipt_status: "accepted",
        provider_response: {
          id: "mtr_evt_123",
          livemode: false,
          object: "billing.meter_event"
        },
        delivered_at: "2026-04-02T00:02:00.000Z"
      }
    });
    expect(deliveryReceipt.statusCode).toBe(200);
    const deliveredExport = deliveryReceipt.json<{
      billing_export: {
        status: string;
        delivered_at: string;
        provider_receipt_id: string;
        provider_receipt_status: string;
        provider_receipt_payload_sha256: string;
        provider_receipt_recorded_at: string;
      };
    }>().billing_export;
    expect(deliveredExport).toMatchObject({
      status: "delivered",
      delivered_at: "2026-04-02T00:02:00.000Z",
      provider_receipt_id: "mtr_evt_123",
      provider_receipt_status: "accepted"
    });
    expect(deliveredExport.provider_receipt_payload_sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(Date.parse(deliveredExport.provider_receipt_recorded_at)).not.toBeNaN();

    const deliveredExportsList = await runtime.app.inject({
      method: "GET",
      url: "/v1/billing/exports?tenant_id=ten_demo&provider=stripe_meter_event&status=delivered",
      headers: TEST_VIEWER_HEADERS
    });
    expect(deliveredExportsList.statusCode).toBe(200);
    expect(deliveredExportsList.json<{ billing_exports: Array<{ id: string; provider_receipt_id?: string }> }>().billing_exports).toEqual([
      expect.objectContaining({ id: stripeExportBody.billing_export.id, provider_receipt_id: "mtr_evt_123" })
    ]);

    const missingExportReceipt = await runtime.app.inject({
      method: "POST",
      url: "/v1/billing/exports/bex_ffffffffffffffffffffffffffffffff/delivery-receipt",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        provider_receipt_id: "mtr_evt_missing",
        provider_receipt_status: "accepted"
      }
    });
    expect(missingExportReceipt.statusCode).toBe(404);
    expect(missingExportReceipt.json()).toMatchObject({ error: "billing_export_not_found" });

    const missingExportRollup = await runtime.app.inject({
      method: "POST",
      url: "/v1/billing/exports",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        tenant_id: "ten_demo",
        period_start: "2026-03-01T00:00:00.000Z",
        period_end: "2026-03-02T00:00:00.000Z",
        provider: "stripe_meter_event",
        destination_ref: "cus_missing"
      }
    });
    expect(missingExportRollup.statusCode).toBe(404);
    expect(missingExportRollup.json()).toMatchObject({ error: "billing_rollup_not_found" });

    const counterfactual = await runtime.app.inject({
      method: "GET",
      url: "/v1/counterfactuals/enforcement?site_id=sit_adopt&route_template=/checkout",
      headers: TEST_VIEWER_HEADERS
    });
    expect(counterfactual.statusCode).toBe(200);
    expect(counterfactual.json()).toMatchObject({
      counterfactual: {
        sample_count: 3,
        currently_blocked: 0,
        would_block_if_enforced: 2,
        newly_blocked_if_enforced: 2
      }
    });

    const webhook = await runtime.app.inject({
      method: "POST",
      url: "/v1/webhooks/endpoints",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        tenant_id: "ten_demo",
        url: "https://hooks.example.com/aidenid",
        event_types: ["decision.recorded"],
        signing_secret_ref: "aws-sm://aidenid/webhook/demo"
      }
    });
    expect(webhook.statusCode).toBe(201);
    const endpointId = webhook.json<{ endpoint: { id: string } }>().endpoint.id;
    const signature = await runtime.app.inject({
      method: "POST",
      url: "/v1/webhooks/signature-preview",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        endpoint_id: endpointId,
        payload: { type: "decision.recorded", id: "dec_1" }
      }
    });
    expect(signature.statusCode).toBe(200);
    const expectedPayload = JSON.stringify({ type: "decision.recorded", id: "dec_1" });
    const expectedSignature = createHmac("sha256", "resolved-demo-webhook-secret")
      .update(`2026-04-25T00:00:00.000Z.${expectedPayload}`, "utf8")
      .digest("base64url");
    expect(signature.json()).toMatchObject({
      payload_sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
      headers: {
        "x-aidenid-webhook-id": endpointId,
        "x-aidenid-webhook-signature": `v1=${expectedSignature}`
      }
    });
    expect(signature.body).not.toContain("aws-sm://aidenid/webhook/demo");

    const erase = await runtime.app.inject({
      method: "POST",
      url: "/v1/privacy/erase",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        site_id: "sit_adopt",
        subject_handle: "sub_demo_subject",
        reason: "dsar",
        actor_id: "platform_admin"
      }
    });
    expect(erase.statusCode).toBe(202);
    expect(erase.json()).toMatchObject({ erasure: { erased_decision_count: 3 } });

    const onboarding = await runtime.app.inject({
      method: "GET",
      url: "/v1/onboarding/target-plan?tenant_id=ten_demo&site_id=sit_new&name=New%20Shop&origin=https%3A%2F%2Fnew.example.com",
      headers: TEST_VIEWER_HEADERS
    });
    expect(onboarding.statusCode).toBe(200);
    expect(onboarding.json()).toMatchObject({
      plan: {
        sdk_install: "pnpm add ./aidenid-verifier-node-0.0.0.tgz",
        sdk: {
          package_name: "@aidenid/verifier-node",
          delivery: "ci_tarball_bundle",
          artifact_name_pattern: "aidenid-verifier-node-sdk-<source_sha>",
          manifest: "aidenid-verifier-node-sdk-manifest.json",
          verify_command: "node verify-verifier-sdk-pack.mjs aidenid-verifier-node-sdk-manifest.json",
          public_registry_available: false,
          public_registry_command_when_published: "pnpm add @aidenid/verifier-node",
          tarballs: ["aidenid-verifier-node-0.0.0.tgz"],
          bundled_internal_dependencies: [
            "@aidenid/common-schemas",
            "@aidenid/policy-engine",
            "@aidenid/crypto",
            "@aidenid/fingerprint-sidecar"
          ]
        },
        env: { AIDENID_REQUIRE_DISTRIBUTED_STORES: "true" }
      }
    });

    await runtime.app.inject({
      method: "PUT",
      url: "/v1/tenants/ten_quota/quota",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        monthly_decision_limit: 1,
        stored_decision_limit: 1,
        target_limit: 1
      }
    });
    expect(
      (
        await runtime.app.inject({
          method: "POST",
          url: "/v1/targets",
          headers: TEST_ADMIN_HEADERS,
          payload: {
            tenant_id: "ten_quota",
            site_id: "sit_quota_one",
            name: "Quota One",
            origin: "https://quota-one.example.com"
          }
        })
      ).statusCode
    ).toBe(201);
    expect(
      (
        await runtime.app.inject({
          method: "POST",
          url: "/v1/targets",
          headers: TEST_ADMIN_HEADERS,
          payload: {
            tenant_id: "ten_quota",
            site_id: "sit_quota_two",
            name: "Quota Two",
            origin: "https://quota-two.example.com"
          }
        })
      ).statusCode
    ).toBe(429);

    const mcpMetadata = await runtime.app.inject({ method: "GET", url: "/.well-known/oauth-protected-resource" });
    expect(mcpMetadata.statusCode).toBe(200);
    expect(mcpMetadata.json()).toMatchObject({
      resource: "https://api.aidenid.local",
      authorization_servers: ["https://api.aidenid.local"],
      bearer_methods_supported: ["header"],
      dpop_bound_access_tokens_required: true,
      dpop_signing_alg_values_supported: ["EdDSA", "ES256"]
    });
    expect(mcpMetadata.json().scopes_supported).toContain("aidenid:session.exchange");

    const mcpResourceMetadata = await runtime.app.inject({
      method: "GET",
      url: "/v1/mcp/protected-resource-metadata?resource=https%3A%2F%2Fmcp.customer.example"
    });
    expect(mcpResourceMetadata.statusCode).toBe(200);
    expect(mcpResourceMetadata.json()).toMatchObject({ resource: "https://mcp.customer.example" });

    const invalidMcpMetadata = await runtime.app.inject({
      method: "GET",
      url: "/v1/mcp/protected-resource-metadata?resource=http%3A%2F%2Fmcp.customer.example"
    });
    expect(invalidMcpMetadata.statusCode).toBe(400);
    expect(invalidMcpMetadata.json()).toMatchObject({ error: "invalid_mcp_resource_metadata_query" });

    const mcp = await runtime.app.inject({ method: "GET", url: "/v1/mcp/front-door/roadmap" });
    expect(mcp.statusCode).toBe(200);
    expect(mcp.json()).toMatchObject({
      roadmap: {
        hot_path: false,
        protected_resource_metadata: "/.well-known/oauth-protected-resource",
        standards: ["RFC 9728", "RFC 8414", "RFC 8693", "RFC 9449"]
      }
    });
    await runtime.app.close();
  });

  it("fails closed when a webhook signing_secret_ref is not resolvable", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });
    const webhook = await runtime.app.inject({
      method: "POST",
      url: "/v1/webhooks/endpoints",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        tenant_id: "ten_demo",
        url: "https://hooks.example.com/unresolved",
        event_types: ["decision.recorded"],
        signing_secret_ref: "aws-sm://aidenid/webhook/unresolved"
      }
    });
    expect(webhook.statusCode).toBe(201);

    const signature = await runtime.app.inject({
      method: "POST",
      url: "/v1/webhooks/signature-preview",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        endpoint_id: webhook.json<{ endpoint: { id: string } }>().endpoint.id,
        payload: { type: "decision.recorded" }
      }
    });
    expect(signature.statusCode).toBe(424);
    expect(signature.json()).toMatchObject({ error: "webhook_signing_secret_unresolved" });
    await runtime.app.close();
  });

  it("rejects non-HTTPS outbound webhook endpoints", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });
    const webhook = await runtime.app.inject({
      method: "POST",
      url: "/v1/webhooks/endpoints",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        tenant_id: "ten_demo",
        url: "http://hooks.example.com/insecure",
        event_types: ["decision.recorded"],
        signing_secret_ref: "env://AIDENID_WEBHOOK_SECRET"
      }
    });

    expect(webhook.statusCode).toBe(400);
    expect(webhook.json()).toMatchObject({ error: "invalid_webhook_endpoint" });
    expect(webhook.body).toContain("webhook endpoint URL must use https");
    await runtime.app.close();
  });

  it("requires an admin operator for destructive and billing adoption controls", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });

    // Every entry mutates tenant state, destroys records, or discloses signing_secret_ref.
    const guarded: Array<{ method: "GET" | "POST" | "PUT"; url: string; payload?: Record<string, unknown> }> = [
      { method: "PUT", url: "/v1/tenants/ten_demo/quota", payload: { monthly_decision_limit: 1, stored_decision_limit: 1, target_limit: 1 } },
      { method: "PUT", url: "/v1/tenants/ten_demo/pricing-plan", payload: { plan: "growth" } },
      { method: "POST", url: "/v1/billing/rollups", payload: { tenant_id: "ten_demo" } },
      { method: "POST", url: "/v1/billing/exports", payload: { tenant_id: "ten_demo" } },
      { method: "POST", url: "/v1/billing/exports/bex_ffffffffffffffffffffffffffffffff/delivery-receipt", payload: {} },
      { method: "POST", url: "/v1/privacy/erase", payload: { site_id: "sit_adopt", subject_handle: "sub_demo_subject", reason: "dsar", actor_id: "platform_admin" } },
      { method: "POST", url: "/v1/webhooks/endpoints", payload: { tenant_id: "ten_demo", url: "https://hooks.example.com/x", event_types: ["decision.recorded"], signing_secret_ref: "env://AIDENID_WEBHOOK_SECRET" } },
      { method: "GET", url: "/v1/webhooks/endpoints?tenant_id=ten_demo" }
    ];

    for (const route of guarded) {
      // Built conditionally: exactOptionalPropertyTypes rejects an explicit payload: undefined.
      const options = {
        method: route.method,
        url: route.url,
        ...(route.payload === undefined ? {} : { payload: route.payload })
      };

      const anonymous = await runtime.app.inject(options);
      expect(anonymous.statusCode, `${route.method} ${route.url} must reject anonymous callers`).toBe(401);
      expect(anonymous.json()).toMatchObject({ error: "operator_auth_required" });

      // A viewer token authenticates but holds only decision_search, so this proves the gate
      // checks the role and is not merely checking that some token was presented.
      const viewer = await runtime.app.inject({ ...options, headers: TEST_VIEWER_HEADERS });
      expect(viewer.statusCode, `${route.method} ${route.url} must reject a non-admin operator`).toBe(403);
      expect(viewer.json()).toMatchObject({ error: "operator_forbidden", required_role: "admin" });
    }

    await runtime.app.close();
  });

  it("binds the privacy erasure actor to the authenticated operator, not the request body", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });

    // An authenticated admin naming someone else as the actor is the forged-attribution case:
    // gating alone would have accepted this and written a misleading audit record.
    const impersonating = await runtime.app.inject({
      method: "POST",
      url: "/v1/privacy/erase",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        site_id: "sit_adopt",
        subject_handle: "sub_demo_subject",
        reason: "dsar",
        actor_id: "someone_else"
      }
    });
    expect(impersonating.statusCode).toBe(400);
    expect(impersonating.json()).toMatchObject({ error: "actor_id_mismatch", expected_actor_id: "platform_admin" });

    const honest = await runtime.app.inject({
      method: "POST",
      url: "/v1/privacy/erase",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        site_id: "sit_adopt",
        subject_handle: "sub_demo_subject",
        reason: "dsar",
        actor_id: "platform_admin"
      }
    });
    expect(honest.statusCode).toBe(202);
    expect(honest.json()).toMatchObject({ erasure: { site_id: "sit_adopt" } });

    const erasures = await runtime.services.store.listPrivacyErasures("sit_adopt", 10);
    expect(erasures).toHaveLength(1);
    expect(erasures[0]?.actorId).toBe("platform_admin");

    await runtime.app.close();
  });

  it("requires an operator for the bulk decision list and the decision await long poll", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });

    // The bulk list is the broader exposure: site_id is optional, so omitting it spans every
    // tenant, and no id is required. It must reject before it reads anything.
    const anonymousList = await runtime.app.inject({ method: "GET", url: "/v1/decisions" });
    expect(anonymousList.statusCode).toBe(401);
    expect(anonymousList.json()).toMatchObject({ error: "operator_auth_required" });

    const anonymousAwait = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions/dec_00000000000000000000000000000000/await?timeout_ms=1"
    });
    expect(anonymousAwait.statusCode).toBe(401);
    expect(anonymousAwait.json()).toMatchObject({ error: "operator_auth_required" });

    // Rejected before the long poll begins: an unauthenticated caller must not be able to hold a
    // connection open at all, so this returns immediately rather than after timeout_ms.
    const slowAnonymous = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions/dec_00000000000000000000000000000000/await?timeout_ms=30000"
    });
    expect(slowAnonymous.statusCode).toBe(401);

    // A viewer holds decision_search and is sufficient for both reads.
    const viewerList = await runtime.app.inject({
      method: "GET",
      url: "/v1/decisions",
      headers: TEST_VIEWER_HEADERS
    });
    expect(viewerList.statusCode).toBe(200);

    await runtime.app.close();
  });

  it("refuses to act as a webhook signing oracle for unauthorized callers", async () => {
    const runtime = await createControlPlaneRuntime({
      operatorAuth: TEST_OPERATOR_AUTH,
      webhookSecrets: new StaticWebhookSecretResolver({
        "aws-sm://aidenid/webhook/demo": "resolved-demo-webhook-secret"
      })
    });
    const created = await runtime.app.inject({
      method: "POST",
      url: "/v1/webhooks/endpoints",
      headers: TEST_ADMIN_HEADERS,
      payload: {
        tenant_id: "ten_demo",
        url: "https://hooks.example.com/oracle",
        event_types: ["decision.recorded"],
        signing_secret_ref: "aws-sm://aidenid/webhook/demo"
      }
    });
    expect(created.statusCode).toBe(201);
    const endpointId = created.json<{ endpoint: { id: string } }>().endpoint.id;

    // This route resolves the tenant's real signing secret and returns HMAC headers for a
    // caller-supplied payload. Ungated, anyone could mint a valid signature for any tenant's
    // webhook receiver, so it must reject before the secret is resolved.
    const forged = {
      method: "POST" as const,
      url: "/v1/webhooks/signature-preview",
      payload: { endpoint_id: endpointId, payload: { attacker: "controlled" } }
    };

    const anonymous = await runtime.app.inject(forged);
    expect(anonymous.statusCode).toBe(401);
    expect(anonymous.json()).toMatchObject({ error: "operator_auth_required" });
    expect(anonymous.body).not.toContain("x-aidenid-webhook-signature");

    const viewer = await runtime.app.inject({ ...forged, headers: TEST_VIEWER_HEADERS });
    expect(viewer.statusCode).toBe(403);
    expect(viewer.json()).toMatchObject({ error: "operator_forbidden", required_role: "admin" });
    expect(viewer.body).not.toContain("x-aidenid-webhook-signature");

    const admin = await runtime.app.inject({ ...forged, headers: TEST_ADMIN_HEADERS });
    expect(admin.statusCode).toBe(200);

    await runtime.app.close();
  });

  it("requires an operator for tenant-scoped adoption reads", async () => {
    const runtime = await createControlPlaneRuntime({ operatorAuth: TEST_OPERATOR_AUTH });

    const reads = [
      "/v1/usage/meter?site_id=sit_adopt&tenant_id=ten_demo",
      "/v1/usage/price-required?site_id=sit_adopt&tenant_id=ten_demo",
      "/v1/counterfactuals/enforcement?site_id=sit_adopt",
      "/v1/tenants/ten_demo/quota",
      "/v1/tenants/ten_demo/pricing-plan",
      "/v1/billing/rollups?tenant_id=ten_demo&period_start=2026-04-01T00%3A00%3A00.000Z&period_end=2026-04-02T00%3A00%3A00.000Z",
      "/v1/billing/exports?tenant_id=ten_demo",
      "/v1/privacy/erasures?site_id=sit_adopt",
      "/v1/onboarding/target-plan?tenant_id=ten_demo&site_id=sit_new&name=Acme&origin=https%3A%2F%2Facme.example.com"
    ];

    for (const url of reads) {
      const anonymous = await runtime.app.inject({ method: "GET", url });
      expect(anonymous.statusCode, `${url} must reject anonymous callers`).toBe(401);
      expect(anonymous.json()).toMatchObject({ error: "operator_auth_required" });
    }

    // The MCP protected-resource metadata must STAY anonymous per RFC 9728.
    const metadata = await runtime.app.inject({ method: "GET", url: "/v1/mcp/protected-resource-metadata" });
    expect(metadata.statusCode).toBe(200);

    await runtime.app.close();
  });

  it("stores adoption control-plane state through the Postgres store contract", async () => {
    const client = new AdoptionSqlClient();
    const store = new PostgresControlPlaneStore(client);
    const now = "2026-04-25T00:00:00.000Z";
    const quota = await store.upsertTenantQuota(
      {
        tenantId: "ten_pg",
        monthlyDecisionLimit: 10,
        storedDecisionLimit: 25,
        targetLimit: 3
      },
      now
    );
    expect(quota).toMatchObject({ tenantId: "ten_pg", monthlyDecisionLimit: 10, updatedAt: now });
    expect(await store.getTenantQuota("ten_pg")).toMatchObject({ tenantId: "ten_pg", targetLimit: 3 });
    const plan = await store.upsertTenantPricingPlan(
      {
        tenantId: "ten_pg",
        planTier: "growth",
        currency: "USD",
        unitPriceUsd: 0.0002,
        includedMonthlyClearedDecisions: 1,
        effectiveFrom: now
      },
      now
    );
    expect(await store.getTenantPricingPlan("ten_pg")).toEqual(plan);

    await store.recordDecision({
      id: "dec_pg_1",
      tenantId: "ten_pg",
      siteId: "sit_pg",
      requestId: "req_pg_1",
      actorClass: "suspicious_automation",
      decision: "allow",
      recommendedDecision: "deny",
      routeTemplate: "/checkout",
      method: "POST",
      occurredAt: now,
      latencyUs: 42,
      subjectHandle: "sub_pg_subject",
      issuer: "https://partner-broker.example",
      suspicionScore: 0.9,
      reasonCodes: ["matched_policy"],
      cascadeTrace: [
        { ordinal: 1, layer: "crypto_identity", status: "skipped", reason: "actor_class_not_signed_agent", latency_us: 0 },
        { ordinal: 2, layer: "delegation_authorization", status: "skipped", reason: "depends_on_crypto_identity", latency_us: 0 },
        { ordinal: 3, layer: "fingerprint_sidecar", status: "not_configured", reason: "fingerprint_provider_missing", latency_us: 0 },
        { ordinal: 4, layer: "operator_reputation", status: "not_configured", reason: "operator_reputation_provider_missing", latency_us: 0 }
      ]
    });
    expect(await store.listDecisions("sit_pg", 10)).toEqual([
      expect.objectContaining({
        id: "dec_pg_1",
        recommendedDecision: "deny",
        subjectHandle: "sub_pg_subject",
        reasonCodes: ["matched_policy"],
        cascadeTrace: expect.arrayContaining([expect.objectContaining({ layer: "operator_reputation", status: "not_configured" })])
      })
    ]);
    expect(client.leases).toBeGreaterThanOrEqual(1);
    expect(client.releases).toBe(client.leases);
    const pgOutbox = await store.listDecisionOutboxAfter(0, 10);
    expect(pgOutbox).toEqual([
      expect.objectContaining({
        seq: 1,
        decisionId: "dec_pg_1",
        eventType: "recorded",
        previousHash: DECISION_OUTBOX_GENESIS_HASH,
        entryHash: expect.stringMatching(/^[a-f0-9]{64}$/),
        payload: expect.objectContaining({
          request_id: "req_pg_1",
          recommended_decision: "deny",
          reason_codes: ["matched_policy"],
          cascade_trace: expect.arrayContaining([expect.objectContaining({ layer: "crypto_identity", status: "skipped" })])
        })
      })
    ]);
    expect(pgOutbox[0]?.entryHash).toBe(
      decisionOutboxEntryHash({
        previousHash: DECISION_OUTBOX_GENESIS_HASH,
        decisionId: "dec_pg_1",
        eventType: "recorded",
        payload: pgOutbox[0]!.payload
      })
    );
    const receiptIssuer = new LocalDecisionReceiptIssuer({
      issuer: "https://api.aidenid.local",
      keyId: "decision-receipt-key-pg",
      now: () => new Date(now)
    });
    const activeKey = await store.upsertDecisionReceiptKey(
      receiptIssuer.currentKeyRecord({ activatedAt: now, retireAfter: "2026-05-25T00:00:00.000Z" }),
      now
    );
    expect(activeKey).toMatchObject({
      kid: "decision-receipt-key-pg",
      state: "active",
      retireAfter: "2026-05-25T00:00:00.000Z",
      jwkThumbprintSha256: expect.stringMatching(/^[a-f0-9]{64}$/)
    });
    expect(await store.getDecisionReceiptKey("decision-receipt-key-pg")).toEqual(
      expect.objectContaining({ kid: "decision-receipt-key-pg", state: "active" })
    );
    expect(await store.getActiveDecisionReceiptKey("https://api.aidenid.local", now)).toEqual(
      expect.objectContaining({ kid: "decision-receipt-key-pg", state: "active" })
    );
    expect(await store.listDecisionReceiptKeys(10)).toEqual([expect.objectContaining({ kid: "decision-receipt-key-pg", state: "active" })]);
    expect(await store.retireDecisionReceiptKey("decision-receipt-key-pg", "2026-04-26T00:00:00.000Z", "scheduled-rotation")).toEqual(
      expect.objectContaining({ kid: "decision-receipt-key-pg", state: "retired", rotationReason: "scheduled-rotation" })
    );
    const tenantPeriodDecisions = await store.listDecisionsForTenantPeriod("ten_pg", now, "2026-04-26T00:00:00.000Z", 10);
    expect(tenantPeriodDecisions).toEqual([expect.objectContaining({ id: "dec_pg_1", tenantId: "ten_pg" })]);
    const rollup = await store.upsertBillingPeriodRollup(
      {
        tenantId: "ten_pg",
        periodStart: now,
        periodEnd: "2026-04-26T00:00:00.000Z",
        planTier: plan.planTier,
        currency: "USD",
        unitPriceUsd: plan.unitPriceUsd,
        includedClearedDecisions: plan.includedMonthlyClearedDecisions,
        clearedDecisionCount: 1,
        billableClearedDecisionCount: 1,
        overageClearedDecisionCount: 0,
        estimatedCostUsd: 0,
        priceRequiredGrossUsd: 0,
        invoiceLineItemId: "ili_0123456789abcdef0123456789abcdef",
        exportIdempotencyKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
      now
    );
    expect(rollup.id).toMatch(/^bil_[a-f0-9]{32}$/);
    expect(await store.getBillingPeriodRollup("ten_pg", now, "2026-04-26T00:00:00.000Z")).toEqual(rollup);
    const billingExport = await store.upsertBillingExport(
      {
        id: "bex_0123456789abcdef0123456789abcdef",
        rollupId: rollup.id,
        tenantId: "ten_pg",
        periodStart: now,
        periodEnd: "2026-04-26T00:00:00.000Z",
        provider: "stripe_meter_event",
        destinationRef: "cus_pg_123",
        idempotencyKey: "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        payloadSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        payload: { adapter: "stripe_meter_event", body: { identifier: "pg" } },
        status: "prepared"
      },
      now
    );
    expect(await store.getBillingExport(billingExport.id)).toEqual(billingExport);
    expect(
      await store.listBillingExports({
        tenantId: "ten_pg",
        provider: "stripe_meter_event",
        status: "prepared",
        periodStart: now,
        periodEnd: "2026-04-26T00:00:00.000Z",
        limit: 10
      })
    ).toEqual([billingExport]);
    const providerReceiptPayloadSha256 = "f".repeat(64);
    const deliveredBillingExport = await store.recordBillingExportDeliveryReceipt(
      {
        id: billingExport.id,
        providerReceiptId: "mtr_evt_pg",
        providerReceiptStatus: "accepted",
        providerReceiptPayloadSha256,
        deliveredAt: "2026-04-25T00:01:00.000Z"
      },
      "2026-04-25T00:02:00.000Z"
    );
    expect(deliveredBillingExport).toEqual(
      expect.objectContaining({
        id: billingExport.id,
        status: "delivered",
        deliveredAt: "2026-04-25T00:01:00.000Z",
        providerReceiptId: "mtr_evt_pg",
        providerReceiptStatus: "accepted",
        providerReceiptPayloadSha256,
        providerReceiptRecordedAt: "2026-04-25T00:02:00.000Z"
      })
    );
    expect(
      await store.recordBillingExportDeliveryReceipt(
        {
          id: "bex_missing",
          providerReceiptId: "mtr_evt_missing",
          providerReceiptStatus: "accepted",
          providerReceiptPayloadSha256,
          deliveredAt: now
        },
        now
      )
    ).toBeUndefined();
    const operatorEvent = await store.applyDecisionOperatorAction({
      decisionId: "dec_pg_1",
      action: "deny",
      actorId: "pg_ciso",
      reason: "manual override",
      occurredAt: now
    });
    expect(operatorEvent).toEqual(
      expect.objectContaining({
        decisionId: "dec_pg_1",
        eventType: "updated",
        payload: expect.objectContaining({ operator_action: "deny", operator_action_actor_id: "pg_ciso" })
      })
    );
    expect(await store.getDecision("dec_pg_1")).toMatchObject({
      operatorAction: "deny",
      operatorActionActorId: "pg_ciso",
      operatorActionReason: "manual override",
      operatorActionEffectiveDecision: "deny"
    });
    const quarantineEvent = await store.applyDecisionOperatorAction({
      decisionId: "dec_pg_1",
      action: "quarantine",
      actorId: "pg_ciso",
      reason: "manual quarantine",
      occurredAt: now,
      ttlSeconds: 120
    });
    expect(quarantineEvent).toEqual(
      expect.objectContaining({
        decisionId: "dec_pg_1",
        eventType: "updated",
        payload: expect.objectContaining({
          operator_action: "quarantine",
          operator_action_effective_decision: "deny",
          operator_action_effects: ["deny", "actor_pin", "ocsf_emit", "webhook_emit"]
        })
      })
    );
    expect(await store.listQuarantinePins("sit_pg", 10)).toEqual([
      expect.objectContaining({
        decisionId: "dec_pg_1",
        siteId: "sit_pg",
        issuer: "https://partner-broker.example",
        subjectHandle: "sub_pg_subject",
        operatorActorId: "pg_ciso"
      })
    ]);
    expect(await store.latestDecisionOutboxSeq()).toBe(3);
    expect(await store.eraseSubjectDecisions("sit_pg", "sub_pg_subject")).toBe(1);

    const erasure = await store.recordPrivacyErasure(
      {
        siteId: "sit_pg",
        subjectHandle: "sub_pg_subject",
        reason: "dsar",
        actorId: "privacy_admin",
        erasedDecisionCount: 1
      },
      now
    );
    expect(await store.listPrivacyErasures("sit_pg", 10)).toEqual([erasure]);

    const endpoint = await store.upsertWebhookEndpoint(
      {
        tenantId: "ten_pg",
        url: "https://hooks.example.com/pg",
        eventTypes: ["decision.recorded"],
        signingSecretRef: "env://PG_WEBHOOK_SECRET"
      },
      now
    );
    expect(await store.listWebhookEndpoints("ten_pg")).toEqual([endpoint]);

    const reputation = await store.upsertOperatorReputation(
      {
        siteId: "sit_pg",
        operatorActorId: "pg_ciso",
        displayName: "PG CISO",
        trustTier: "restricted",
        status: "watchlist",
        reputationScore: 58,
        defaultAction: "throttle",
        defaultScopeRoutes: ["/pg/*"],
        defaultScopeRedirectPath: "/agent-access",
        notes: "manual review pending",
        lastReviewedAt: now,
        updatedBy: "risk_ops"
      },
      now
    );
    expect(reputation).toMatchObject({
      siteId: "sit_pg",
      operatorActorId: "pg_ciso",
      trustTier: "restricted",
      status: "watchlist",
      reputationScore: 58,
      defaultAction: "throttle",
      defaultScopeRoutes: ["/pg/*"],
      defaultScopeRedirectPath: "/agent-access",
      updatedBy: "risk_ops"
    });
    expect(await store.getOperatorReputation("sit_pg", "pg_ciso")).toEqual(reputation);
    expect(await store.listOperatorReputations({ siteId: "sit_pg", status: "watchlist", trustTier: "restricted", limit: 10 })).toEqual([
      reputation
    ]);

    expect(client.sql.some((statement) => statement.includes("tenant_quotas"))).toBe(true);
    expect(client.sql.some((statement) => statement.includes("tenant_pricing_plans"))).toBe(true);
    expect(client.sql.some((statement) => statement.includes("billing_period_rollups"))).toBe(true);
    expect(client.sql.some((statement) => statement.includes("tenant_id = $1 AND occurred_at >= $2 AND occurred_at < $3"))).toBe(true);
    expect(client.sql.some((statement) => statement.includes("privacy_erasure_requests"))).toBe(true);
    expect(client.sql.some((statement) => statement.includes("webhook_endpoints"))).toBe(true);
    expect(client.sql.some((statement) => statement.includes("operator_reputation"))).toBe(true);
  });

  it("rolls back Postgres decision writes when decision outbox append fails", async () => {
    const client = new AdoptionSqlClient({ failDecisionOutbox: true });
    const store = new PostgresControlPlaneStore(client);

    await expect(
      store.recordDecisionWithOutbox({
        id: "dec_rollback_1",
        siteId: "sit_pg",
        requestId: "req_rollback_1",
        actorClass: "unknown",
        decision: "deny",
        routeTemplate: "/benefits/PHI/*",
        method: "GET",
        occurredAt: "2026-04-25T00:00:00.000Z"
      })
    ).rejects.toThrow(/forced decision outbox failure/);

    expect(await store.listDecisions("sit_pg", 10)).toEqual([]);
    expect(await store.listDecisionOutboxAfter(0, 10)).toEqual([]);
    expect(client.sql.map((statement) => statement.trim())).toEqual(expect.arrayContaining(["BEGIN", "ROLLBACK"]));
    expect(client.sql.map((statement) => statement.trim())).not.toContain("COMMIT");
    expect(client.releases).toBe(client.leases);
  });

  it("locks Postgres tenant quota while recording decisions and outbox events", async () => {
    const client = new AdoptionSqlClient();
    const store = new PostgresControlPlaneStore(client);
    const now = "2026-04-25T00:00:00.000Z";
    await store.upsertTenantQuota(
      {
        tenantId: "ten_pg_quota",
        monthlyDecisionLimit: 10,
        storedDecisionLimit: 1,
        targetLimit: 10
      },
      now
    );
    let issuedDecisions = 0;

    const first = await store.recordDecisionWithTenantQuota({
      tenantId: "ten_pg_quota",
      issueDecision: () => {
        issuedDecisions += 1;
        return { ...decisionForTest("dec_pg_quota_1"), tenantId: "ten_pg_quota", siteId: "sit_pg_a" };
      }
    });
    const second = await store.recordDecisionWithTenantQuota({
      tenantId: "ten_pg_quota",
      issueDecision: () => {
        issuedDecisions += 1;
        return { ...decisionForTest("dec_pg_quota_2"), tenantId: "ten_pg_quota", siteId: "sit_pg_b" };
      }
    });

    expect(first.status).toBe("recorded");
    expect(second).toEqual({ status: "quota_exceeded", tenantId: "ten_pg_quota", storedDecisionLimit: 1 });
    expect(issuedDecisions).toBe(1);
    expect(await store.listDecisions(undefined, 10)).toEqual([expect.objectContaining({ id: "dec_pg_quota_1", tenantId: "ten_pg_quota" })]);
    expect(await store.listDecisionOutboxAfter(0, 10)).toHaveLength(1);
    expect(client.sql.some((statement) => statement.includes("FROM tenant_quotas") && statement.includes("FOR UPDATE"))).toBe(true);
    expect(client.sql.some((statement) => statement.includes("SELECT count(*) AS count FROM decisions WHERE tenant_id = $1"))).toBe(true);
  });

  it("refuses transactional Postgres writes without a leased client", async () => {
    const client: SqlClient = {
      async query() {
        return { rows: [], rowCount: 0 };
      }
    };
    const store = new PostgresControlPlaneStore(client);
    await expect(store.recordDecisionWithOutbox(decisionForTest("dec_no_lease_1"))).rejects.toThrow(/leased SQL client/);
  });

  it("uses Postgres LISTEN/NOTIFY to wake decision outbox waits", async () => {
    const client = new NotificationSqlClient({ notifyDuringOutboxRead: true });
    const store = new PostgresControlPlaneStore(client);
    const waiter = store.waitForDecisionOutboxAfter(41, 1_000);
    await expect(waiter).resolves.toBeUndefined();
    expect(client.sql.map((statement) => statement.trim())).toEqual(
      expect.arrayContaining(["LISTEN aidenid_decision_outbox", "UNLISTEN aidenid_decision_outbox"])
    );
    expect(client.notificationsDelivered).toBe(1);
    expect(client.releases).toBe(1);
  });

  it("polls the decision outbox when SQL leases do not expose notification events", async () => {
    const client = new PollingWaitSqlClient();
    const store = new PostgresControlPlaneStore(client);
    await expect(store.waitForDecisionOutboxAfter(41, 1_000)).resolves.toBeUndefined();
    expect(client.outboxReads).toBe(2);
    expect(client.sql.map((statement) => statement.trim())).toEqual(
      expect.arrayContaining(["LISTEN aidenid_decision_outbox", "UNLISTEN aidenid_decision_outbox"])
    );
    expect(client.releases).toBe(1);
  });

  it("returns offline Policy Copilot suggestions with audit metadata and no apply side effect", async () => {
    const runtime = await createControlPlaneRuntime();
    const response = await runtime.app.inject({
      method: "POST",
      url: "/v1/policy-copilot/suggestions",
      payload: {
        policy_yaml: `version: 1
site_id: sit_copilot
mode: enforce
defaults:
  strict: false
  on_degraded: queue
  rate: { capacity: 100, refill_per_sec: 10, cost: 1 }
routes:
  - template: /comments/:id
    method: POST
    per_actor_class:
      likely_human: { decision: allow }
`,
        prompt: "suggest offline comment policy hardening",
        input_refs: ["decision_stream:sit_copilot"],
        suspicious_automation_threshold: 2,
        decision_samples: [
          {
            route_template: "/comments/:id",
            method: "POST",
            actor_class: "suspicious_automation",
            decision: "allow",
            reason_codes: ["matched_policy"]
          },
          {
            route_template: "/comments/:id",
            method: "POST",
            actor_class: "suspicious_automation",
            decision: "allow",
            reason_codes: ["matched_policy"]
          }
        ]
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      apply_policy: false,
      suggestions: [
        {
          label: "ai_proposed",
          approval_status: "pending",
          metadata: {
            model: "offline-policy-copilot-rules-v1",
            tool: "aidenid-policy-copilot",
            input_refs: ["decision_stream:sit_copilot"]
          },
          output_diff: {
            format: "aidenid.policy.diff.v1"
          }
        }
      ]
    });
    expect(response.json<{ suggestions: Array<{ metadata: { prompt_digest_sha256: string }; proposed_policy_yaml: string }> }>().suggestions[0])
      .toMatchObject({
        metadata: { prompt_digest_sha256: expect.stringMatching(/^[a-f0-9]{64}$/) },
        proposed_policy_yaml: expect.stringContaining("suspicious_automation")
      });
    await runtime.app.close();
  });

  it("ships the initial Postgres migration with hot-query indexes", () => {
    const sql = readFileSync(new URL("../migrations/0001_control_plane.sql", import.meta.url), "utf8");
    const adoptionSql = readFileSync(new URL("../migrations/0002_adoption_controls.sql", import.meta.url), "utf8");
    const decisionOutboxSql = readFileSync(new URL("../migrations/0003_decisions_outbox.sql", import.meta.url), "utf8");
    const decisionReasonCodesSql = readFileSync(new URL("../migrations/0004_decision_reason_codes.sql", import.meta.url), "utf8");
    const decisionOperatorActionsSql = readFileSync(new URL("../migrations/0005_decision_operator_actions.sql", import.meta.url), "utf8");
    const quarantinePriceSql = readFileSync(new URL("../migrations/0006_quarantine_price_insights.sql", import.meta.url), "utf8");
    const llmBrandSql = readFileSync(new URL("../migrations/0007_llm_brand_decisions.sql", import.meta.url), "utf8");
    const searchIndexesSql = readFileSync(new URL("../migrations/0008_decisions_search_indexes.sql", import.meta.url), "utf8");
    const operatorReputationSql = readFileSync(new URL("../migrations/0009_operator_reputation.sql", import.meta.url), "utf8");
    const expandedSearchIndexesSql = readFileSync(new URL("../migrations/0010_decisions_search_index_expansion.sql", import.meta.url), "utf8");
    const compoundSearchIndexesSql = readFileSync(new URL("../migrations/0011_decisions_search_compound_indexes.sql", import.meta.url), "utf8");
    const cascadeTraceSql = readFileSync(new URL("../migrations/0012_decision_cascade_trace.sql", import.meta.url), "utf8");
    const decisionReceiptsSql = readFileSync(new URL("../migrations/0013_decision_receipts.sql", import.meta.url), "utf8");
    const billingMeterSql = readFileSync(new URL("../migrations/0014_billing_meter.sql", import.meta.url), "utf8");
    const outboxChainSql = readFileSync(new URL("../migrations/0015_decision_outbox_chain_receipt_keys.sql", import.meta.url), "utf8");
    const receiptKeyUniquenessSql = readFileSync(
      new URL("../migrations/0016_decision_receipt_key_active_uniqueness.sql", import.meta.url),
      "utf8"
    );
    const billingExportsSql = readFileSync(new URL("../migrations/0017_billing_exports.sql", import.meta.url), "utf8");
    const billingExportDeliveryReceiptsSql = readFileSync(
      new URL("../migrations/0018_billing_export_delivery_receipts.sql", import.meta.url),
      "utf8"
    );
    const decisionPurposeSql = readFileSync(new URL("../migrations/0019_decision_purpose.sql", import.meta.url), "utf8");
    const agentIdentitySubmissionsSql = readFileSync(
      new URL("../migrations/0020_agent_identity_submissions.sql", import.meta.url),
      "utf8"
    );
    const agentIdentityReviewSql = readFileSync(
      new URL("../migrations/0021_agent_identity_submission_reviews.sql", import.meta.url),
      "utf8"
    );
    const operatorReputationDefaultsSql = readFileSync(
      new URL("../migrations/0023_operator_reputation_defaults.sql", import.meta.url),
      "utf8"
    );
    const operatorReputationExpirySql = readFileSync(
      new URL("../migrations/0025_operator_reputation_expiry.sql", import.meta.url),
      "utf8"
    );
    expect(sql).toContain("CREATE TABLE outbox_events");
    expect(sql).toContain("idx_decisions_site_time");
    expect(sql).toContain("idx_grants_active");
    expect(sql).toContain("idx_outbox_pending");
    expect(adoptionSql).toContain("CREATE TABLE IF NOT EXISTS tenant_quotas");
    expect(adoptionSql).toContain("idx_decisions_counterfactual");
    expect(decisionOutboxSql).toContain("CREATE TABLE IF NOT EXISTS decision_outbox");
    expect(decisionOutboxSql).toContain("CHECK (event_type IN ('recorded', 'pending', 'resolved', 'updated'))");
    expect(decisionOutboxSql).toContain("idx_decision_outbox_retention");
    expect(decisionReasonCodesSql).toContain("ADD COLUMN IF NOT EXISTS reason_codes jsonb");
    expect(decisionOperatorActionsSql).toContain("ADD COLUMN IF NOT EXISTS operator_action text");
    expect(decisionOperatorActionsSql).toContain("idx_decisions_operator_action_at");
    expect(quarantinePriceSql).toContain("CREATE TABLE IF NOT EXISTS quarantine_pins");
    expect(quarantinePriceSql).toContain("idx_decisions_price_required_issuer");
    expect(llmBrandSql).toContain("ADD COLUMN IF NOT EXISTS llm_brand text");
    expect(llmBrandSql).toContain("idx_decisions_llm_brand");
    expect(searchIndexesSql).toContain("idx_decisions_operator_search");
    expect(searchIndexesSql).toContain("idx_decisions_subject_search");
    expect(searchIndexesSql).toContain("WHERE operator_action_actor_id IS NOT NULL");
    expect(searchIndexesSql).toContain("WHERE subject_handle IS NOT NULL");
    expect(searchIndexesSql).not.toContain("CONCURRENTLY");
    expect(operatorReputationSql).toContain("CREATE TABLE IF NOT EXISTS operator_reputation");
    expect(operatorReputationSql).toContain("UNIQUE (site_id, operator_actor_id)");
    expect(operatorReputationSql).toContain("idx_operator_reputation_site_status");
    expect(operatorReputationSql).toContain("idx_operator_reputation_site_trust");
    expect(expandedSearchIndexesSql).toContain("idx_decisions_decision_search");
    expect(expandedSearchIndexesSql).toContain("ON decisions(site_id, decision, occurred_at DESC)");
    expect(expandedSearchIndexesSql).toContain("idx_decisions_issuer_search");
    expect(expandedSearchIndexesSql).toContain("WHERE issuer IS NOT NULL");
    expect(expandedSearchIndexesSql).toContain("idx_decisions_actor_class_search");
    expect(expandedSearchIndexesSql).toContain("idx_decisions_route_search");
    expect(expandedSearchIndexesSql).not.toContain("CONCURRENTLY");
    expect(compoundSearchIndexesSql).toContain("idx_decisions_decision_actor_search");
    expect(compoundSearchIndexesSql).toContain("ON decisions(site_id, decision, actor_class, occurred_at DESC)");
    expect(compoundSearchIndexesSql).toContain("idx_decisions_route_decision_actor_search");
    expect(compoundSearchIndexesSql).toContain("ON decisions(site_id, route_template, decision, actor_class, occurred_at DESC)");
    expect(compoundSearchIndexesSql).toContain("idx_decisions_issuer_decision_search");
    expect(compoundSearchIndexesSql).toContain("WHERE issuer IS NOT NULL");
    expect(compoundSearchIndexesSql).not.toContain("CONCURRENTLY");
    expect(cascadeTraceSql).toContain("ADD COLUMN IF NOT EXISTS cascade_trace jsonb");
    expect(cascadeTraceSql).toContain("idx_decisions_cascade_trace_gin");
    expect(cascadeTraceSql).not.toContain("CONCURRENTLY");
    expect(decisionReceiptsSql).toContain("ADD COLUMN IF NOT EXISTS receipt_jws text");
    expect(decisionReceiptsSql).toContain("ADD COLUMN IF NOT EXISTS transparency_inclusion_proof jsonb");
    expect(decisionReceiptsSql).toContain("idx_decisions_transparency_leaf");
    expect(decisionReceiptsSql).not.toContain("CONCURRENTLY");
    expect(billingMeterSql).toContain("CREATE TABLE IF NOT EXISTS tenant_pricing_plans");
    expect(billingMeterSql).toContain("CREATE TABLE IF NOT EXISTS billing_period_rollups");
    expect(billingMeterSql).toContain("UNIQUE (tenant_id, period_start, period_end)");
    expect(billingMeterSql).toContain("UNIQUE (export_idempotency_key)");
    expect(billingMeterSql).toContain("idx_decisions_tenant_billing_period");
    expect(billingMeterSql).toContain("idx_billing_period_rollups_invoice_line");
    expect(billingMeterSql).not.toContain("CONCURRENTLY");
    expect(outboxChainSql).toContain("ADD COLUMN IF NOT EXISTS previous_hash text");
    expect(outboxChainSql).toContain("ADD COLUMN IF NOT EXISTS entry_hash text");
    expect(outboxChainSql).toContain("idx_decision_outbox_entry_hash");
    expect(outboxChainSql).toContain("CREATE TABLE IF NOT EXISTS decision_receipt_keys");
    expect(outboxChainSql).toContain("idx_decision_receipt_keys_rotation_due");
    expect(outboxChainSql).not.toContain("CONCURRENTLY");
    expect(receiptKeyUniquenessSql).toContain("idx_decision_receipt_keys_one_active_per_issuer");
    expect(receiptKeyUniquenessSql).toContain("WHERE state = 'active'");
    expect(receiptKeyUniquenessSql).not.toContain("CONCURRENTLY");
    expect(billingExportsSql).toContain("CREATE TABLE IF NOT EXISTS billing_exports");
    expect(billingExportsSql).toContain("REFERENCES billing_period_rollups(id)");
    expect(billingExportsSql).toContain("CHECK (provider IN ('stripe_meter_event', 'quickbooks_invoice'))");
    expect(billingExportsSql).toContain("UNIQUE (provider, idempotency_key)");
    expect(billingExportsSql).toContain("idx_billing_exports_tenant_period");
    expect(billingExportsSql).not.toContain("CONCURRENTLY");
    expect(billingExportDeliveryReceiptsSql).toContain("ADD COLUMN IF NOT EXISTS provider_receipt_id text");
    expect(billingExportDeliveryReceiptsSql).toContain("provider_receipt_payload_sha256 ~ '^[a-f0-9]{64}$'");
    expect(billingExportDeliveryReceiptsSql).toContain("idx_billing_exports_provider_receipt");
    expect(billingExportDeliveryReceiptsSql).not.toContain("CONCURRENTLY");
    expect(decisionPurposeSql).toContain("ADD COLUMN IF NOT EXISTS purpose text");
    expect(decisionPurposeSql).toContain("decisions_purpose_format");
    expect(decisionPurposeSql).toContain("idx_decisions_site_purpose_occurred");
    expect(decisionPurposeSql).not.toContain("CONCURRENTLY");
    expect(agentIdentitySubmissionsSql).toContain("CREATE TABLE IF NOT EXISTS agent_identity_submissions");
    expect(agentIdentitySubmissionsSql).toContain("idx_agent_identity_submissions_site_status");
    expect(agentIdentitySubmissionsSql).toContain("idx_agent_identity_submissions_operator_claim");
    expect(agentIdentitySubmissionsSql).not.toContain("CONCURRENTLY");
    expect(agentIdentityReviewSql).toContain("ADD COLUMN IF NOT EXISTS reviewed_at");
    expect(agentIdentityReviewSql).toContain("ADD COLUMN IF NOT EXISTS assigned_trust_tier");
    expect(agentIdentityReviewSql).toContain("agent_identity_submissions_review_state");
    expect(agentIdentityReviewSql).toContain("idx_agent_identity_submissions_reviewed_at");
    expect(agentIdentityReviewSql).toContain("idx_agent_identity_submissions_operator_reputation");
    expect(agentIdentityReviewSql).not.toContain("CONCURRENTLY");
    expect(operatorReputationDefaultsSql).toContain("ADD COLUMN IF NOT EXISTS default_action text NOT NULL DEFAULT 'allow'");
    expect(operatorReputationDefaultsSql).toContain("default_action IN ('allow', 'throttle', 'queue', 'sandbox', 'deny', 'price_required')");
    expect(operatorReputationDefaultsSql).toContain("ADD COLUMN IF NOT EXISTS default_scope_routes jsonb NOT NULL DEFAULT '[]'::jsonb");
    expect(operatorReputationDefaultsSql).toContain("operator_reputation_default_scope_routes_bounded");
    expect(operatorReputationDefaultsSql).toContain("operator_reputation_default_scope_redirect_path_local");
    expect(operatorReputationExpirySql).toContain("ADD COLUMN IF NOT EXISTS expires_at timestamptz");
    expect(operatorReputationExpirySql).toContain("operator_reputation_status_valid");
    expect(operatorReputationExpirySql).toContain("'expired'");
    expect(operatorReputationExpirySql).toContain("operator_reputation_expires_after_created_at");
    expect(operatorReputationExpirySql).toContain("idx_operator_reputation_site_expires_at");
    expect(operatorReputationExpirySql).not.toContain("CONCURRENTLY");
  });
});
