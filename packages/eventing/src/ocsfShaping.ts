export type OcsfDecisionAction = "allow" | "throttle" | "queue" | "sandbox" | "deny" | "price_required";
export type OcsfOperatorAction = OcsfDecisionAction | "quarantine";
export type OcsfHttpMethod = "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";

export interface DecisionEventForOcsf {
  readonly id: string;
  readonly requestId: string;
  readonly traceId?: string;
  readonly siteId: string;
  readonly occurredAt: string;
  readonly actorClass: string;
  readonly decision: OcsfDecisionAction;
  readonly operatorAction?: OcsfOperatorAction | undefined;
  readonly operatorEffectiveDecision?: OcsfDecisionAction | undefined;
  readonly reasonCodes: readonly string[];
  readonly routeTemplate: string;
  readonly method: OcsfHttpMethod;
  readonly subjectHandle?: string;
  readonly issuer?: string;
  readonly llmBrand?: string;
  readonly purpose?: string;
  readonly priceUsd?: number;
  readonly clientIp?: string;
  readonly statusPreview?: number;
}

export interface OcsfApiActivity {
  readonly class_name: "API Activity";
  readonly class_uid: 6003;
  readonly category_uid: 6;
  readonly activity_id: number;
  readonly metadata: {
    readonly version: "1.2.0";
    readonly product: {
      readonly name: "AIdenID Clearance Layer";
      readonly vendor_name: "PlexAura";
    };
    readonly correlation_uid: string;
  };
  readonly time: number;
  readonly severity_id: number;
  readonly actor: {
    readonly user: { readonly uid: string };
    readonly invoked_by: string;
    readonly process: { readonly name: string };
  };
  readonly src_endpoint?: { readonly ip: string };
  readonly dst_endpoint: { readonly svc_name: string; readonly path: string };
  readonly api: { readonly operation: OcsfHttpMethod; readonly request: { readonly uid: string } };
  readonly http_request: { readonly http_method: OcsfHttpMethod; readonly url: { readonly path: string } };
  readonly http_response: { readonly code: number };
  readonly observables: readonly { readonly name: string; readonly type: "Other"; readonly value: string | number }[];
}

export function ocsfActivityId(method: OcsfHttpMethod): number {
  switch (method) {
    case "GET":
    case "HEAD":
      return 1;
    case "POST":
      return 2;
    case "PUT":
    case "PATCH":
      return 3;
    case "DELETE":
      return 4;
    case "OPTIONS":
      return 99;
  }
}

export function severityFromDecision(decision: OcsfDecisionAction): number {
  switch (decision) {
    case "allow":
      return 1;
    case "throttle":
    case "queue":
    case "price_required":
      return 2;
    case "sandbox":
      return 3;
    case "deny":
      return 4;
  }
}

export function statusPreviewFromDecision(decision: OcsfDecisionAction): number {
  switch (decision) {
    case "allow":
      return 200;
    case "throttle":
      return 429;
    case "queue":
      return 202;
    case "sandbox":
      return 200;
    case "deny":
      return 403;
    case "price_required":
      return 402;
  }
}

export function toOcsfApiActivity(event: DecisionEventForOcsf): OcsfApiActivity {
  const time = Date.parse(event.occurredAt);
  if (!Number.isFinite(time)) {
    throw new Error("decision event occurredAt is invalid");
  }

  const traceId = event.traceId ?? event.requestId;
  const effectiveDecision = event.operatorEffectiveDecision ?? event.decision;
  const operatorObservables =
    event.operatorAction === undefined
      ? []
      : [
          { name: "operator_action", type: "Other" as const, value: event.operatorAction },
          { name: "operator_effective_decision", type: "Other" as const, value: effectiveDecision }
        ];
  const llmBrandObservable = event.llmBrand === undefined ? [] : [{ name: "llm_brand", type: "Other" as const, value: event.llmBrand }];
  const purposeObservable = event.purpose === undefined ? [] : [{ name: "purpose", type: "Other" as const, value: event.purpose }];
  const priceObservable = event.priceUsd === undefined ? [] : [{ name: "price_usd", type: "Other" as const, value: event.priceUsd }];
  return {
    class_name: "API Activity",
    class_uid: 6003,
    category_uid: 6,
    activity_id: ocsfActivityId(event.method),
    metadata: {
      version: "1.2.0",
      product: {
        name: "AIdenID Clearance Layer",
        vendor_name: "PlexAura"
      },
      correlation_uid: traceId
    },
    time,
    severity_id: severityFromDecision(effectiveDecision),
    actor: {
      user: { uid: event.subjectHandle ?? "unknown_subject" },
      invoked_by: event.issuer ?? "unknown_issuer",
      process: { name: event.actorClass }
    },
    ...(event.clientIp === undefined ? {} : { src_endpoint: { ip: event.clientIp } }),
    dst_endpoint: {
      svc_name: event.siteId,
      path: event.routeTemplate
    },
    api: {
      operation: event.method,
      request: { uid: traceId }
    },
    http_request: {
      http_method: event.method,
      url: { path: event.routeTemplate }
    },
    http_response: {
      code: event.statusPreview ?? statusPreviewFromDecision(effectiveDecision)
    },
    observables: [
      { name: "decision", type: "Other", value: event.decision },
      { name: "actor_class", type: "Other", value: event.actorClass },
      { name: "reason_codes", type: "Other", value: event.reasonCodes.join(",") },
      ...llmBrandObservable,
      ...purposeObservable,
      ...priceObservable,
      ...operatorObservables
    ]
  };
}
