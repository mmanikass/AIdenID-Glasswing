export interface ServiceDescriptor {
  readonly name: string;
  readonly hotPath: boolean;
  readonly owns: readonly string[];
}

export function describeControlPlane(): ServiceDescriptor {
  return {
    name: "control-plane-api",
    hotPath: false,
    owns: ["targets", "policies", "grants", "sessions", "revocation"]
  };
}

export * from "./app.js";
export * from "./ids.js";
export * from "./migrations.js";
export * from "./plugins/correlation.js";
export * from "./plugins/operatorAuth.js";
export * from "./services/revocation.js";
export * from "./services/killSwitch.js";
export * from "./services/store.js";
export * from "./services/decisionReceipts.js";
export * from "./services/webhookSecrets.js";
export * from "./types.js";
