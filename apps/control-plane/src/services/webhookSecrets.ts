import { createHash } from "node:crypto";

import { WebhookSecretResolutionError, type WebhookSecretResolver } from "../types.js";

function envKeyForRef(ref: string): string {
  const digest = createHash("sha256").update(ref, "utf8").digest("hex").slice(0, 16).toUpperCase();
  return `AIDENID_WEBHOOK_SECRET_${digest}`;
}

export class EnvironmentWebhookSecretResolver implements WebhookSecretResolver {
  resolve(ref: string): string {
    const trimmed = ref.trim();
    if (trimmed.startsWith("env://")) {
      const key = trimmed.slice("env://".length);
      const value = process.env[key];
      if (value !== undefined && value.length > 0) {
        return value;
      }
      throw new WebhookSecretResolutionError(ref, `webhook signing secret env var '${key}' is not set`);
    }

    const hashedEnvKey = envKeyForRef(trimmed);
    const value = process.env[hashedEnvKey];
    if (value !== undefined && value.length > 0) {
      return value;
    }
    throw new WebhookSecretResolutionError(ref, `webhook signing secret ref must resolve through env:// or ${hashedEnvKey}`);
  }
}

export class StaticWebhookSecretResolver implements WebhookSecretResolver {
  readonly #secrets: Readonly<Record<string, string | Uint8Array>>;

  constructor(secrets: Readonly<Record<string, string | Uint8Array>>) {
    this.#secrets = secrets;
  }

  resolve(ref: string): string | Uint8Array {
    const secret = this.#secrets[ref];
    if (secret === undefined || (typeof secret === "string" && secret.length === 0)) {
      throw new WebhookSecretResolutionError(ref);
    }
    return secret;
  }
}
