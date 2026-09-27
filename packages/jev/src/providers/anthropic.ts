import Anthropic from "@anthropic-ai/sdk";
import { zodOutputFormat } from "@anthropic-ai/sdk/helpers/zod";

import { JEV_OUTPUT_SCHEMA } from "../schema.js";
import type { JevProvider, JevProviderRequest } from "../types.js";

export interface AnthropicJevProviderOptions {
  /** Explicit key; otherwise ANTHROPIC_API_KEY (or an `ant auth login` profile) is used by the SDK. */
  readonly apiKey?: string | undefined;
  /** Model id. Default claude-opus-5 at low effort: this is a one-question classifier. */
  readonly model?: string | undefined;
  /** Injected client for tests. */
  readonly client?: Anthropic | undefined;
  /** Per-request SDK timeout in ms; the core's AbortSignal still governs the deadline. */
  readonly requestTimeoutMs?: number | undefined;
}

const DEFAULT_MODEL = "claude-opus-5";

function keyConfigured(options: AnthropicJevProviderOptions): boolean {
  if (options.client !== undefined || options.apiKey !== undefined) {
    return true;
  }
  return Boolean(process.env.ANTHROPIC_API_KEY?.trim() || process.env.ANTHROPIC_AUTH_TOKEN?.trim());
}

/**
 * Anthropic-backed Jev provider. Returns undefined when no credential is configured, so the
 * caller runs with no provider and every check reports `unavailable` instead of a fake verdict.
 * The provider key never leaves the server process.
 */
export function createAnthropicJevProvider(options: AnthropicJevProviderOptions = {}): JevProvider | undefined {
  if (!keyConfigured(options)) {
    return undefined;
  }
  const model = options.model ?? process.env.JEV_MODEL?.trim() ?? DEFAULT_MODEL;
  const client =
    options.client ??
    new Anthropic({
      ...(options.apiKey === undefined ? {} : { apiKey: options.apiKey }),
      maxRetries: 0,
      timeout: options.requestTimeoutMs ?? 8_000
    });

  return {
    modelVersion: model,
    async assess(request: JevProviderRequest): Promise<unknown> {
      const response = await client.messages.parse(
        {
          model,
          max_tokens: 512,
          system: request.system,
          messages: [{ role: "user", content: request.user }],
          output_config: { format: zodOutputFormat(JEV_OUTPUT_SCHEMA), effort: "low" }
        },
        { signal: request.signal }
      );
      if (response.stop_reason === "refusal") {
        // A declined classification is not an answer. The core records provider_error ->
        // unavailable, which keeps a mandatory check non-executable.
        throw new Error("jev_provider_refusal");
      }
      // parsed_output is null when the SDK could not validate; the core re-validates anyway.
      return response.parsed_output ?? textOutput(response);
    }
  };
}

function textOutput(response: Anthropic.Message): unknown {
  const text = response.content.find((block): block is Anthropic.TextBlock => block.type === "text")?.text;
  if (text === undefined) {
    return undefined;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}
