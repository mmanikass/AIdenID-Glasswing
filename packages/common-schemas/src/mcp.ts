import { z } from "zod";

export const MCP_PROTECTED_RESOURCE_WELL_KNOWN_PATH = "/.well-known/oauth-protected-resource";

export const MCP_FRONT_DOOR_SCOPES = [
  "aidenid:session.exchange",
  "aidenid:decisions.read",
  "aidenid:decisions.write",
  "aidenid:policy.read"
] as const;

export const MCP_FRONT_DOOR_DPOP_ALGS = ["EdDSA", "ES256"] as const;

export const McpProtectedResourceMetadataSchema = z
  .object({
    resource: z.string().url(),
    authorization_servers: z.array(z.string().url()).min(1),
    scopes_supported: z.array(z.string().min(1)).min(1),
    bearer_methods_supported: z.array(z.literal("header")).min(1),
    resource_documentation: z.string().url(),
    resource_policy_uri: z.string().url(),
    dpop_bound_access_tokens_required: z.literal(true),
    dpop_signing_alg_values_supported: z.array(z.enum(MCP_FRONT_DOOR_DPOP_ALGS)).min(1),
    resource_signing_alg_values_supported: z.array(z.enum(MCP_FRONT_DOOR_DPOP_ALGS)).min(1)
  })
  .strict();

export type McpProtectedResourceMetadata = z.infer<typeof McpProtectedResourceMetadataSchema>;

function httpsUrl(value: string, field: string): string {
  const parsed = new URL(value);
  if (parsed.protocol !== "https:") {
    throw new Error(`${field} must use https`);
  }
  return parsed.toString().replace(/\/$/, "");
}

export function buildMcpProtectedResourceMetadata(input: {
  readonly resource: string;
  readonly authorizationServers: readonly string[];
  readonly documentationUrl?: string | undefined;
  readonly policyUrl?: string | undefined;
  readonly scopes?: readonly string[] | undefined;
}): McpProtectedResourceMetadata {
  const resource = httpsUrl(input.resource, "resource");
  const authorizationServers = input.authorizationServers.map((server) => httpsUrl(server, "authorization server"));
  const metadata = {
    resource,
    authorization_servers: authorizationServers,
    scopes_supported: [...(input.scopes ?? MCP_FRONT_DOOR_SCOPES)],
    bearer_methods_supported: ["header"],
    resource_documentation: httpsUrl(input.documentationUrl ?? "https://aidenid.com/docs/mcp-front-door", "resource documentation"),
    resource_policy_uri: httpsUrl(input.policyUrl ?? "https://aidenid.com/legal/mcp-front-door-policy", "resource policy URI"),
    dpop_bound_access_tokens_required: true,
    dpop_signing_alg_values_supported: [...MCP_FRONT_DOOR_DPOP_ALGS],
    resource_signing_alg_values_supported: [...MCP_FRONT_DOOR_DPOP_ALGS]
  };
  return McpProtectedResourceMetadataSchema.parse(metadata);
}
