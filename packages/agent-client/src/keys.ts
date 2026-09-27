import { createPublicKey, generateKeyPairSync, randomUUID, type KeyObject } from "node:crypto";

import { canonicalJwkThumbprintBase64Url, type PublicJwk } from "@aidenid/crypto";

/**
 * An agent's proof-of-possession key. Minted server-side for the demo runner; the private
 * key never leaves the process that acts as the agent. The thumbprint is what a grant
 * exchange binds the session to (`proof_jkt`), and the keyId is what the protected site
 * registers for HTTP message signatures.
 */
export interface AgentKeyMaterial {
  readonly keyId: string;
  readonly privateKey: KeyObject;
  readonly publicJwk: PublicJwk;
  /** RFC 7638 canonical thumbprint, base64url. Equals the `cnf.jkt` the session token must carry. */
  readonly thumbprint: string;
}

function publicJwkOf(publicKey: KeyObject): PublicJwk {
  const exported = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  // Only the public members, in a stable shape; no private scalar ever reaches a JWK we hand out.
  return { kty: exported.kty, crv: exported.crv, x: exported.x, ...(exported.y === undefined ? {} : { y: exported.y }) };
}

/** Mint a fresh Ed25519 agent key. `keyId` defaults to a random `agk_` identifier. */
export function mintAgentKey(keyId: string = `agk_${randomUUID().replaceAll("-", "")}`): AgentKeyMaterial {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicJwkOf(publicKey);
  return { keyId, privateKey, publicJwk, thumbprint: canonicalJwkThumbprintBase64Url(publicJwk) };
}

/** Rebuild key material from a stored private key (for a runner that persists its key). */
export function agentKeyFromPrivateKey(keyId: string, privateKey: KeyObject): AgentKeyMaterial {
  const publicJwk = publicJwkOf(createPublicKey(privateKey));
  return { keyId, privateKey, publicJwk, thumbprint: canonicalJwkThumbprintBase64Url(publicJwk) };
}

/** What a protected site registers so its verifier trusts this agent's HTTP signatures. */
export function httpSignatureTrustEntry(key: AgentKeyMaterial): Readonly<Record<string, PublicJwk>> {
  return { [key.keyId]: key.publicJwk };
}
