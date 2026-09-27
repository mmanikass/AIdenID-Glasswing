import { describe, expect, it } from "vitest";

import { KmsSigningKeyProvider, type KmsSignClient, type KmsSignRequest } from "../src/index.js";

describe("KMS signing key provider", () => {
  it("delegates detached signing to a KMS-shaped client", async () => {
    const requests: KmsSignRequest[] = [];
    const client: KmsSignClient = {
      async sign(request) {
        requests.push(request);
        return {
          KeyId: request.KeyId,
          SigningAlgorithm: request.SigningAlgorithm,
          Signature: new Uint8Array([1, 2, 3])
        };
      }
    };
    const provider = new KmsSigningKeyProvider({
      client,
      keyId: "arn:aws:kms:us-east-1:123456789012:key/example",
      alg: "ES256",
      signingAlgorithm: "ECDSA_SHA_256"
    });

    const signature = await provider.sign(Buffer.from("payload"));

    expect(signature).toMatchObject({ keyId: "arn:aws:kms:us-east-1:123456789012:key/example", alg: "ES256" });
    expect(Buffer.from(signature.signature)).toEqual(Buffer.from([1, 2, 3]));
    expect(requests).toEqual([
      {
        KeyId: "arn:aws:kms:us-east-1:123456789012:key/example",
        Message: Buffer.from("payload"),
        MessageType: "RAW",
        SigningAlgorithm: "ECDSA_SHA_256"
      }
    ]);
  });
});
