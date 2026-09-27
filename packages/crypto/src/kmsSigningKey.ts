export interface KmsSignRequest {
  readonly KeyId: string;
  readonly Message: Uint8Array;
  readonly MessageType: "RAW";
  readonly SigningAlgorithm: string;
}

export interface KmsSignResponse {
  readonly Signature?: Uint8Array;
  readonly KeyId?: string;
  readonly SigningAlgorithm?: string;
}

export interface KmsSignClient {
  sign(request: KmsSignRequest): Promise<KmsSignResponse>;
}

export interface KmsSigningKeyProviderOptions {
  readonly client: KmsSignClient;
  readonly keyId: string;
  readonly alg: "ES256" | "EdDSA";
  readonly signingAlgorithm: string;
}

export interface DetachedSignature {
  readonly keyId: string;
  readonly alg: "ES256" | "EdDSA";
  readonly signature: Uint8Array;
}

export class KmsSigningKeyProvider {
  readonly #client: KmsSignClient;
  readonly #keyId: string;
  readonly #alg: "ES256" | "EdDSA";
  readonly #signingAlgorithm: string;

  constructor(options: KmsSigningKeyProviderOptions) {
    if (!options.keyId.trim()) {
      throw new Error("KMS keyId is required");
    }
    if (!options.signingAlgorithm.trim()) {
      throw new Error("KMS signingAlgorithm is required");
    }

    this.#client = options.client;
    this.#keyId = options.keyId;
    this.#alg = options.alg;
    this.#signingAlgorithm = options.signingAlgorithm;
  }

  async sign(payload: Uint8Array): Promise<DetachedSignature> {
    const response = await this.#client.sign({
      KeyId: this.#keyId,
      Message: payload,
      MessageType: "RAW",
      SigningAlgorithm: this.#signingAlgorithm
    });

    if (response.Signature === undefined) {
      throw new Error("KMS sign response did not include Signature");
    }

    return {
      keyId: response.KeyId ?? this.#keyId,
      alg: this.#alg,
      signature: Buffer.from(response.Signature)
    };
  }
}
