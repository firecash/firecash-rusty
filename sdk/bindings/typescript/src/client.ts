import { assertPaymentRequest, type PaymentSigner } from "./signer.js";
import type { DeviceSignature, Network, PaymentRequest, PrepareResponse, SendStage, SubmitResponse } from "./types.js";

export class ZKasSdkError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly body?: unknown,
  ) {
    super(message);
    this.name = "ZKasSdkError";
  }
}

export interface ZKasClientConfig {
  baseUrl: string;
  walletToken?: string;
  network: Network;
  fetch?: typeof globalThis.fetch;
}

export class ZKasClient {
  readonly #baseUrl: string;
  readonly #walletToken: string | undefined;
  readonly #network: Network;
  readonly #fetch: typeof globalThis.fetch;

  constructor(config: ZKasClientConfig) {
    this.#baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.#walletToken = config.walletToken;
    this.#network = config.network;
    this.#fetch = config.fetch ?? globalThis.fetch.bind(globalThis);
  }

  async send(
    signer: PaymentSigner,
    request: PaymentRequest,
    onStage?: (stage: SendStage) => void,
  ): Promise<SubmitResponse> {
    assertPaymentRequest(request);
    const fvk = await signer.fullViewingKeyHex();
    onStage?.("preparing");
    const prepared = await this.prepare(fvk, request);
    const amount = BigInt(prepared.amount_sompi_exact);
    const fee = BigInt(prepared.fee_sompi_exact);
    if (amount !== request.amountSompi) throw new ZKasSdkError("prover changed the requested amount");
    if (request.feeSompi !== undefined && fee < request.feeSompi)
      throw new ZKasSdkError("prover returned a fee below the requested relay floor");
    onStage?.("verifying");
    onStage?.("signing");
    const signatures = await signer.verifyAndSign({
      network: this.#network,
      recipient: request.to.trim(),
      amountSompi: request.amountSompi,
      feeSompi: fee,
      prepared,
    });
    onStage?.("broadcasting");
    const result = await this.submit(prepared.session, signatures);
    onStage?.("submitted");
    return result;
  }

  async prepare(fvkHex: string, request: PaymentRequest): Promise<PrepareResponse> {
    return this.#request<PrepareResponse>("/api/wallet/prepare", {
      fvk_hex: fvkHex,
      to: request.to.trim(),
      amount_sompi: request.amountSompi.toString(),
      ...(request.feeSompi === undefined ? {} : { fee: request.feeSompi.toString() }),
      ...(request.memo === undefined ? {} : { memo: request.memo }),
    });
  }

  async submit(session: string, signatures: DeviceSignature[]): Promise<SubmitResponse> {
    return this.#request<SubmitResponse>("/api/wallet/submit", { session, sigs: signatures });
  }

  async #request<T>(path: string, body: unknown): Promise<T> {
    const headers = new Headers({ "content-type": "application/json" });
    if (this.#walletToken !== undefined) headers.set("x-wallet-token", this.#walletToken);
    const response = await this.#fetch(`${this.#baseUrl}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
    const value: unknown = await response.json().catch(() => undefined);
    if (!response.ok) {
      const message = typeof value === "object" && value !== null && "error" in value ? String(value.error) : `wallet service returned ${response.status}`;
      throw new ZKasSdkError(message, response.status, value);
    }
    return value as T;
  }
}
