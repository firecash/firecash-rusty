import type { DeviceSignature, Network, PaymentRequest, PrepareResponse } from "./types.js";

/** Security boundary implemented by the ZKas Rust/WASM signer. */
export interface PaymentSigner {
  fullViewingKeyHex(): Promise<string>;
  verifyAndSign(input: {
    network: Network;
    recipient: string;
    amountSompi: bigint;
    /**
     * Fee CEILING, not the fee. The signer reads the fee the bundle actually
     * pays (its public value balance) and refuses anything above this bound —
     * never trust a fee figure reported by the prover.
     */
    maxFeeSompi: bigint;
    prepared: PrepareResponse;
  }): Promise<DeviceSignature[]>;
}

/** Adapter for the production firecash-signer WASM wrapper. */
export function wasmPaymentSigner(input: {
  seedHex: string;
  fvkHex(seedHex: string): Promise<string>;
  verifyAndSignPayment(
    seedHex: string,
    network: Network,
    recipient: string,
    amountSompi: bigint,
    maxFeeSompi: bigint,
    bundleHex: string,
    disclosureJson: string,
    alphasJson: string,
  ): Promise<DeviceSignature[]>;
}): PaymentSigner {
  return {
    fullViewingKeyHex: () => input.fvkHex(input.seedHex),
    verifyAndSign: ({ network, recipient, amountSompi, maxFeeSompi, prepared }) =>
      input.verifyAndSignPayment(
        input.seedHex,
        network,
        recipient,
        amountSompi,
        maxFeeSompi,
        prepared.bundle_hex,
        JSON.stringify(prepared.disclosure),
        JSON.stringify(prepared.spend_auth),
      ),
  };
}

export function assertPaymentRequest(request: PaymentRequest): void {
  if (request.amountSompi <= 0n) throw new RangeError("amountSompi must be positive");
  if (request.feeSompi !== undefined && request.feeSompi < 0n) throw new RangeError("feeSompi cannot be negative");
  if (request.maxFeeSompi !== undefined && request.maxFeeSompi <= 0n) throw new RangeError("maxFeeSompi must be positive");
  if (!request.to.trim()) throw new TypeError("recipient is required");
}
