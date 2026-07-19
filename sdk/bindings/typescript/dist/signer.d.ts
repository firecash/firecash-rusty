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
export declare function wasmPaymentSigner(input: {
    seedHex: string;
    fvkHex(seedHex: string): Promise<string>;
    verifyAndSignPayment(seedHex: string, network: Network, recipient: string, amountSompi: bigint, maxFeeSompi: bigint, bundleHex: string, disclosureJson: string, alphasJson: string): Promise<DeviceSignature[]>;
}): PaymentSigner;
export declare function assertPaymentRequest(request: PaymentRequest): void;
