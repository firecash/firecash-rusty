import { type PaymentSigner } from "./signer.js";
import type { DeviceSignature, Network, PaymentRequest, PrepareResponse, SendProgress, SendStage, SubmitResponse, WalletBalance, WalletHistory, WalletStatus, SendResult } from "./types.js";
/**
 * Largest per-transaction fee the SDK authorizes unless the caller sets a
 * higher `maxFeeSompi` (0.1 ZKAS). The worst honest byte-priced fee — a
 * 6-spend standard transaction — is ~0.044 ZKAS.
 */
export declare const DEFAULT_MAX_FEE_SOMPI = 10000000n;
export declare class ZKasSdkError extends Error {
    readonly status?: number | undefined;
    readonly body?: unknown | undefined;
    constructor(message: string, status?: number | undefined, body?: unknown | undefined);
}
export interface ZKasClientConfig {
    baseUrl: string;
    walletToken?: string;
    network: Network;
    fetch?: typeof globalThis.fetch;
}
export declare class ZKasClient {
    #private;
    constructor(config: ZKasClientConfig);
    /** Daemon + wallet status. Check `missing_history` before trusting a balance. */
    status(): Promise<WalletStatus>;
    balance(): Promise<WalletBalance>;
    /** Chain-derived history (survives seed restores, unlike device-local lists). */
    history(): Promise<WalletHistory>;
    /**
     * Register a WATCH-ONLY wallet from a 96-byte full viewing key: the daemon
     * can sync and prepare payments but is powerless to authorize them. This is
     * the only registration path the SDK offers — a seed never belongs on a
     * hosted daemon. `birthdayDaa` bounds the initial scan; always pass it for
     * restored wallets so the daemon knows history before it is complete.
     */
    watch(fvkHex: string, birthdayDaa?: number): Promise<{
        address: string;
    }>;
    /**
     * Re-derive the wallet from the chain. The daemon REFUSES a rescan that
     * would lose sight of notes the connected node has pruned (HTTP 409); pass
     * `force` only after the user explicitly accepted that loss.
     */
    rescan(force?: boolean): Promise<{
        rescanning: boolean;
    }>;
    /**
     * Send a payment, non-custodially: prepare on the daemon, verify and sign on
     * this device, submit. Splits across up to 24 standard transactions when the
     * wallet's notes require it (each chunk is independently verified and
     * signed). The signer bounds every chunk's fee by `maxFeeSompi`.
     */
    send(signer: PaymentSigner, request: PaymentRequest, onStage?: (stage: SendStage, progress?: SendProgress) => void): Promise<SendResult>;
    prepare(fvkHex: string, request: PaymentRequest, allowPartial?: boolean): Promise<PrepareResponse>;
    submit(session: string, signatures: DeviceSignature[]): Promise<SubmitResponse>;
}
/** The effective per-transaction fee ceiling of a request: the caller's ceiling
 * or the standing default, never below the caller's own fee floor. */
export declare function maxFeeOf(request: PaymentRequest): bigint;
