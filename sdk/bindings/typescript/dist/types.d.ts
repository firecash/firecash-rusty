export type Network = "mainnet" | "testnet" | "devnet" | "simnet";
export interface DisclosureV1 {
    spendValue: string;
    outValue: string;
    outRecipient: string;
    outRseed: string;
    rcv: string;
}
export interface SpendAuthV1 {
    actionIndex: number;
    alpha: string;
}
/**
 * Versioned prepared-payment envelope (see `zkas-sdk`'s `PreparedPaymentEnvelope`).
 * Version 2 embeds the prover's CLAIMED intent — recipient, amount, fee — so a
 * detached signer can display the payment from the envelope alone. Claims are
 * display data: the signer cross-checks them against the user's approval and
 * against the bundle itself, and reads the real fee from the bundle's value
 * balance, never from these fields.
 */
export interface PreparedPaymentEnvelope {
    format: "zkas-prepared-payment";
    version: 2;
    networkDomain: string;
    recipient: string;
    amount: string;
    fee: string;
    txContext: string;
    bundle: string;
    disclosure: DisclosureV1[];
    spendAuth: SpendAuthV1[];
    checksum: string;
}
export interface LegacyDisclosure {
    spend_value: number;
    out_value: number;
    out_recipient: string;
    out_rseed: string;
    rcv: string;
}
export interface LegacySpendAuth {
    index: number;
    alpha: string;
}
export interface PrepareResponse {
    session: string;
    amount_sompi: number;
    fee_sompi: number;
    amount_sompi_exact: string;
    fee_sompi_exact: string;
    /** Sompi of the request this transaction does NOT cover; only non-zero when
     * `allow_partial` was sent. Older daemons omit the exact form. */
    remaining_sompi?: number;
    remaining_sompi_exact?: string;
    bundle_hex: string;
    disclosure: LegacyDisclosure[];
    spend_auth: LegacySpendAuth[];
    preparedPayment: PreparedPaymentEnvelope;
}
export interface DeviceSignature {
    index: number;
    sig: string;
}
export interface SubmitResponse {
    txid: string;
    amount_sompi: number;
    fee_sompi: number;
    amount_sompi_exact: string;
    fee_sompi_exact: string;
}
export interface PaymentRequest {
    to: string;
    /** Exact integer amount. Never pass a floating-point coin amount. */
    amountSompi: bigint;
    /** Fee FLOOR the daemon may raise to the byte-priced relay minimum. */
    feeSompi?: bigint;
    /**
     * Largest per-transaction fee the local signer will authorize, in sompi.
     * Defaults to {@link DEFAULT_MAX_FEE_SOMPI} (0.1 ZKAS — far above any honest
     * byte-priced fee, far below a wallet's change). The signer reads the fee the
     * bundle ACTUALLY pays and refuses anything above this bound, so a malicious
     * prover cannot burn change as fee.
     */
    maxFeeSompi?: bigint;
    memo?: string;
    /**
     * A standard transaction spends at most 6 notes, so a fragmented wallet may
     * need several transactions for one payment. `true` (the default) sends in
     * chunks until the amount is covered; `false` refuses a payment that does not
     * fit one transaction instead of partially paying it.
     */
    allowChunking?: boolean;
}
/** One transaction of a logical payment that spanned several. */
export interface SendPart {
    txid: string;
    amountSompi: bigint;
    feeSompi: bigint;
}
export interface SendResult {
    /** First transaction id — kept for single-tx callers. */
    txid: string;
    txids: string[];
    parts: SendPart[];
    amountSompi: bigint;
    feeSompi: bigint;
}
export interface SendProgress {
    /** 1-based index of the transaction being built. */
    part: number;
    /** Best estimate of the total number of transactions, once known. */
    parts: number;
    sentSompi: bigint;
    totalSompi: bigint;
}
export type SendStage = "preparing" | "verifying" | "signing" | "broadcasting" | "submitted";
/** Mirror of walletd's `/api/status`. Optional fields come from newer daemons. */
export interface WalletStatus {
    has_wallet: boolean;
    address: string | null;
    network: string;
    node_connected: boolean;
    daa_score: number;
    synced: boolean;
    warming?: boolean;
    /** The connected node has pruned part of this wallet's history: the balance
     * is a LOWER BOUND and a rescan through this node would lose sight of older
     * notes. Surface this; silence is how "my coins vanished" happens. */
    missing_history?: boolean;
    scanned_blocks: number;
    chain_len: number;
    balance_sompi: string;
    spendable_sompi?: string;
    maturing_sompi?: string;
    note_count: number;
    updated_unix: number;
    error: string | null;
}
export interface WalletBalance {
    balance_sompi: string;
    synced: boolean;
    scanned_blocks: number;
    chain_len: number;
    notes: {
        position: number;
        value: number;
    }[];
    updated_unix: number;
    error: string | null;
}
export interface HistoryRow {
    kind: "coinbase" | "received" | "sent";
    txid: string;
    daaScore: number;
    timestamp: number;
    amountSompi: number;
    amountZkas: number;
    feeSompi: number;
    recipient?: string | null;
    memo?: string | null;
}
export interface WalletHistory {
    recoverableHistory: boolean;
    total: number;
    rows: HistoryRow[];
    pendingOutgoing?: {
        txid: string;
        amountSompi: number;
        amountZkas: number;
        submittedDaa: number;
    }[];
}
