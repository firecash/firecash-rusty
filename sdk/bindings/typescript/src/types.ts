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

export interface PreparedPaymentV1 {
  format: "zkas-prepared-payment";
  version: 1;
  networkDomain: string;
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
  bundle_hex: string;
  disclosure: LegacyDisclosure[];
  spend_auth: LegacySpendAuth[];
  preparedPayment: PreparedPaymentV1;
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
  /** Fee floor approved by the user; walletd may only raise it before signing. */
  feeSompi?: bigint;
  memo?: string;
}

export type SendStage = "preparing" | "verifying" | "signing" | "broadcasting" | "submitted";
