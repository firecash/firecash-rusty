# Gateway Status

## Implemented

- Reusable merchant gateway core.
- Unique Orchard diversified address per invoice.
- Watch-only FVK operation; no spending keys.
- Exact integer amounts, invoice expiry, partial payments, overpayments,
  idempotent creation, and duplicate-payment protection.
- Confirmation policy by selected-chain depth: an invoice confirms only once the
  node's virtual DAA score (from walletd `/api/status`) is `requiredBlueScore`
  beyond each paying transaction's DAA score — never instantly on first sight.
- Persistent snapshots with restart-safe invoice/address/payment indexes.
- Timestamped HMAC webhook signing and verification.
- Runnable hosted/self-hosted HTTP service.
- Automatic reconciliation from walletd's settled, FVK-derived history.
- Hosted checkout page and generic browser launcher.
- WooCommerce payment method and signed webhook receiver.
- Same API URL contract for hosted and self-hosted merchants.

## Before public hosted production

- Add a hosted control plane that provisions an isolated gateway tenant per
  merchant (the current service is deliberately single-store and ideal for
  self-hosting or one isolated hosted tenant).
- Add a durable webhook outbox with exponential retries and delivery logs.
- Add merchant dashboard/API-key rotation and encrypted configuration storage.
- Add multi-source fiat price quotes with frozen rate, currency, and expiry.
- Package/test the WordPress ZIP across supported PHP/WooCommerce versions.
- Add refund-request workflow; actual refund signing must remain in the merchant
  wallet and require explicit approval.
- Conduct an external security review and load test.

The single-store isolation model is intentional: a hosted operator can provision
one container and state volume per business immediately, while a later control
plane manages those tenants without pooling FVKs or invoice databases.

