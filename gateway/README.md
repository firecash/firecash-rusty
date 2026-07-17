# ZKas Payment Gateway

Merchant payment infrastructure built on the ZKas SDK. The design follows the
proven invoice/webhook model used by BTCPay Server and the unique-address model
used by privacy-coin gateways, adapted to Orchard and Kaspa BlockDAG finality.

- `core/` — invoice state machine, diversified addresses, idempotency, payment
  reconciliation, confirmation policy, and signed webhook events.
- `service/` — runnable HTTP API, checkout, wallet observer, persistence, and webhooks.
- `integrations/woocommerce/` — WooCommerce payment method.
- `integrations/web/` — generic browser checkout launcher.
- `docs/STATUS.md` — implemented scope and hosted-production hardening work.
