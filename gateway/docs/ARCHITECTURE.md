# ZKas Merchant Gateway Architecture

## Deployment choices

| Merchant | Deployment | Keys and privacy |
|---|---|---|
| Fastest setup | Hosted gateway + plugin/API key | Hosted service receives the merchant FVK and can observe that merchant's payments, but cannot spend |
| Privacy-focused business | Self-host the same gateway and walletd | FVK, order graph, and customer payment metadata stay with merchant |
| Application/platform | Embed `zkas-payment-gateway` and `zkas-sdk` | Application owns transport, database, checkout, and webhook policy |
| Simple donation page | Static address/widget | No invoice reconciliation; suitable only when order matching is unnecessary |

All modes use the same invoice states and HTTP contract, so WooCommerce and
generic integrations switch between hosted and self-hosted by changing URL and
API key.

## Why unique diversified addresses

Every invoice receives a different Orchard diversified address derived from the
merchant FVK. The watch-only scanner can decrypt the received note and recover
that address, while observers cannot associate it with the merchant. This avoids
fragile amount matching and lets two customers pay identical prices concurrently.

The gateway never needs a seed or spending key. Refunds are intentionally a
merchant-wallet action requiring explicit approval; the gateway can create a
refund request but must not silently spend.

## Invoice lifecycle

```text
new -> partial -> paid -> confirmed
  \       \         \-> overpaid
   \-------> expired (only when unpaid)
```

`paid` means sufficient value was detected. `confirmed` means each contributing
payment is at least the configured confirmation distance behind the current tip.
The observer reads the node's virtual DAA score from walletd `/api/status` and
each payment's DAA score from history, so confirmation depth is measured in
selected-chain DAA (walletd exposes DAA, not blue score) — an invoice reaches
`confirmed` only once the tip advances `requiredBlueScore` beyond the paying
transaction, never instantly on first sight.

## API

`POST /api/v1/invoices` requires a bearer API key and accepts an
`Idempotency-Key`. Amounts are decimal sompi strings. It returns an unguessable
invoice ID, unique address, exact amount, status, and hosted checkout URL.

`GET /api/v1/invoices/{id}` supports checkout polling. Invoice IDs carry enough
entropy to act as public read capabilities; merchant administration endpoints
must still require authentication.

Webhook bodies are signed as `t=<unix>,v1=<HMAC-SHA256>` over
`timestamp + "." + exact_body`. Consumers verify with constant-time comparison,
reject stale timestamps, and process event IDs idempotently.

## Research applied

- BTCPay Server: self-hosting, store API keys, invoices, checkout redirect,
  webhooks, refunds, and plugins.
- Stripe/Coinbase-style integrations: idempotency keys, signed webhook bodies,
  explicit state transitions, and backend-only secrets.
- Monero gateways: unique address per order and honest disclosure of view-key
  privacy tradeoffs.
- ZKas-specific: Orchard FVK/diversified addresses, encrypted recipient recovery,
  integer sompi, BlockDAG blue-score confirmation, and watch-only operation.

