# Gateway Operations

## Self-hosted service

Run walletd in watch-only mode for the merchant FVK, then configure:

```text
ZKAS_GATEWAY_FVK=<96-byte hex FVK>
ZKAS_GATEWAY_PUBLIC_URL=https://pay.example.com
ZKAS_GATEWAY_API_KEY=<random merchant API key>
ZKAS_GATEWAY_WEBHOOK_SECRET=<random webhook secret>
ZKAS_GATEWAY_WEBHOOK_URL=https://shop.example.com/wp-json/zkas/v1/webhook
ZKAS_WALLETD_URL=http://127.0.0.1:8501
ZKAS_WALLET_TOKEN=<watch-only wallet token>
ZKAS_GATEWAY_LISTEN=127.0.0.1:8510
ZKAS_GATEWAY_STATE=/var/lib/zkas-gateway/state.json
```

Put TLS and request limits in a reverse proxy. Back up the state file and FVK.
The FVK cannot spend funds, but disclosure reveals merchant transaction activity.

```bash
cargo run -p zkas-gateway --release
```

## WooCommerce

Zip `integrations/woocommerce/zkas-gateway.php`, install it as a plugin, then set
the gateway URL, API key, webhook secret, and conversion rate. The same plugin
works with the hosted service or a merchant's own instance.

The fixed conversion rate is an explicit initial limitation. A production hosted
deployment should add a quote service with multiple price sources, quote expiry,
and the fiat amount/currency frozen into each invoice.

