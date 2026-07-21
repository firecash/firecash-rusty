# Gateway integration

Use the same API for the hosted gateway or a self-hosted instance.

## 1. Create an invoice

Call the gateway from your **server**, never directly from browser code because
the API key must remain secret.

```http
POST /api/v1/invoices
Authorization: Bearer YOUR_API_KEY
Idempotency-Key: order-123
Content-Type: application/json

{
  "orderId": "order-123",
  "amountSompi": "10000000",
  "expiresIn": 900,
  "requiredBlueScore": 10,
  "redirectUrl": "https://shop.example.com/order/123"
}
```

`1 ZKAS = 100,000,000 sompi`; therefore `10000000` is `0.1 ZKAS`.
Amounts are decimal strings so JavaScript cannot lose integer precision.

The response contains:

```json
{
  "id": "inv_...",
  "address": "zkas:...",
  "amountSompi": "10000000",
  "status": "new",
  "checkoutUrl": "https://pay.example.com/checkout/inv_..."
}
```

Redirect the customer to `checkoutUrl` or display the returned address and
amount in your own interface.

## 2. Check payment status

```http
GET /api/v1/invoices/inv_...
```

Possible statuses are:

| Status | Meaning |
|---|---|
| `new` | No payment received |
| `partial` | Some value received, but not enough |
| `paid` | Full amount detected; confirmation policy not reached |
| `confirmed` | Full amount received and confirmed |
| `overpaid` | More than the requested amount received |
| `expired` | Unpaid invoice expired |
| `paidLate` | Payment arrived after expiry |

Fulfil an order only for `confirmed` or `overpaid`.

## 3. Receive webhooks

Set `ZKAS_GATEWAY_WEBHOOK_URL` and `ZKAS_GATEWAY_WEBHOOK_SECRET` on the gateway.
The gateway sends invoice events as JSON with this header:

```text
ZKas-Signature: t=TIMESTAMP,v1=HEX_HMAC
```

Verify:

```text
expected = HMAC-SHA256(secret, timestamp + "." + exact_request_body)
```

Use a constant-time comparison and reject timestamps outside a short tolerance.
Process webhook event IDs idempotently because delivery may be repeated.

## 4. Website integration

Your backend creates the invoice, then the browser redirects to its checkout:

```js
const response = await fetch("/api/create-zkas-invoice", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ orderId: "order-123" })
});
const invoice = await response.json();
location.href = invoice.checkoutUrl;
```

`gateway/integrations/web/zkas-pay.js` provides the same redirect flow as a
small reusable browser helper.

## 5. WooCommerce

Install `gateway/integrations/woocommerce/zkas-gateway.php` as a WordPress
plugin, enable **ZKAS Gateway** under WooCommerce payment settings, and enter:

- gateway URL;
- API key;
- webhook secret;
- ZKAS conversion rate;
- required blue-score confirmation distance.

Configure the gateway webhook URL as:

```text
https://shop.example.com/wp-json/zkas/v1/webhook
```

## Important

- Generate one unique gateway address per invoice.
- Never expose the merchant API key in frontend JavaScript.
- Store the invoice ID against the merchant order ID.
- Use a unique, stable `Idempotency-Key` for every order.
- Use exact sompi strings, not floating-point ZKAS values.
- Do not fulfil an order from a browser redirect alone; verify gateway status or
  a valid signed webhook.

