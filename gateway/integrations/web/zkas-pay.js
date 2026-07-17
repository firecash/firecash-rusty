/** Drop-in checkout launcher. Your backend endpoint creates the invoice so the
 * merchant API key is never exposed in browser JavaScript. */
export async function openZKasCheckout({ createInvoiceUrl, orderId, amount, metadata = {} }) {
  const response = await fetch(createInvoiceUrl, {
    method: "POST",
    headers: { "content-type": "application/json", "idempotency-key": String(orderId) },
    body: JSON.stringify({ orderId, amount, metadata }),
  });
  if (!response.ok) throw new Error(`ZKas invoice creation failed (${response.status})`);
  const invoice = await response.json();
  if (typeof invoice.checkoutUrl !== "string") throw new Error("Gateway returned no checkout URL");
  window.location.assign(invoice.checkoutUrl);
}

