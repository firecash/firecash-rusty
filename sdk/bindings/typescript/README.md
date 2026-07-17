# `@zkas/sdk`

TypeScript orchestration for the ZKas hosted non-custodial flow. Cryptographic
verification and signing remain in the Rust/WASM `zkas-signer`; this package
coordinates typed prepare, local authorization, submit, errors, and progress.

All payment amounts are `bigint`. The package intentionally has no API accepting
floating-point ZKAS amounts.

```ts
const signer = wasmPaymentSigner({ seedHex, fvkHex, verifyAndSignPayment });
const client = new ZKasClient({ baseUrl, walletToken, network: "mainnet" });
const sent = await client.send(signer, {
  to: recipient,
  amountSompi: 100_000_000n,
  feeSompi: 3_000_000n,
});
```

