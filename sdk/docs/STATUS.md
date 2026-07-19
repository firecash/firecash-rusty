# SDK Status

## 2026-07-19 security & scope revision

- **Fee ceiling enforced by the signer.** `PaymentIntent.fee` became
  `PaymentIntent.max_fee`: the signer now reads the fee a bundle actually pays
  from its value balance, requires it positive and at or below the user's
  ceiling, and refuses otherwise. Previously both TypeScript clients passed the
  *server-reported* fee into the intent, so a malicious prover could burn a
  wallet's entire change as fee while every commitment check passed.
- **Envelope v2** (`PreparedPaymentEnvelope`, format `zkas-prepared-payment`,
  version 2): embeds the prover's claimed recipient/amount/fee for detached
  display; claims are cross-checked against the approved intent and the bundle.
  Version-1 envelopes are no longer accepted. Walletd emits v2.
- **`@zkas/sdk` 0.2.0**: chunked sends (`allow_partial` loop with progress),
  fee-ceiling refusal before signing, and the missing wallet surface
  (status/watch/balance/history/rescan). Tested against a scripted fake daemon
  (`npm test`).
- **`zkas_sdk::engine` demoted to a reference skeleton** (see its module doc):
  it is not the production engine and must not carry a user-facing wallet. Its
  per-block checkpointing (O(blocks²) I/O) was fixed to per-batch.

## Delivered v1 foundation

- Public Rust facade (`zkas-sdk`).
- Deterministic payment planning with ZKas standard-mass and dynamic relay fees.
- Multi-transaction chunking for fragmented Orchard wallets.
- Zeroizing software signer with anti-blind payment verification.
- Versioned prepared-payment envelope with strict parsing and integrity checksum.
- Shielded-address parsing/formatting for supported ZKas networks.
- BlockDAG chain-source contract using selected-chain hash cursors, blue/DAA
  scores, pruning points, explicit reorg signals, and GHOSTDAG accepted order.
- Wallet engine that validates genesis, applies a settlement margin, decodes
  accepted Orchard bundles, updates history, and atomically checkpoints state.
- In-memory and atomic file stores.
- Rust payment-planning and prepared-signing examples.
- TypeScript package for hosted non-custodial prepare/verify/sign/submit.
- Production WASM signer delegates security policy to `zkas-signer`.
- Walletd emits the SDK prepared envelope and exact decimal u64 fields while
  preserving its legacy API.

## Trust modes supported now

| Mode | SDK support |
|---|---|
| Hosted FVK + local signer | Complete v1 path |
| Native local wallet engine + caller-supplied chain source | Core complete; application supplies node adapter |
| Watch-only | Core wallet constructor and hosted walletd path |
| Full browser scan/prove/store | Not production-ready |

## Work intentionally not mislabeled as finished

- A browser compact-block service and authenticated HTTP/WebSocket adapter.
- IndexedDB `WalletStore` and Web Worker scan/prove orchestration.
- Replacement of the current witness implementation with a sharded/checkpointed
  tree proven under very large wallet histories.
- Swift/Kotlin/Python packaging and hardware-signer transports.
- External security audit and published reproducible WASM artifacts.

Those are platform/distribution phases on top of v1, not missing cryptographic
logic that application developers should reimplement themselves.

