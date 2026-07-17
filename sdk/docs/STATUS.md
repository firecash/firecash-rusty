# SDK Status

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

