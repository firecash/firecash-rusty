# ZKas Wallet SDK Architecture

Status: proposed architecture based on the current node, shielded core, wallet daemon,
web wallet, WASM signer, and desktop integration.

## Decision

Build the SDK by extracting a reusable wallet engine from the code that already ships.
Do not expose `zkas-walletd` itself as the SDK and do not reimplement Orchard or transaction
cryptography in TypeScript, Swift, Kotlin, or Python.

Rust remains the canonical implementation. Thin bindings expose the same engine to native Rust,
WebAssembly/TypeScript, mobile, and eventually Python. `zkas-walletd`, the web wallet, CLI, and
Tauri application become consumers of this engine.

## What exists today

| Existing component | Reusable capability | SDK action |
|---|---|---|
| `kaspa-shielded-core` | Orchard keys and addresses, note encryption/scanning, bundles, wallet state, payment preparation/finalization, anti-blind checks, message signing | Keep as the protocol/cryptography foundation; split wallet-state concerns from pure protocol types over time |
| `kaspa-shielded-wallet` | Canonical version-2 Kaspa transaction construction, shielded payload wrapping, sighash context, accepted-block effects | Evolve into the transaction/chain adapter; remove unnecessary consensus-service coupling |
| `zkas-walletd` | Node sync, reorg/checkpoint handling, persistence, fees, coin selection, proving, prepare/submit, REST and gRPC integration | Extract the state machine into `zkas-wallet-engine`; leave walletd as a thin host and HTTP adapter |
| `firecash-signer` | Seed/FVK/address functions and local anti-blind verification/signing in WASM | Make this the first binding of a canonical `zkas-signer` crate; stop maintaining signing policy in app-specific code |
| `firecash-wallet` | Working watch-only registration, prepare -> local verify/sign -> submit flow, browser integration | Replace `api.ts`, signer glue, local pending-history heuristics, and direct seed handling with `@zkas/sdk` |
| Tauri wallet | Embeds `zkas_walletd::serve` and selects local or remote nodes | Migrate to an in-process SDK engine; optionally retain embedded walletd for compatibility |

The current hosted flow is genuinely non-custodial for spending: the browser holds the seed and
the daemon receives an FVK, prepares/proves, and returns material that the local signer verifies
before authorizing. It is not fully private from the wallet service because the service sees the
FVK and wallet activity. The SDK must name this mode accurately.

## Target layers

```text
Applications
  web wallet | desktop wallet | CLI | mobile | exchanges
                         |
Public SDK facades and bindings
  zkas-sdk (Rust) | @zkas/sdk (WASM/TS) | Swift/Kotlin | Python
                         |
zkas-wallet-engine
  accounts | sync | reorgs | notes/witnesses | proposals | fees
  proving | signing orchestration | pending tx | history | events
                  /                         \
        ChainSource                         WalletStore
  gRPC | light HTTP | wRPC          SQLite | IndexedDB | memory
                  \                         /
       zkas-signer + transaction adapter + shielded core
                         |
                 ZKas consensus/node
```

### Protocol and transaction core

The low-level crates own network parameters, address and key types, bundle encoding, note
encryption, transaction versioning, and sighash construction. They must not know about HTTP,
databases, React, or wallet sessions. Circuit/prover dependencies remain behind a feature so a
small signer or watch-only client does not carry proving code.

### Wallet engine

This is the actual SDK. It owns deterministic sync and transaction lifecycle behavior. UI code
must not calculate balances, reconcile pending transactions, choose notes, or infer confirmation
state independently.

The engine exposes operations such as:

```text
open(config, store, chain)
create_wallet / import_wallet / import_viewing_key
sync / pause_sync / sync_status / event_stream
balance / addresses / history / transaction_status
propose_payment(intent)
prepare_payment(proposal)
verify_and_sign(prepared, signer)
broadcast(signed)
```

Amounts are integer sompi-like units (`u64` in Rust and `bigint` or decimal strings at JS
boundaries). Floating-point coin amounts are presentation-only.

### Chain source

Define a narrow async interface rather than exposing node RPC messages:

```text
network_identity()
tip()
shielded_blocks(range)
mempool_effects(optional cursor)
submit_transaction(bytes)
transaction_status(id)
```

Implementations:

1. Native gRPC for desktop, servers, and CLI.
2. Versioned light HTTP/WebSocket transport for browsers and mobile.
3. Kaspa wRPC when its data model can serve the required shielded block information.
4. In-memory/mock sources for deterministic tests.

Every source is untrusted input. The engine validates network identity, block linkage and the
commitments required by the wallet model; only node consensus decides whether a transaction is
valid for the chain.

### Wallet store

Define transactional storage around accounts, scan checkpoints, note metadata, witnesses,
nullifiers, transactions, and pending broadcasts. The first durable implementation should be
SQLite; IndexedDB follows for full browser wallets. Writes for a scanned block and its checkpoint
must commit atomically so a crash cannot create an impossible wallet state.

The current opaque scan/checkpoint persistence may be supported by a migration reader, but it is
not the long-term public format. Stored records need schema versions and resumable migrations.

## Prepared transaction format

Replace the app-specific ephemeral prepare session with a versioned Prepared Shielded
Transaction format. It plays the same architectural role as PCZT/PSBT: construction, proving,
policy verification, signing, finalization, and broadcast can occur in different components.

It contains at least:

- format version, network identity and genesis/domain identifier;
- payment intent, fee, expiry, anchor and selected shielded effects;
- canonical unsigned transaction context and bundle bytes;
- signer disclosures needed to verify recipient, value and change;
- spend authorization data that is safe to transport;
- integrity checksum and explicit optional/required field rules.

It never contains a seed or spending key. The signer reconstructs the transaction and sighash
locally, validates network, recipient, amount, fee, change and expiry, and then signs. It must
never sign a hash supplied as an opaque trusted value by a server.

## Supported trust modes

| Mode | Keys/FVK | Scan and proving | Privacy/trust statement |
|---|---|---|---|
| Hosted hybrid (first public SDK) | Seed local; FVK at service | Service | Non-custodial spending, but service can observe the wallet and may censor preparation |
| Local/native | Seed and FVK local | SDK with remote or local node | Non-custodial and wallet-private from the node except for normal network metadata |
| Full browser | Seed and FVK in browser | WASM workers plus light source | Fully client-side wallet state; requires robust browser proving and authenticated sync |
| Watch-only | FVK only | SDK or service | Cannot spend; intentionally reveals wallet activity to its host |

Hosted hybrid is the fastest safe package because the production wallet already exercises it.
Full browser operation is the target, not a claim to make before witness persistence and browser
proving are reliable.

## Public packages

1. `kaspa-shielded-core`: protocol primitives and optional circuits.
2. `kaspa-shielded-wallet`: canonical ZKas transaction and block-effect adapter.
3. `zkas-signer`: key custody and anti-blind signing policy, with software signer traits.
4. `zkas-wallet-engine`: sync, storage, proposals, proving, history and lifecycle state machine.
5. `zkas-sdk`: stable Rust facade with feature-selected transports and stores.
6. `@zkas/sdk`: generated WASM/TypeScript package for browser and Node.js.
7. `zkas-walletd`: thin daemon using the same public SDK, with versioned `/v1` REST endpoints.

Mobile bindings should wrap `zkas-sdk` through UniFFI or small platform-specific FFI layers after
the Rust API stabilizes. A Python binding can follow through PyO3; it must wrap Rust rather than
porting cryptography.

## Build sequence

### Phase 0: freeze boundaries and vectors

- Document and version bundle bytes, transaction v2 encoding, address domains and sighash rules.
- Add golden vectors shared by core, walletd and the WASM signer.
- Define typed errors and integer amount conventions.
- Define the prepared-transaction schema before publishing an API.

### Phase 1: signer and interfaces

- Move the production anti-blind signer into `zkas-signer`.
- Keep `firecash-signer` as a compatibility wrapper around it.
- Introduce `ChainSource`, `WalletStore`, `Prover`, `Signer`, and clock/randomness abstractions.
- Add mock sources/stores and cross-target conformance tests.

### Phase 2: extract the engine

- Move sync, reorg recovery, note selection, dynamic fees, preparation, finalization, pending
  state and history from walletd into `zkas-wallet-engine`.
- Implement atomic SQLite storage and migration from existing wallet data.
- Refactor walletd, CLI and Tauri to use only the public engine API.
- Run the existing end-to-end coinbase -> scan -> spend -> consensus -> recipient test through
  the SDK facade.

### Phase 3: publish the practical SDK

- Publish Rust crates and `@zkas/sdk` with key/address/signing, prepared-transaction validation,
  hosted-hybrid REST transport, watch-only accounts, balance/history and send lifecycle.
- Replace the web wallet's hand-written API/signer coordination with the package.
- Version walletd endpoints and retain one compatibility release for the existing UI.

This phase is useful immediately even though proving and scanning still run at the service.

### Phase 4: light-client sync

- Specify compact shielded blocks and cursor/checkpoint semantics.
- Replace linear/full-state witness handling with a checkpointed commitment-tree implementation
  such as `bridgetree` or an equivalent proven design.
- Add authenticated reorg recovery, resumable ranges, batching and IndexedDB storage.
- Benchmark initial sync, steady-state sync, memory and recovery on real wallet histories.

### Phase 5: local browser proving and broader bindings

- Run scanning and proving in Web Workers with bounded memory and cancellation/progress events.
- Package prover parameters with integrity/version controls and caching.
- Ship Swift/Kotlin bindings, then hardware/remote signer support and Python if demanded.

## Non-negotiable security properties

- Seeds and spending keys are zeroized where possible and never logged, serialized to API errors,
  or sent to walletd.
- Each signing request is pinned to a network and reconstructed locally.
- Signers enforce explicit user intent, maximum fee, exact external outputs and valid change.
- Remote block, fee and transaction-status responses are treated as adversarial.
- Reorg rollback restores the commitment tree, witnesses, notes, nullifiers, balances and history
  to one consistent checkpoint.
- Persistent secrets use OS keystores on native platforms; browser storage is not described as a
  hardware security boundary.
- API and persistence formats are versioned before third parties depend on them.
- Cryptographic dependencies stay pinned and changes require vectors, differential tests and
  review.

## Required test matrix

- Golden vectors for keys, addresses, bundle encoding, note decryption, sighash and signatures.
- Rust/WASM/native differential tests using identical prepared transactions.
- End-to-end create/import/watch, sync, send, mine, receive and rescan tests.
- Reorg tests at every interruption point, including crash between database writes.
- Malicious preparer tests: changed recipient, amount, fee, change, network, anchor and expiry.
- Property/fuzz tests for wire parsers, migration readers and RPC conversion.
- Browser memory and performance tests for long histories and many notes.
- Backward-compatibility tests for every published schema and REST version.

## External designs used as references

- Kaspa's Rust/WASM wallet SDK demonstrates one Rust implementation exposed to browser and
  Node.js, with IndexedDB for browser transaction records.
- `librustzcash` provides the strongest package-boundary model: protocol primitives, keys,
  prepared transaction interchange, client backend, and storage implementation are separate.
- Zcash light-client FFI and Zingo show Rust wallet engines reused by native/mobile front ends.
- Independent Zcash browser projects validate Rust-to-WASM reuse, while their reports identify
  compact-block retrieval, trial decryption, commitment-tree witnesses, proving memory, and
  browser storage as the difficult work.
- PSBT/PCZT-style role separation informs the prepared-transaction format; ZKas must define its
  own format because its shielded v2 transaction and signing policy are different.

These projects are architectural references, not code to copy blindly. Consensus serialization,
network domains, fees, and shielded transaction rules must always come from this repository.

## Definition of SDK v1

SDK v1 is complete when an external application can, without importing walletd internals:

1. create/import a spending wallet or FVK-only wallet;
2. synchronize with deterministic progress and reorg recovery;
3. obtain authoritative balance and history from the engine;
4. create a payment proposal with an explicit fee;
5. verify and sign locally without trusting a server-provided sighash;
6. broadcast and track the transaction through confirmation or rollback;
7. run the same conformance vectors in Rust and TypeScript/WASM;
8. migrate an existing production wallet without rescanning or losing history.
