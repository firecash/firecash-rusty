# SDK Research Notes

This research informed the architecture in `ARCHITECTURE.md`. External projects
are design references, not sources of ZKas consensus rules.

## Kaspa

- Rusty Kaspa exposes one Rust wallet implementation to native Rust, Node.js and
  browsers through WASM. Its integrated wallet coordinates accounts, storage,
  RPC, transaction generation, events, and pending transactions.
- Browser storage is split between local storage and IndexedDB.
- The lower-level Wallet SDK separates event processing/account contexts from
  the higher-level integrated Wallet API.
- Community Kaspa wallets confirm demand for simpler TypeScript-facing wallet
  APIs, but ZKas cannot reuse transparent UTXO transaction construction for its
  Orchard state and witnesses.

References:

- <https://github.com/kaspanet/rusty-kaspa>
- <https://kaspa.aspectron.org/docs/>
- <https://kaspa.aspectron.org/wallets/wallet-sdk/index.html>
- <https://github.com/ScopeLift/kaspa-wallet>

## Zcash and Orchard

- `librustzcash` provides the strongest package-boundary model: protocol types,
  keys, PCZT, client backend, and SQLite storage are distinct packages.
- `zcash_client_backend` separates chain data, scanning, fees, proposals, and
  transaction construction. Parsing chain data is not consensus validation;
  final consensus acceptance remains the node's responsibility.
- Zcash light-client FFI and Zingo demonstrate a Rust wallet engine reused by
  Swift/mobile front ends.
- Orchard's commitment tree requires durable checkpoints and marked-note
  witnesses; this is directly relevant to ZKas sync and reorg reliability.

References:

- <https://github.com/zcash/librustzcash>
- <https://github.com/Electric-Coin-Company/zcash-light-client-ffi>
- <https://github.com/zingolabs/zingolib>
- <https://github.com/zingolabs/zingo-mobile>
- <https://zcash.github.io/orchard/design/commitment-tree.html>

## Independent and community implementations

- LeakIX's independent browser wallet shares a Rust core between WASM and CLI,
  reinforcing the single-implementation approach. It remains experimental and
  is not treated as a security authority.
- ChainSafe's Zcash browser feasibility work identified the important browser
  constraints: compact-block transport, deserialization/trial decryption,
  witness maintenance, proving, memory, and gRPC incompatibility. Their results
  also support Web Workers and browser-specific transport/data layouts.
- Zingo's community ecosystem reinforces keeping application UI separate from
  the Rust sync and transaction engine.

References:

- <https://github.com/LeakIX/zcash-web-wallet>
- <https://forum.zcashcommunity.com/t/zcash-sdk-implementation-js-ts-proposal/46158/1>
- <https://github.com/zingolabs/zingolib>

## Transaction role separation

Bitcoin PSBT and Zcash PCZT separate creation, updating/proving, signing,
finalization, and extraction. ZKas needs its own versioned prepared-payment
format because its transaction-v2 envelope, network domain, disclosures, and
anti-blind signing rules are chain-specific.

References:

- <https://github.com/bitcoin/bitcoin/blob/master/doc/psbt.md>
- <https://docs.rs/pczt/latest/pczt/>

