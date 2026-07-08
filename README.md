# FireCash — `firecash-rusty`

**Private-by-default money at Kaspa speed.** FireCash is a fork of
[rusty-kaspa](https://github.com/kaspanet/rusty-kaspa) that makes every balance and
transfer **shielded by default** (Zcash **Orchard** notes, Halo 2 proofs — no trusted
setup), while keeping Kaspa's sub-second BlockDAG confirmation and **kHeavyHash**
proof-of-work.

This repo is the **core node and tooling**: the `kaspad` node, the standalone miner,
the wallet daemon, and the explorer API.

## What's different from Kaspa

| | FireCash | Kaspa |
|---|---|---|
| Privacy | **Shielded by default** (Orchard) | Transparent |
| Consensus | GHOSTDAG BlockDAG, 10 blocks/s | same |
| PoW | **kHeavyHash** (byte-identical to Kaspa) | kHeavyHash |
| Merged mining | **Yes** — AuxPoW dual-acceptance with Kaspa | — |
| Emission | 6 FC start, 3-month halving, two-step perpetual tail | fixed cap |

- **Shielded state:** coinbase rewards and transfers enter a mandatory Orchard pool;
  the only public quantity is the fee a spender exposes to the miner. A shielded
  state root (anchor + nullifier accumulator + turnstile) is committed in the coinbase.
- **Merged mining (Option-2 dual acceptance):** a block is valid if **either** its
  native kHeavyHash clears the target **or** it carries an `AuxPoW` proof — a parent
  kHeavyHash block (e.g. a Kaspa block) whose coinbase commits to the FireCash block
  hash. Native mining stays the backbone; merged mining adds security at zero marginal
  cost to Kaspa miners. See `consensus/core/src/auxpow.rs` and `consensus/pow/src/auxpow.rs`.
- **Tokenomics:** 6 FC initial reward, halving every 3 months, settling on a two-step
  perpetual tail (0.6 FC/block → 0.3 FC/block at month 24). No fixed supply cap.

## Binaries in this repo

| Crate | Binary | Role |
|---|---|---|
| `kaspad` | `kaspad` | the node (gRPC :16110, p2p :16111) |
| `miner` | `firecash-miner` | standalone CPU miner (native + `--merged` AuxPoW) |
| `firecash-walletd` | `firecash-walletd` | shielded wallet daemon (token-scoped, local) |
| `firecash-api` | `firecash-api` | explorer REST backend (gRPC → REST) |

Companion repos: **firecash-pool** (stratum bridge — ASIC mining), **firecash-explorer**
(SPA), **firecash-wallet** (web wallet SPA), **firecash-website**.

## Build

```
# Ubuntu 24.04: rustup + build deps (see the toolchain files)
cargo build --release -p kaspad -p miner -p firecash-walletd -p firecash-api
```

## Run (fresh chain)

```
# node
./target/release/kaspad --appdir=./fc-mainnet --rpclisten=127.0.0.1:16110 --utxoindex --enable-unsynced-mining
# miner (mine to a firecash: shielded address)
./target/release/firecash-miner -s 127.0.0.1:16110 -a firecash:<addr> -t 4
#   merged-mining test: add --merged
# wallet daemon
./target/release/firecash-walletd --network mainnet --rpc-server 127.0.0.1:16110 --wallet-dir ./fc-wallets --listen 127.0.0.1:8501
# explorer API
./target/release/firecash-api --rpc-server 127.0.0.1:16110 --listen 127.0.0.1:8500
```

The node gRPC and all daemons bind **127.0.0.1 only** — front them with nginx + TLS for
anything public. Prebuilt binaries are attached to the GitHub Release.

## Status & known flaws (pre-launch)

- `merged_mining_activation` is currently `ForkActivation::always()` — a **test** value.
  Set it to `12_096_000` (day 14) in `consensus/core/src/config/params.rs` for a real launch.
- Pool merged mining uses a **synthetic parent** (no real Kaspa node yet) — proves aux
  acceptance, not the Kaspa "free-ride" dual-reward.
- No header-commitment pruning / IBD fast-sync hardening yet; no external audit.
- Explorer keeps only a recent tx window (no full `--txindex`).

## License

Inherits rusty-kaspa's licensing (MIT / Apache-2.0). See `LICENSE-MIT` / `LICENSE-APACHE`.
