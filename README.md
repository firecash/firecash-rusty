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

## Requirements

- **Prebuilt binaries (GitHub Release):** Linux x86-64. The default `.tar.gz` is built on
  Ubuntu 24.04 and needs **glibc ≥ 2.38**. On older systems (Ubuntu 22.04 = glibc 2.35,
  Debian 12, CentOS/Rocky, …) it errors with `GLIBC_2.38 not found` — use the **static
  (musl) build** attached to the release (runs on any Linux, no glibc needed), or build
  from source.
- **Build from source (any recent Linux):** the Rust toolchain (rustup) plus these system
  packages — see below.

## Build from source

Tested on **Ubuntu 24.04 (x86-64)**.

**1. System dependencies**
```bash
sudo apt-get update
sudo apt-get install -y curl git build-essential pkg-config libssl-dev protobuf-compiler clang
```

**2. Rust toolchain** (rustup; the repo pins a toolchain via `rust-toolchain.toml`)
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

**3. Clone & compile** (release profile — optimized binaries land in `target/release/`)
```bash
git clone https://github.com/firecash/firecash-rusty.git
cd firecash-rusty
# all node-side binaries at once:
cargo build --release -p kaspad -p miner -p firecash-walletd -p firecash-api
# or the whole workspace:
cargo build --release
```
First build downloads and compiles all dependencies (RocksDB, Halo 2, etc.) and takes
~10–20 min; later builds are incremental. Run the test suite with `cargo test --release`.

## Run a node & join the network

Grab the binaries from the latest [Release](https://github.com/firecash/firecash-rusty/releases)
(or build from source, below), then run a node that syncs from the FireCash seed nodes:

```bash
./kaspad --appdir=./fc-node --rpclisten=127.0.0.1:16110 --utxoindex \
  --connect=185.147.157.125:16111 --connect=160.187.211.153:16111
```
Your node does an initial block download from the network and then follows the tip. It only
needs outbound access to the seed nodes' **p2p port 16111**; its own RPC (16110) stays local.

## Mine

- **Pool (recommended — works with ASICs):** point your miner or KS-series ASIC at the
  FireCash stratum pool at **mining-pool.firecash.info**. No node required.
- **Solo:** with your synced node running, mine to your `firecash:` shielded address:
  ```bash
  ./firecash-miner -s 127.0.0.1:16110 -a firecash:<your-address> -t 4
  ```

## Wallet

- **Web wallet:** https://wallet.firecash.info
- **Self-hosted:**
  ```bash
  ./firecash-walletd --network mainnet --rpc-server 127.0.0.1:16110 --wallet-dir ./fc-wallets --listen 127.0.0.1:8501
  ```

## Explorer

https://explorer.firecash.info

## Configuration

- `merged_mining_activation` (DAA score at which AuxPoW acceptance turns on) and all
  tokenomics constants live in `consensus/core/src/config/params.rs`.
- Genesis, network prefixes (`firecash:` / `firecashtest:`), and BPS are compiled in;
  changing consensus parameters requires a rebuild and a fresh chain.

## License

Inherits rusty-kaspa's licensing (MIT / Apache-2.0). See `LICENSE-MIT` / `LICENSE-APACHE`.
