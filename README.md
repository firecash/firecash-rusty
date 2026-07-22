# ZKas — `firecash-rusty` (rebranded from ZKas 2026-07-14)

> **⚠️ TESTNET — this is a live test network. Coins have no value, the chain may be
> reset without notice, and consensus parameters can still change. Do not treat ZKAS
> as money.**

**Private-by-default money at Kaspa speed.** ZKas is a fork of
[rusty-kaspa](https://github.com/kaspanet/rusty-kaspa) that makes every balance and
transfer **shielded by default** (Zcash **Orchard** notes, Halo 2 proofs — no trusted
setup), while keeping Kaspa's sub-second BlockDAG confirmation and **kHeavyHash**
proof-of-work.

This repo is the **core node and tooling**: the `kaspad` node, the standalone miner,
the wallet daemon, and the explorer API.

## What's different from Kaspa

| | ZKas | Kaspa |
|---|---|---|
| Privacy | **Shielded by default** (Orchard) | Transparent |
| Consensus | GHOSTDAG BlockDAG, 10 blocks/s | same |
| PoW | **kHeavyHash** (byte-identical to Kaspa) | kHeavyHash |
| Merged mining | **Yes** — AuxPoW dual-acceptance with Kaspa | — |
| Emission | 6 ZKAS start, 3-month halving, two-step perpetual tail | fixed cap |

- **Shielded state:** coinbase rewards and transfers enter a mandatory Orchard pool;
  the only public quantity is the fee a spender exposes to the miner. A shielded
  state root (anchor + nullifier accumulator + turnstile) is committed in the coinbase.
- **Merged mining (Option-2 dual acceptance):** a block is valid if **either** its
  native kHeavyHash clears the target **or** it carries an `AuxPoW` proof — a parent
  kHeavyHash block (e.g. a Kaspa block) whose coinbase commits to the ZKas block
  hash. Native mining stays the backbone; merged mining adds security at zero marginal
  cost to Kaspa miners. See `consensus/core/src/auxpow.rs` and `consensus/pow/src/auxpow.rs`.
- **Tokenomics:** 6 ZKAS initial reward, halving every 3 months, settling on a two-step
  perpetual tail (0.6 ZKAS/block → 0.3 ZKAS/block at month 24). No fixed supply cap.

## Binaries in this repo

| Crate | Binary | Role |
|---|---|---|
| `kaspad` | `kaspad` | the node (gRPC :16110, p2p :16111) |
| `miner` | `zkas-miner` | standalone CPU miner (native + `--merged` AuxPoW) |
| `zkas-walletd` | `zkas-walletd` | shielded wallet daemon (token-scoped, local) |
| `zkas-api` | `zkas-api` | explorer REST backend (gRPC → REST) |

Companion repos: **firecash-pool** (stratum bridge — ASIC mining), **firecash-explorer**
(SPA), **firecash-wallet** (web wallet SPA), **firecash-website**.

## Requirements

- **Prebuilt binaries (GitHub Release):** Linux x86-64. Built on Ubuntu 24.04, so they need
  **glibc ≥ 2.38**. They run on Ubuntu 24.04+ and other current distros. On older systems
  (Ubuntu 22.04 = glibc 2.35, Debian 12, …) they error with `GLIBC_2.38 not found` — on those,
  build from source (below), which works on any recent Linux.
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
cargo build --release -p kaspad -p miner -p zkas-walletd -p zkas-api
# or the whole workspace:
cargo build --release
```
First build downloads and compiles all dependencies (RocksDB, Halo 2, etc.) and takes
~10–20 min; later builds are incremental. Run the test suite with `cargo test --release`.

## Run a node & join the network

Grab the binaries from the latest [Release](https://github.com/firecash/firecash-rusty/releases)
(or build from source, below), then run a node that syncs from the ZKas seed nodes:

```bash
./kaspad --appdir=./fc-node --rpclisten=127.0.0.1:16110 --utxoindex \
  --connect=185.147.157.125:16111 --connect=160.187.211.153:16111
```
Your node does an initial block download from the network and then follows the tip. It only
needs outbound access to the seed nodes' **p2p port 16111**; its own RPC (16110) stays local.

## Mine

- **Pool (recommended — works with ASICs):** point your miner or KS-series ASIC at the
  ZKas stratum pool at **mining-pool.zkas.info**. No node required.
- **Solo:** with your synced node running, mine to your `firecash:` shielded address:
  ```bash
  ./zkas-miner -s 127.0.0.1:16110 -a firecash:<your-address> -t 4
  ```

## Wallet

Everything is on the **shielded (Orchard) pool** — balances and amounts are private.
`1 ZKAS = 100,000,000 sompi`. There are three ways to use a wallet:

- **Web & mobile wallet (easiest):** https://wallet.zkas.info — no install; also
  packaged as a native iOS/Android app (Capacitor). See
  [firecash-wallet](https://github.com/firecash/firecash-wallet) / its `MOBILE.md`.

  > **Custody:** in the default hosted mode the daemon holds the seed and *can* spend.
  > Orchard splits a spend into **prove** (viewing key only) and **sign** (spend key only),
  > so the seed never has to be on the server — the non-custodial roadmap moves signing to
  > the device (see `docs/NON_CUSTODIAL_WALLET.md`). Self-hosting the daemon is already
  > fully non-custodial.

### `shielded-pay` — CLI wallet

Quick offline/CLI operations against a running node. (Seeds are `[byte; 32]` for the
reference tool; use the daemon or web wallet for real random-seed wallets.)

```bash
# Obtain your shielded address (this is what you give a sender or the miner's -a)
./shielded-pay address --seed-byte 1 --network mainnet
# -> firecash:pyfjy228l6gukj2vwztyq6q88eeyggjhvcuzf2jx8u4lvla42d6x0y3dsgp0w...

# Check spendable balance + owned notes (scans the chain via the node RPC)
./shielded-pay balance -s 127.0.0.1:16110 --seed-byte 1

# Send a private payment (amount/fee in sompi; change returns to you)
./shielded-pay send -s 127.0.0.1:16110 --owner-seed-byte 1 \
  --to firecash:<recipient-address> --amount 500000000 --fee 3000000

# Prove you control an address without spending (offline; discloses viewing key)
./shielded-pay sign   --seed-byte 1 --network mainnet --message "gm"
./shielded-pay verify --address firecash:<addr> --message "gm" --signature <hex>
```

### `zkas-walletd` — wallet daemon (REST, powers the web wallet)

Run it locally for a non-custodial wallet with a REST API on `:8501`:

```bash
./zkas-walletd --network mainnet --rpc-server 127.0.0.1:16110 \
  --wallet-dir ./fc-wallets --listen 127.0.0.1:8501 \
  --allow-origin http://localhost:5173   # your web-wallet origin (omit for same-origin)
```

Every request carries an `X-Wallet-Token` header selecting your wallet (mint any
random hex string once and reuse it):

```bash
TOK=$(head -c16 /dev/urandom | xxd -p)     # your wallet token — keep it

# Create a new wallet (returns the seed once — write it down)
curl -X POST -H "X-Wallet-Token: $TOK" http://127.0.0.1:8501/api/wallet/create

# Obtain your shielded receive address
curl -H "X-Wallet-Token: $TOK" http://127.0.0.1:8501/api/wallet/address

# Balance + sync status
curl -H "X-Wallet-Token: $TOK" http://127.0.0.1:8501/api/wallet/balance

# Send (amount_fc or amount_sompi; fee optional, default 3000000 sompi)
curl -X POST -H "X-Wallet-Token: $TOK" -H "Content-Type: application/json" \
  -d '{"to":"firecash:<recipient>","amount_fc":5.0}' \
  http://127.0.0.1:8501/api/wallet/send
```

Flags: `--wallet-secret <s>` (or `FIRECASH_WALLET_SECRET`) encrypts seed files at
rest; `--allow-default-token` permits tokenless requests for single-user localhost.

## Explorer

https://explorer.zkas.info

## Configuration

- `merged_mining_activation` (DAA score at which AuxPoW acceptance turns on) and all
  tokenomics constants live in `consensus/core/src/config/params.rs`.
- Genesis, network prefixes (`firecash:` / `firecashtest:`), and BPS are compiled in;
  changing consensus parameters requires a rebuild and a fresh chain.

## License

Inherits rusty-kaspa's ISC license. See [`LICENSE`](./LICENSE).
