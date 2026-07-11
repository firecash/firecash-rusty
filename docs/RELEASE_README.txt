===============================================================================
 FireCash — release binaries
===============================================================================

This archive contains statically-linked FireCash binaries. FireCash is a
shielded-by-default (Orchard / Halo 2) fork of rusty-kaspa; kHeavyHash PoW,
1 block/second, ticker $firecash. 1 $firecash = 100,000,000 sompi.

-------------------------------------------------------------------------------
 What's in here
-------------------------------------------------------------------------------
  kaspad           FireCash full node. Run with --utxoindex.
  firecash-miner   Built-in CPU miner (kHeavyHash). Enough to bootstrap /
                   solo-mine; for real hashrate use an ASIC or GPU (see below).
  shielded-pay     CLI shielded wallet: derive a firecash: address, check
                   balance, send private payments, and sign/verify address
                   ownership. Offline-capable for address + sign/verify.
  firecash-walletd Local wallet daemon (REST) that powers the web/mobile wallet.
  stratum-bridge   Stratum bridge for pointing ASICs/pools at a FireCash node.

-------------------------------------------------------------------------------
 GPU / ASIC mining
-------------------------------------------------------------------------------
There is NO bundled GPU miner. FireCash's proof-of-work is kHeavyHash,
BYTE-IDENTICAL to Kaspa, so any existing Kaspa kHeavyHash miner works unchanged:

  - GPU:  bzminer, lolMiner, Rigel, etc. — point them at a FireCash node's
          stratum (or the pool at mining-pool.firecash.info) with a
          firecash: address as the username.
  - ASIC: IceRiver / Bitmain / Goldshell kHeavyHash units work as-is.

The bundled firecash-miner is CPU-only and intended for bootstrapping or solo
low-difficulty mining, not competitive hashrate.

-------------------------------------------------------------------------------
 Wallets
-------------------------------------------------------------------------------
  - CLI:    shielded-pay  (in this archive)
  - Web:    https://wallet.firecash.info   (also has on-device "Local" tools)
  - Paper:  https://firecash.github.io/firecash-paper-wallet/  — an OFFLINE,
            single-file cold-storage wallet. Save it, go offline, generate.
            Source: github.com/firecash/firecash-paper-wallet

Quick start:
  ./kaspad --utxoindex
  ./shielded-pay address --seed-byte 1 --network mainnet
  ./firecash-miner -s 127.0.0.1:16110 -a firecash:<your-address> -t 4
===============================================================================
