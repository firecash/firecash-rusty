# ZKas — Live Operations Runbook

How the live ZKas network is deployed, how to keep it up, and how to relaunch
it. Read this before touching the running node/miner/pool. Every incident in here
has already happened at least once — the point of this file is that it never
happens again.

## Topology

Two servers, each running its own full `kaspad` (own datadir), peered over P2P.

| | VPS1 `185.147.157.125` | VPS2 `160.187.211.153` |
|---|---|---|
| Role | node + miner + mining pool + nginx | node + walletd + explorer API |
| Process mgr | **systemd** | `setsid nohup` (from `/root/zkas/` → symlink to /root/zkas) |
| Node datadir | `/root/work/fc-mainnet` | `/root/zkas/fc-node` |
| Binaries | `/root/work/kaspad-run`, `zkas-miner-run`; pool `zkas-pool/bin/stratum-bridge` | `/root/zkas/bin/{kaspad,zkas-walletd,zkas-api}` |
| Ports | node gRPC 16110, P2P 16111, pool stratum (see bridge yaml) | node gRPC 16110, walletd 8501, api 8500 |

> **Port migration (reset):** these are the **current live** ports. The reset binary
> defaults ZKas to its own port block — gRPC **16810**, P2P **16811**, wRPC borsh **17810**,
> json **18810** — so a ZKas node and the merged-mining Kaspa parent stop clashing. At the
> coordinated reset, migrate every explicit `:16110`/`:16111`/`:17110` here and in the pool
> `*-bridge.yaml`, nginx upstreams, and the VPS2 tunnel. Until then everything stays on 161xx.

VPS1 nginx reaches VPS2's walletd/api over an `autossh -L 8500 -L 8501 root@VPS2`
tunnel. wallet.zkas.info → walletd (8501); explorer → api (8500).

Chain facts: kHeavyHash PoW (byte-identical to Kaspa), ~1 BPS, 60 ZKAS/block,
addresses `zkas:...`, network id `zkas-mainnet`. AuxPoW merged-mining
activation lives in `params.rs` (`merged_mining_activation`).

## Golden rules (the hard-won ones)

1. **Run long-lived processes under a process manager that survives your shell.**
   On VPS1 that is **systemd** — NOT tmux. In some automated shells a
   tmux-launched process is reaped ~12 s after the launching command returns
   (the node logs a clean `SIGTERM … Kaspad has stopped` ~12 s in, every time).
   systemd units live in their own cgroup and are immune. On VPS2, `setsid nohup
   … </dev/null >log 2>&1 &` over ssh is fine (the remote host isn't doing the
   reaping).

2. **VPS1 must have swap.** The box is ~7.8 GB RAM. A `cargo build --release`
   LTO link step spikes several GB and the OOM killer takes the node/miner/bridge
   (dmesg: `Out of memory: Killed process … stratum-bridge`; the node log just
   stops mid-block with no shutdown line). Keep an 8 GB swapfile on:
   ```
   fallocate -l 8G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
   # persist: echo '/swapfile none swap sw 0 0' >> /etc/fstab
   ```

3. **Run the live node/miner from COPIES of the binaries**, e.g.
   `cp target/release/kaspad /root/work/kaspad-run`. Otherwise an in-progress
   `cargo build` cannot relink `target/release/kaspad` while it's running
   (ETXTBSY), and you can't upgrade without stopping the chain.

4. **`pkill -f` / `pgrep -f` self-match footgun.** `pkill -f 'bin/kaspad'` run
   over ssh matches the *command string itself* (which contains that path) and
   kills its own shell → ssh exits 255 and the real target may survive. `pgrep -c
   -f X` also counts the wrapping `sh -c`. **Kill by explicit PID**, and read
   `pgrep -c` as N+1.

5. **A "fresh chain" means wiping BOTH datadirs before EITHER node mines.**
   Genesis is unchanged, so a fresh (empty) node will happily IBD the *old* chain
   from whichever peer still has it. Wipe VPS1 and VPS2, start VPS1 (the miner),
   then start VPS2 to follow. See "Relaunch" below.

6. **A consensus change requires a fresh relaunch — never hot-swap it onto the
   live chain.** The difficulty-floor `kaspad`, for example, changes difficulty
   validation; on a chain already past the easy-difficulty window it can reject
   the chain's own history and fork/halt. Deploy consensus changes only via a
   full wipe+relaunch of both nodes.

## Normal operation (VPS1)

```
systemctl status  zkas-node zkas-miner zkas-pool
systemctl restart zkas-node              # node
systemctl restart zkas-miner         # solo/native miner (threads set in unit)
systemctl restart zkas-pool              # stratum bridge
journalctl -u zkas-node -f               # follow logs
```

Unit files: `/etc/systemd/system/zkas-{node,miner,pool,kaspa-node,grpc-public,pool-redactor,tunnel}.service`; the pool uses a
drop-in `/etc/systemd/system/zkas-pool.service.d/override.conf` pointing at
the **release** `bin/stratum-bridge` (the debug build used ~3 GB RSS and caused
OOMs; release is ~60 MB). `zkas-pool.service` env: `BRIDGE_ALLOW_UNSYNCED=1`
(a peerless solo node reports `is_synced=false` forever even while mining with
`--enable-unsynced-mining`).

## Recover "node is down"

1. Check RAM/OOM: `free -h` (is swap on?), `dmesg | grep -i oom`.
2. VPS1: `systemctl start zkas-node zkas-miner zkas-pool`.
3. VPS2 (from `/root/zkas`):
   ```
   setsid nohup bin/kaspad --appdir=/root/zkas/fc-node --utxoindex \
     --rpclisten=127.0.0.1:16110 --addpeer=185.147.157.125:16111 \
     </dev/null >node.log 2>&1 &
   setsid nohup bin/zkas-walletd --network mainnet --rpc-server 127.0.0.1:16110 \
     --listen 127.0.0.1:8501 --wallet-dir /root/zkas/wallets \
     --allow-origin https://wallet.zkas.info </dev/null >walletd.log 2>&1 &
   setsid nohup bin/zkas-api -s 127.0.0.1:16110 -l 127.0.0.1:8500 \
     </dev/null >api.log 2>&1 &
   ```
4. Verify: `ss -tlnp | grep -E ':16110|:8500|:8501'`, tail the logs.

## Relaunch a fresh chain (e.g. to ship a consensus change)

Order matters — both empty before either mines.

```
# 0. Build + copy the new binary to run-paths on BOTH boxes first.

# 1. VPS1: stop everything, wipe.
systemctl stop zkas-miner zkas-node zkas-pool
rm -rf /root/work/fc-mainnet

# 2. VPS2: stop everything (kill by PID), wipe.
#    kill <kaspad_pid> <walletd_pid> <api_pid>   # NOT pkill -f (self-match!)
rm -rf /root/zkas/fc-node

# 3. VPS1 first (has the miner): start node, then miner, then pool.
systemctl start zkas-node && sleep 15 && systemctl start zkas-miner zkas-pool

# 4. VPS2: start node (follows VPS1 via relay), then walletd + api (see Recover).

# 5. CRITICAL: clear stale wallet scan checkpoints on VPS2, or walletd HANGS.
#    Genesis is unchanged across relaunches, so the .scan genesis-guard passes and
#    walletd loads old-chain scan state (50 MB+ files), all wallets thrash
#    re-scanning, the CPU pegs and the HTTP runtime starves (even /health times
#    out). Move them aside BEFORE (re)starting walletd:
mkdir -p /root/zkas/wallets_scan_bak
mv /root/zkas/wallets/*.scan /root/zkas/wallets_scan_bak/   # keep the .json seeds
```

Verify the wallet after: `curl https://wallet.zkas.info/daemon/api/status` must
return JSON (not the SPA `<!doctype html>`). The SPA calls `origin + /daemon` — nginx
`location /daemon/` proxies to walletd on `127.0.0.1:8501` via the autossh tunnel. A
bare `/api/status` correctly returns the SPA (catch-all); always test under `/daemon`.

Verify the fresh chain: VPS1 log shows `Accepted N blocks … via submit block`;
VPS2 log shows `Accepted block … via relay` (following, not IBD of an old chain).

## Wallet daemon security (VPS2)

`zkas-walletd` is hardened: CORS is locked to `--allow-origin`
(default same-origin only), `X-Wallet-Token` is required (`--allow-default-token`
restores the old single-user fallback), and seeds encrypt at rest when
`--wallet-secret` / `ZKAS_WALLET_SECRET` is set. Always launch it with
`--allow-origin https://wallet.zkas.info` so the web wallet keeps working.

## Repos

- Node/consensus/wallet: `github.com/firecash/zkas-rusty`
- Mining pool: `github.com/firecash/zkas-pool` (see its `help.txt` for pool
  operators + AuxPoW merged-mining details)
