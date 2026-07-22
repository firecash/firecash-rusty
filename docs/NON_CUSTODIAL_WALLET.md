# Non-custodial ZKas web wallet — design

**Goal:** a web wallet at `wallet.zkas.info` where **the server cannot spend user
coins.** Today's hosted `zkas-walletd` is *custodial* — it generates and stores each
user's seed (plaintext), so a server compromise drains everyone. This document is the
plan to remove that.

## The enabling fact (why this is even possible on a shielded chain)

Orchard splits a spend into two independent steps (see `shielded-core/src/wallet.rs`):

1. **`create_proof(pk, …)`** — the heavy Halo 2 proof. Built with **only the full
   viewing key (FVK)** + notes + witnesses + the public proving key. **No spend
   authority.** (`Builder::add_spend` takes `keys.fvk`, not the seed.)
2. **`apply_signatures(…, &[ask])`** — the RedPallas spend-authorization signature.
   This is the **only** step that needs `ask = SpendAuthorizingKey::from(sk)` — the real
   secret derived from the seed.

`ask` cannot be derived from the FVK (one-way). Therefore **a party holding only the FVK
can build a fully-proven bundle that is worthless until the seed-holder signs it.** That
is the whole basis for non-custody: keep `ask` on the client, put everything else
wherever is convenient.

## Phase 1 — Hybrid "client signs, server proves" (ship first)

Non-custodial against theft; lightweight client (no Halo 2 in the browser).

```
Browser (holds seed)                     Server (zkas-walletd, key-less)
--------------------                     -----------------------------------
generate seed -> sk, FVK, ask
send FVK (once) ------------------------> scan chain with FVK, track notes+witnesses
"send X to addr" -----------------------> build spend: add_spend(FVK) + create_proof
                                          -> proven-but-UNSIGNED bundle + sighash
apply_signatures(ask, sighash) <--------- return proven bundle + sighash + per-spend alpha
submit signed bundle -------------------> relay to node
```

- **The server never holds `sk`/`ask` → it cannot spend.** A server hack leaks viewing
  keys, not coins.
- Client work is tiny: seed/key derivation + RedPallas signing over the sighash. No
  circuit, no proving-key download. Compiles from `shielded-core` **without** the
  `circuit` feature.
- The code already has the split point: `create_proof` and `apply_signatures` are
  separate calls, and there is a build path that applies an **empty** signature set
  (`apply_signatures(rng, msg, &[])`) — i.e. a proven, unsigned bundle.

**Honest tradeoff:** the server sees the FVK, so it can *watch* balances/history — a
**privacy** loss, not a **custody** loss. Acceptable interim; closed by Phase 2.

**Work items (Phase 1):**
1. `walletd`: replace seed storage with per-session FVK. New endpoints:
   `POST /api/wallet/prepare-send` → returns `{ unsigned_bundle, sighash, alphas }`;
   `POST /api/wallet/submit-signed` → relays the client-signed bundle.
   Delete all seed persistence.
2. Browser signer (WASM, `shielded-core` light path): derive keys, reconstruct the
   proven bundle, `apply_signatures(ask, …)`, serialize.
3. Web SPA: generate/store the seed **in-browser only** (encrypted with a user
   passphrase in IndexedDB), never POST it.

## Phase 2 — Full in-browser WASM wallet (gold standard)

Compile `shielded-core` **with** the `circuit` feature to `wasm32`: keygen + scan +
witness + **prove** + sign, all in the browser. Seed never leaves the device and the
server sees nothing (fully private + non-custodial). The server degrades to a dumb,
untrusted light-server: serve compact blocks / tree frontier / submit-tx.

- Feasible — Zcash's **WebZjs** does Orchard proving in-browser today.
- Costs: large WASM bundle (Halo 2 prover), proving is slow in-browser (seconds),
  proving params (~tens of MB) loaded once and cached; needs threads/SharedArrayBuffer.
- Prereq that also helps everything else: the O(N)-per-note witness rebuild must become
  O(log N) via a **`bridgetree`** (marked positions + checkpoint) — otherwise witnessing
  in WASM is worse than on the server.

## Recommendation

Ship **Phase 1** to kill the custody risk now (small client, server can't steal), then
invest in **Phase 2** for full privacy. Both require the bridgetree witness rework
(tracked separately) to be genuinely fast.

## Server-side supporting changes (independent, also needed)

- **Recent frontier for new wallets:** the only reorg-safe fast-sync checkpoint today is
  the finality point (`FINALITY_DURATION = 12 h` ⇒ ~43,200 blocks at 1 BPS), so a
  freshly-created wallet still builds the tree over ~12 h of history. A new wallet has no
  funds, so it can safely start at the **sink/tip** frontier and re-sync on a reorg. Add
  a node RPC that returns the tree frontier at the sink (the internal
  `async_get_shielded_tree_frontier(block_hash)` already exists; expose it for the sink),
  and have `walletd` use it for `create` so new wallets scan ~nothing.
