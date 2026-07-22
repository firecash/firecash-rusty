# ZKas — Consensus Changes & Pre-Mainnet Reset Plan

_Last updated: 2026-07-22_
_Working branch: `ibd-shielded-import` @ `db41527` (origin/firecash-rusty)_
_Live node currently runs the rollback build `fca5229` (VPS1) / `fb64afe` (VPS2) — **NOT** the reset bundle._

---

## Strategy

Every consensus-breaking change is bundled into **one new-genesis reset** so the chain
breaks exactly once. The reset produces a fresh genesis + a new binary; all nodes,
wallets, and the pool/bridge upgrade together at relaunch.

A change belongs in the bundle **only if it is consensus-breaking** (changes block/tx
validity, the state-transition, or a committed root). Anything that produces the same
observable state and roots — e.g. how DB writes are batched — is a normal node patch and
must **not** be gated on the reset. This document is the authority on what is in vs. out.

**Hard rule learned the hard way (2026-07-20 freeze):** never "fix" a shielded/wallet
symptom by editing consensus without an activation gate. An ungated recompute that
diverges from a coinbase-committed root freezes the whole chain. See
`send-receive-divergent-anchor` memory / `/root/work/badfix.txt`.

---

## IN the reset bundle

### Already committed + tested (prior sessions)

| # | Change | Consensus effect | Where |
|---|--------|------------------|-------|
| F-01 | Dropped-spend fee-inflation fix | A shielded spend dropped for a non-final anchor / nullifier conflict no longer has its fee re-minted into supply | `virtual_processor/utxo_validation.rs` (fees of dropped spends not re-minted) |
| #24 | Shielded state commitment | Coinbase carries `shielded_commitment[32]` = `shielded_state_root(selected_parent)`; every child validates it → a wrong shielded state halts the offending node, it cannot forge acceptance | `processes/coinbase.rs`, `processes/shielded.rs::shielded_state_root` |
| — | Nullifier MuHash accumulator | The spent-nullifier set is summarised by an order-independent MuHash folded into the state root | `model/stores/shielded.rs`, `processes/shielded.rs` |
| — | Turnstile / SupplyLedger | Cumulative coinbase + fees tracked so shielded value creation is bounded and auditable; part of the state root | `processes/shielded.rs` (cumulative_coinbase / cumulative_fees) |
| #29/#31 | Shielded finality soundness | `is_shielded_anchor_final`: a spend's anchor must be a canonical, matured tree root; a non-final anchor **drops the spend** (liveness) rather than disqualifying the block | `virtual_processor/processor.rs::is_shielded_anchor_final` |
| — | 512-action cap | `MAX_ACTIONS_PER_BUNDLE = 512` bounds per-tx proof-verification work | `shielded-core/src/bundle.rs:58` |
| — | Circuit guard | Not exposed to the June-2026 Zcash Orchard forgery bug (patched orchard 0.14.0 / halo2_gadgets 0.5.0) | `Cargo.toml` pins |

### Verified already-done this session (was on the "open" list, is actually closed)

**F-10 — AuxPoW pruning-proof level mismatch.**
Concern was that the pruning proof re-derived a *native* block level while the header
pipeline used an aux-aware level, breaking aux-history pruning-proof sync. **Verified
resolved:** `pruning_proof/validate.rs`, `pruning_proof/apply.rs`, **and** the live
header pipeline (`header_processor/pre_ghostdag_validation.rs:102`) all route level
derivation through the same aux-aware `kaspa_pow::calc_block_level_gated` /
`check_pow_gated(header, aux_pow, merged_mining_activation.is_active(daa_score))`. No
consensus path uses the native `calc_block_level`. Regression test
`aux_accepted_block_level_rederives_consistently` (`consensus/pow/src/auxpow.rs:325`).

### #1 — Pruning / IBD shielded-state import ✅ DONE + proven end-to-end (this session)

**Problem.** A fast-syncing node imported the UTXO set at the pruning point but no
shielded state (frontier / anchor index / supply totals / nullifier set). #24 commits the
state roots but nothing seeded them, so virtual wedged ("N disqualified vs 0 valid") the
moment it validated the first post-pruning-point block's coinbase commitment.

**Fix.** Transfer `(FrontierState, SupplyTotals, nullifier MuHash)` as compact metadata +
the full global nullifier set streamed separately (unbounded, unprunable per PLAN §2.9),
over new p2p messages, and seed the same store shapes `persist()` writes. Verification is
internal-consistency (streamed set reproduces the committed MuHash; declared root ==
recompute); the real binding is the #24 coinbase commitment enforced on the first real
child.

**Code.** `processes/shielded.rs` (export/verify/seed), `model/stores/shielded.rs`
(`iter_all`/`count`), `consensus/mod.rs` + `core/api/mod.rs` + `session.rs` (ConsensusApi),
`model/stores/pruning_meta.rs` (shielded_stable flag), new p2p messages
(`p2p.proto`/`messages.proto` fields 64-67, `payload_type.rs`, `convert/messages.rs`),
server flow `v10/request_pruning_point_shielded_state.rs`, client `ibd/streams.rs` +
`ibd/flow.rs` (`sync_new_shielded_state` wired into all 3 IBD paths).

**Tests.**
- Unit: `pruning_point_shielded_export_seed_roundtrip` (export→verify(+tamper/short-set
  rejection)→seed→reproduces root/anchor/frontier, catches re-spend of pre-PP nullifier,
  accepts a new spend). 11/11 shielded tests green.
- **Integration (new): `daemon_ibd_shielded_state_sync_test`** (two real daemons). A
  syncer mines past the pruning depth on a shielded-coinbase network; a fresh syncee
  fast-syncs and must (a) reach the syncer's pruning point + DAA, (b) reproduce the
  shielded **frontier byte-for-byte** at the pruning point (`get_shielded_tree_state`,
  `size > 0` so non-vacuous), (c) accept `finality_depth+` post-IBD blocks — which it can
  only do by revalidating each #24 commitment against the seeded state. **GREEN on VPS3**
  (1 passed, 15.9 s). Log confirms the real p2p path executed:
  `downloading the pruning point shielded state` → `Imported shielded state for pruning point …`.

**Test infra added:** `shielded_coinbase: Option<bool>` in `OverrideParams`
(`config/params.rs`) so a small-pruning simnet base can enable shielded coinbases
(simnet is otherwise transparent-coinbase; DEVNET/MAINNET are `true`). Miner reward must
be a `Version::ShieldedOrchard` address (43 raw Orchard bytes via
`kaspa_shielded_core::wallet::address_bytes_from_seed`) or the shielded mint rejects it.

### #4 — Shielded permanent-state pricing ✅ DONE + tested (this session, `db41527`)

**Problem.** A shielded tx leaves permanent state behind — one nullifier (in the
**unprunable** global set) + one note commitment per action — but paid only for the
transient payload bytes (compute mass already prices `tx.payload.len()`). Nothing charged
a premium for the permanent footprint. It is not the "free DoS" the roadmap implied
(nullifiers require real notes + valid proofs + already-paid compute mass), but the
permanent-vs-transient premium is exactly what KIP-9 exists for, and it can only be added
at a reset.

**Fix.** `SHIELDED_MASS_PER_ACTION = 1000` grams (`consensus/core/src/mass/mod.rs`) added
to **compute mass** (scoped to `tx.is_shielded()`), per action. Action count read cheaply
from the bundle header via new `kaspa_shielded_core::bundle::action_count_from_bytes`
(consistency-with-full-decode unit-tested). Added `kaspa-shielded-core` dep to
`consensus-core` (no cycle).

**Why compute mass, not storage mass.** Storage mass is **committed by the sender and
verified** (`tx.storage_mass()`), so charging it there would break every wallet/SDK
tx-builder until they all committed the exact value. Compute mass is **recomputed** by
consensus + mempool, so wallets absorb it through normal dynamic fee estimation — no
coordinated wallet change required.

**Fee impact.** ~20-25 % higher minimum fee on a typical 2-4 action spend ≈ **+0.006-0.009
zkas** — negligible in dollars, meaningful as a permanent-state signal. Tunable at the
reset (it's a plain const in a new binary).

**Tests.** `action_count_matches_full_decode`, `action_count_rejects_malformed` (shielded-
core); existing consensus-core mass tests unchanged & green; full `kaspa-consensus` build
green on VPS3.

### #4b — Shielded per-tx spend cap: 6 → 38 (block-fit only) ✅ DONE + tested (this session, `d8d8574`)

**Problem (the "couldn't send a few thousand zkas" pain).** Live chain is DAA ~950K;
`toccata_activation = 474_165_565` (~15 years out at 1 BPS) → we are permanently
pre-Toccata, so the `MAXIMUM_STANDARD_TRANSACTION_MASS_PRE_TOCCATA = 100_000` per-dimension
standard cap is live forever. transient mass = bytes×4 → 100K = 25 KB = **6 shielded
notes/tx**. Each mining note ≈ one block subsidy (~60 zkas, one note per mergeset output),
so value-per-tx ≈ **6 × 60 = 360 zkas — a hard ceiling.** `plan_payment` doesn't fail; it
shatters a payment into many sequential 360-zkas txs (3000 zkas = 50 notes = 9 txs ≈ 63 s
of proving; recipient gets 9 fragments).

**Fix.** The 100K cap exists only to stop updated nodes relaying txs un-updated peers
reject. On a fresh-genesis reset all nodes ship one binary → rationale gone. Shielded txs
are now **exempt from the artificial cap and bounded only by the block mass limit (500K)**
= **~38 notes/tx**. Transparent txs keep the 100K cap, so the entire upstream Toccata
standardness/relaxation mechanic and its tests are untouched.
- node `mining/src/mempool/check_transaction_standard.rs`: `standard_transaction_mass_cap`
  returns `mempool_block_mass_limits` for `tx.is_shielded()`, else the unchanged 100K path.
- wallet-engine `sdk/wallet-engine/src/payment.rs`: `STANDARD_TX_MASS_CAP` 100K→500K so
  `plan_payment` packs up to 38 spends; walletd + all frontends read `max_spends_per_tx()`
  dynamically (no hardcoded 6 anywhere).

**Effect.** 3000 zkas: 9 txs → **2**; 1000 zkas: 3 → **1**; 10000 zkas: 28 → **5**. Also
makes consolidation 6× faster (38→1/tx), which builds bigger notes and cures fragmentation
at the source. Per-spend fee unchanged (byte-proportional). **Honest limit:** notes are
~60 zkas, so moving *many* thousand in ONE tx still needs bigger notes — the permanent cure
is **opportunistic auto-consolidation** (fold spare small notes into every send's change),
which is wallet-engine-only, ships anytime, NOT reset-gated (follow-up, not done yet).

**Tests (VPS3, green):** `block_limit_allows_thirty_eight_spends` (engine), mining
standardness + the untouched `toccata_transient_mass_activation_tests`, mining build — all
EXIT 0. Note: this is mempool/relay policy (not block validity), but it must ship uniformly
→ belongs in the reset binary. Consensus-adjacent, reset-bundle.

### #3 — Merged-mining activation (decided, no code change)

`merged_mining_activation: ForkActivation::always()` on all four param sets
(`config/params.rs`). **Decision (user-approved): keep `always()`.** Merged mining is this
chain's live production model from genesis (it already merge-mines Kaspa, ~20-25 KAS
blocks/h), not a future fork. This also exercises the aux-PoW path from block 0.

---

## OUT of the reset bundle

| Item | Why it's out | Where it goes instead |
|------|--------------|-----------------------|
| **#5 reorg crash-consistency** | **Not consensus-breaking** — batching of DB writes is invisible to peers (same nullifier set + state root). The disconnect/rejoin nullifier ops (`virtual_processor/processor.rs:672`, `:708`) are idempotent set ops, and a crash leaves `commit_virtual_state` uncommitted so the node re-runs the same reorg on restart and converges. | Ordinary node **durability patch**, deployable anytime. Fix = fold the two standalone `db.write` into the `commit_virtual_state` batch. Site 3 (`commit_utxo_state:806`) is already atomic. |
| **Receive bug** ("sends don't credit") | Root cause is **wallet-side tree drift**, already fixed wallet-side. A prior ungated consensus "fix" **froze the chain**. | Wallet track — find the ~6 phantom-leaf cause; detection+quarantine+rebuild handles it safely meanwhile. See `send-receive-divergent-anchor`. |
| **F-02 coinbase rho collision** (Low) | Low severity, off critical path | Post-reset follow-up |
| Extra 2-proof PoW double-spend test; WrongSubsidy test cleanup | Test-only hardening | Post-reset follow-up |

---

## Remaining before cutting the reset binary

1. **#6 — Genesis difficulty retune** (the only consensus item left). Needs the target
   starting difficulty / block time for the new genesis (or "same as current mainnet" →
   pull live numbers off the node). See `mainnet-mining-difficulty` memory.
2. **Reset execution.** Regenerate genesis with the full bundle; cut the binary; coordinate
   the relaunch in order: **node → wallets/walletd → pool/bridge**. (Genesis regeneration
   also resets the merged-mining activation timeline; `always()` needs no DAA pick.)

---

## Verification & ops notes

- **All heavy builds run on VPS3 (204.10.194.28), never VPS1.** VPS3: rust 1.97.1, 8 G
  swap, repo cloned on branch, creds at `/root/.gh_creds`. See `external-build-box-vps3`.
- **This branch is test-only. Do NOT deploy over the running node** (`fca5229`) until the
  full reset is cut and relaunch is coordinated.
- Never delete `kaspa-upstream/data` (live merged-mining Kaspa parent), `fc-mainnet` (live
  node appdir), or the running datadir.
- This-session build evidence (VPS3): IBD integration test `1 passed` (15.9 s); #4
  consensus-core build + mass tests + full consensus build + shielded-core bundle tests
  all `EXIT 0`.

## Session commit trail (branch `ibd-shielded-import`)

```
db41527 consensus(#4): price shielded permanent-state footprint via per-action mass
88c727f test: add required shielded_anchor_depth to shielded IBD test params
8964d34 test: cover GetShieldedTreeState/GetShieldedBlocks in rpc op coverage test
9fabd6d test: end-to-end two-node shielded-state IBD sync
290afae ibd: shielded-state import over p2p (WIP checkpoint)
8d0ead1 zkas-api: fix indexer cursor freeze + self-heal re-anchor to sink   (explorer, already deployed)
```
