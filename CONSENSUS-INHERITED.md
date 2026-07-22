# Inherited Kaspa parameters that bind harder on ZKas

> **Status (2026-07-22):** this is the original analysis. Two of its headline items are now
> **resolved in the reset bundle** — the per-tx spend cap was raised **6 → 38** (shielded txs
> bounded by the block mass limit, not the 100k standard cap), and shielded permanent-state
> is now **priced via per-action compute mass**. See `CONSENSUS-CHANGES.md` (#4b, #4) for the
> authoritative current state; the "today = 6" figures below are the pre-reset baseline.

ZKas is a Kaspa fork whose transactions do not look like Kaspa transactions. Kaspa's
economic parameters were calibrated for ~300-byte transparent transactions that spend
UTXOs and cost microseconds to verify. A ZKas shielded transaction is ~22 KB, spends
notes the UTXO model cannot see, and costs milliseconds per action to verify.

Every parameter below was correct for Kaspa and is now mispriced — in both directions.
Some cost users money and usability (the 6-note limit); at least one is a latent
soundness/DoS problem (Halo 2 verification is free).

---

## 1. The 6-note spend limit

### Where it actually comes from

The limit is not in consensus. It is mempool **policy**, and it falls out of a chain of
four constants:

```
expected_wire_len(n) = 117 + n·884 + (2720 + 2272·n)      shielded-core/src/bundle.rs:105
                     = 2837 + 3156·n bytes

budget = STANDARD_TX_MASS_CAP / TRANSIENT_BYTE_TO_MASS_FACTOR − TX_ENVELOPE_MARGIN
       = 100_000 / 4 − 256 = 24_744 bytes                  sdk/wallet-engine/src/payment.rs:66

max_spends_per_tx() = largest n with expected_wire_len(n) ≤ 24_744 = 6
```

- `MAXIMUM_STANDARD_TRANSACTION_MASS_PRE_TOCCATA = 100_000` —
  `mining/src/mempool/check_transaction_standard.rs:26`
- `TRANSIENT_BYTE_TO_MASS_FACTOR = 4` — `consensus/core/src/constants.rs:36`

Transient mass models **bandwidth**: serialized bytes × 4. A 6-action bundle is 21,773
bytes → 87,092 transient mass, just under the 100,000 cap. A 7th action would exceed it.

Critically: the cap is enforced in `check_transaction_standard_in_isolation`, which is
mempool admission and relay policy, **not** block validity. A block containing a 40-action
shielded transaction is perfectly valid to every node on the network today. It just
cannot be *relayed* to a miner, because every mempool refuses to admit it.

### Why `toccata_activation` means the cap is permanent

`standard_transaction_mass_cap()` returns `None` — no cap, forever — once Toccata
activates. But `consensus/core/src/config/params.rs:793`:

```rust
// Roughly 2026-06-30 1615 UTC
toccata_activation: ForkActivation::new(474_165_565),
```

474,165,565 is a **Kaspa mainnet DAA score**, inherited verbatim. Kaspa reaches it in
mid-2026 at 10 BPS. ZKas is 1 BPS from genesis and is currently near DAA 684,000, so it
reaches that score in roughly **15 years**. Every Toccata-gated improvement in this
codebase is dead code on ZKas, and the 6-note cap is effectively permanent.

### How to raise it — three options, cheapest first

**Option A — raise the policy constant. No fork. Recommended.**

Change `MAXIMUM_STANDARD_TRANSACTION_MASS_PRE_TOCCATA` in
`mining/src/mempool/check_transaction_standard.rs:26`, and `STANDARD_TX_MASS_CAP` in
`sdk/wallet-engine/src/payment.rs:7` to match, then rebuild and restart nodes.

| per-dimension cap | byte budget | max spends per tx |
|---|---|---|
| 100,000 (today) | 24,744 | **6** |
| 500,000 (= block transient limit) | 124,744 | **38** |
| 1,000,000 (post-Toccata block limit) | 249,744 | **78** |

This is not a consensus change: no fork, no relaunch, no coordinated activation. The
transaction stays valid under existing block rules as long as its transient mass fits the
block limit, which is why 500,000 is the natural ceiling for Option A.

The one real constraint is **relay**: a node still running the old policy will not accept
or forward the larger transaction. Since we run the nodes and the pool, updating them is
a rolling restart. Third-party nodes would need the same build — so bump the policy
alongside a release, and treat 38 as the target rather than 78.

Cost to raise: two constants and their tests (`payment.rs:156` asserts `== 6`).

**Option B — shrink the wire format. Consensus change, but halves cost forever.**

Each action is 3,156 bytes: 884 of `ActionWire` + 2,272 of proof. Of the 884,
**580 bytes are `enc_ciphertext`**, which is dominated by Zcash's 512-byte memo field —
inherited from Orchard, not from Kaspa. ZKas memos are short user strings.

Cutting the memo to 64 bytes saves ~448 bytes/action (14%), taking a 6-action bundle from
21,773 to ~19,085. Modest for the spend limit, but it is a permanent reduction in
bandwidth *and* in the storage every archival node keeps forever. Worth doing when a
relaunch is happening anyway; not worth a relaunch on its own.

**Option C — activate Toccata.** `ForkActivation::always()` or a near-future DAA. This
removes the cap and raises the block transient limit 500k → 1M. But Toccata also changes
the block version (`TOCCATA_BLOCK_VERSION`), `max_signature_script_len`, and P2SH sigop
scanning — it is a real coordinated fork with consequences well beyond this limit. Do not
activate it to fix note counts. Do consider setting it to a *realistic* future DAA so the
codebase's post-Toccata paths are not dead for 15 years.

### What this does and does not fix

Raising to 38 makes almost every real payment single-transaction. It does **not** fix the
cause. The miner wallet holds 1,500+ notes because the pool pays out one note per block
and nothing makes that expensive — see §2, which is the actual bug.

---

## 2. Storage mass (KIP-0009) is exactly zero for shielded transactions

This is the most consequential finding, and it is deliberate — `consensus/core/src/mass/mod.rs:471`:

```rust
// Shielded transactions (and any input-less transaction) consume no
// transparent UTXOs, so the KIP-0009 input term |I|/A(I) is zero ...
// Storage mass is then just the output harmonic portion — zero for a
// shielded tx, which also has no transparent outputs.
if inputs.len() == 0 {
    return Some(harmonic_outs);
}
```

KIP-0009 exists to make UTXO-set fragmentation expensive: creating many small outputs
costs storage mass superlinearly, so dust attacks self-price. It operates on
`tx.outputs` and populated UTXO entries. A shielded bundle lives in `tx.payload` and
creates note commitments that the formula cannot see. **Storage mass for a shielded
transaction is structurally zero.**

The asymmetry is severe. A transparent UTXO can be spent and is then *gone* from the set.
A shielded note commitment is appended to a Merkle tree that is **never pruned**, and its
nullifier joins a set that must be retained forever to prevent double-spends. Shielded
state is strictly more expensive to keep than UTXO state — and it is the one priced at
zero.

Consequences we are already living with:

- The pool fragments wallets at ~60 notes/hour at no cost. That is why a payment needs
  8 transactions, why witness warming exists at all, and why `/api/wallet/consolidate`
  cannot keep up.
- An attacker can grow every node's permanent state and every wallet's scan cost for
  nothing but relay fees. There is no economic backpressure whatsoever.

**Fix direction.** Price note creation into contextual mass: extend `calc_contextual_masses`
so a shielded bundle contributes storage mass proportional to actions created, ideally
with the same superlinear shape KIP-9 uses for outputs. This is a consensus change and
needs care — it must not make ordinary 2-action payments expensive, only fragmentation.
A simpler interim measure that is *not* consensus: batch pool payouts so one payment
produces one note instead of sixty. That fixes the symptom this week and should happen
regardless.

---

## 3. Halo 2 verification is free in compute mass

`calc_non_contextual_masses` prices compute as:

```
compute_mass = size·mass_per_tx_byte + script_pubkey_bytes·10 + sigops·1000
```

A shielded transaction has no transparent inputs, so **zero sigops**, and no outputs, so
zero script-pubkey mass. Its entire compute mass is `payload_bytes × 1` — 21,773 for a
6-action bundle.

But verifying that bundle means 6 Halo 2 action verifications, milliseconds each, on
every node, for every transaction, forever. Kaspa's `mass_per_sig_op = 1000` exists
precisely because signature verification is the expensive part of validating a
transparent transaction. The shielded equivalent is priced at *nothing*.

Right now the byte cost is a rough proxy — actions are large, so big bundles cost
something. But the proxy is coincidental, not designed: proof bytes grow at 2,272/action
while verification cost per action is roughly constant, so the ratio is stable but
unowned. If the proof system is ever changed for smaller proofs (recursion, aggregation),
verification cost stays and the price collapses.

**Fix direction.** Add an explicit per-action term to compute mass, calibrated against
measured verification time, the way `mass_per_sig_op` was. Consensus change; low urgency
while the byte proxy holds, but it should be a deliberate parameter rather than an
accident.

---

## 4. Block transient limit — the real throughput ceiling

`prior_block_mass_limits: BlockMassLimits::with_shared_limit(500_000)` (params.rs:763).

A 6-action shielded transaction is 87,092 transient mass, so **a block holds at most 5
shielded transactions**. At 1 BPS that is the network ceiling: ~5 shielded tx/s, ~30
note-spends/s. Kaspa fits ~1,600 transparent transactions in the same block.

Raising the spend limit per §1 does not raise total throughput — it repackages the same
bytes into fewer, larger transactions, which is a genuine UX win (one payment, one
confirmation, one fee) but not a capacity win. Actual capacity needs either bigger blocks
(bandwidth) or smaller bundles (§1 Option B).

Worth stating plainly because it is easy to assume a 1-BPS chain with 500 KB blocks has
room. For shielded traffic it does not.

---

## 5. Smaller inherited items

- **`merged_mining_activation: ForkActivation::always()`** (params.rs:797) — the comment
  in the source says `TEST VALUE ... REVERT to 12_096_000 = day 14 for a real launch`.
  It was never reverted. Not a mispricing, but a launch-time decision still sitting in
  test configuration on mainnet.
- **Pruning parameters** (`pruning_proof_m: 1000`, and the pruning machinery generally)
  assume discardable state. The note commitment tree and nullifier set are not
  discardable. Pruning a ZKas node does not bound shielded state growth, so pruning-based
  capacity reasoning inherited from Kaspa does not transfer.
- **`max_script_public_key_len: 10_000`, `mass_per_script_pub_key_byte: 10`** — dead
  weight for shielded traffic, harmless, still correct for transparent.
- **`RELAY_FEE_PER_KG = 100_000`** (`sdk/wallet-engine/src/payment.rs:13`) — this is what
  makes a 6-note send cost ~0.0438 ZKAS. It prices bytes, which is the right axis for
  relay, and it is currently the *only* thing charging for shielded fragmentation. If §2
  is implemented, revisit so users are not charged twice for the same externality.

---

## Recommended order

1. **Batch pool payouts.** Not consensus, fixes the root cause of fragmentation, can ship
   this week.
2. **Raise the standardness cap 100k → 500k** (§1 Option A). Not consensus, one rolling
   node restart, takes max spends 6 → 38.
3. **Set `toccata_activation` to a realistic DAA** so post-Toccata code is reachable.
4. **Price shielded note creation into storage mass** (§2). Consensus; the real fix, needs
   design and a relaunch or activation height.
5. **Explicit per-action compute mass** (§3). Consensus; do it alongside 4.
