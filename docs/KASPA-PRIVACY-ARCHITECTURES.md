# Kaspa-native ZKAS privacy architectures

Status: design research, reviewed 2026-07-17.

This document assumes that ZKAS exists only as a token on Kaspa. There is no
ZKas sidechain, bridge, validator set, or separate consensus network. The goal
is strong, trustless privacy whose validity and asset supply are enforced by
Kaspa.

The detailed design for the recommended architecture is in
[KASPA-NATIVE-ZK-SHIELDED-POOL.md](KASPA-NATIVE-ZK-SHIELDED-POOL.md).

## Requirements

All candidate architectures are evaluated against the same requirements:

1. No custodian, federation, or trusted coordinator can steal or mint ZKAS.
2. Kaspa prevents double spends and enforces the canonical ZKAS supply.
3. Sender, recipient, amount, and private transaction graph should be hidden.
4. Users can recover funds without a continuously available proprietary
   service.
5. The system must fit Kaspa's UTXO, covenant, inline-ZK, and future vProg
   model rather than assuming an Ethereum-style VM.
6. Public entry and exit are allowed to be visible, but shielded-to-shielded
   transfers must be private.

## Summary

Difficulty uses `1 = easy` and `10 = extremely difficult`.

| Rank | Architecture | Privacy | Trustlessness | Scalability | Feasibility | Difficulty | Recommended role |
|---:|---|---:|---:|---:|---:|---:|---|
| 1 | Kaspa-native ZK shielded pool | 10 | 10 | 7 initially | 8 after Toccata | 9 | Canonical protocol |
| 2 | Recursive private ZKAS pool | 10 | 9 | 10 | 7 after Toccata | 10 | Scaling mode for architecture 1 |
| 3 | Client-validated private ZKAS | 8 | 9 | 9 | 7 | 8.5 | Fallback if native proving is unsuitable |

The ratings assume that the required Toccata primitives are activated and
stable. As of this review, Kaspa documents KIP-16, KIP-17, KIP-20, and KIP-21
as live on TN12 ahead of mainnet activation. Mainnet capability must be checked
again before deployment.

## 1. Kaspa-native ZK shielded pool

ZKAS is one covenant-native asset with two representations:

- transparent ZKAS covenant UTXOs;
- private ZKAS notes committed into one shielded pool state.

Kaspa observes note commitments, nullifiers, encrypted outputs, old and new
state roots, and a zero-knowledge proof. It does not learn which old note was
spent or the owners and values of the new notes.

```text
transparent ZKAS
       |
       | shield
       v
Kaspa covenant shielded state
       |
       | private note transfers
       v
Kaspa covenant shielded state
       |
       | unshield
       v
transparent ZKAS
```

Kaspa enforces:

- canonical covenant lineage;
- note membership;
- unique nullifiers;
- conservation of value;
- valid state-root transitions;
- exact public-to-private and private-to-public supply changes.

### Strengths

- Strongest settlement and data-availability model.
- No bridge, federation, or separate chain.
- Recipients can recover encrypted notes from Kaspa data.
- One logical pool maximizes the anonymity set.
- Public and shielded ZKAS remain the same canonical asset.

### Weaknesses

- A single state UTXO serializes direct transitions.
- Proof construction and wallet scanning are substantial engineering work.
- Inline proof verification depends on Toccata activation and limits.
- Public shielding and unshielding remain observable.

### Decision

This is the canonical architecture. Begin with a single-state TN12 prototype,
then add permissionless batching. Do not permanently shard the anonymity pool
merely to increase transaction concurrency.

## 2. Recursive private ZKAS pool

Users produce private ZKAS actions off-chain. Permissionless builders batch
many actions and submit one recursive proof and one new state root to the
Kaspa covenant.

```text
private actions from users
           |
           v
permissionless batch builder
           |
           v
recursive transition proof
           |
           v
Kaspa verifies proof and advances ZKAS root
```

The builder is not trusted for validity or custody: it cannot forge a valid
proof, redirect notes, or create supply. It can, however, delay or censor an
action unless the protocol includes competing builders, forced inclusion, and
an escape path.

### Required safety mechanisms

- Multiple permissionless builders and provers.
- Canonical ordering tied to Kaspa sequencing commitments.
- Maximum batch delay.
- Direct fallback or forced-action inclusion.
- User-held encrypted note data.
- Escape against the latest settled root.
- Deterministic fee and replay rules.

### Data modes

| Mode | Cost | Recovery | Trust consequence |
|---|---:|---:|---|
| Publish encrypted notes on Kaspa | Higher | Strong | Validity and availability remain trustless |
| Deliver encrypted notes off-chain | Lower | Weaker | Builder cannot steal, but can withhold data |

### Decision

Do not make this a separate competing protocol. Add recursive batching as the
scaling path for the native shielded pool after the direct transition is fully
specified and audited. KIP-21 application lanes and Kaspa vProgs are the
natural long-term sequencing and proving framework.

## 3. Client-validated private ZKAS

Kaspa UTXOs act as single-use ownership seals. The asset state, amount,
ownership chain, and zero-knowledge proofs move privately between sender and
recipient. Kaspa prevents reuse of the underlying seals, while recipients
independently validate the private state package.

```text
Kaspa UTXO: public single-use seal
Private package: ZKAS state + ownership proof + amount commitment
```

The recipient verifies:

- the previous private state was valid;
- the associated Kaspa seal was consumed correctly;
- the state transition conserves ZKAS;
- the received state is bound to the recipient;
- the same ownership state cannot be reused.

### Strengths

- Very low on-chain data.
- Does not require every private transition to update one global pool state.
- Can be developed if Kaspa's inline verifier proves too costly.
- No global token indexer defines ownership.

### Weaknesses

- The recipient must receive and retain private proof data.
- Backup loss can make ownership impossible to prove.
- Wallets, exchanges, and merchants need custom client-side validation.
- Global supply auditing and recovery are harder.
- Private-state delivery can leak metadata or become unavailable.
- Weaker composability and a smaller effective anonymity set than a shared
  shielded pool.

### Decision

Keep this as a research fallback, not the primary protocol. Its consensus
integration may be smaller, but wallet correctness and recovery are harder.

## Combined recommendation

The desired final system combines the first two architectures:

```text
one canonical covenant-native ZKAS asset
                    +
one global shielded note state
                    +
direct proof transitions as the safety baseline
                    +
recursive permissionless batches for scale
                    +
Kaspa lane sequencing when available
```

Architecture 3 remains a fallback experiment. CoinJoin, stealth addresses,
and network relays are useful supporting techniques, but none replaces the
shielded note protocol.

## Relevant primary sources

- [Kaspa KIP-16: ZK precompile](https://github.com/kaspanet/kips/blob/master/kip-0016.md)
- [Kaspa KIP-17: covenants and transaction introspection](https://github.com/kaspanet/kips/blob/master/kip-0017.md)
- [Kaspa KIP-20: covenant IDs](https://github.com/kaspanet/kips/blob/master/kip-0020.md)
- [Kaspa KIP-21: application-lane sequencing commitments](https://github.com/kaspanet/kips/blob/master/kip-0021.md)
- [Kaspa vProgs prototype](https://github.com/kaspanet/vprogs)
- [Orchard protocol design](https://zcash.github.io/orchard/)
- [Penumbra shielded pool specification](https://protocol.penumbra.zone/main/shielded_pool.html)

