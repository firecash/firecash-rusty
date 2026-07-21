# Kaspa-native ZKAS shielded pool

Status: detailed protocol plan, reviewed 2026-07-17.

This document specifies the recommended trustless privacy architecture for a
ZKAS token that exists only on Kaspa. It does not use a ZKas chain, bridge,
federation, or separate consensus mechanism.

For the comparison with the other two leading designs, see
[KASPA-PRIVACY-ARCHITECTURES.md](KASPA-PRIVACY-ARCHITECTURES.md).

## 1. Deployment boundary

The architecture relies on Kaspa's Toccata programmability work:

- KIP-16 `OpZkPrecompile` for proof verification;
- KIP-17 transaction introspection and covenants;
- KIP-20 consensus-tracked covenant IDs;
- KIP-21 lane sequencing commitments for later batching;
- vProgs for the eventual based, aggregated proving model.

As of this review, Kaspa describes these primitives as live on TN12 ahead of
mainnet activation, while vProgs remains early prototype software. Therefore:

| Target | Current conclusion |
|---|---|
| Pure protocol and state-machine implementation | Possible now |
| Inline-ZK covenant prototype | Possible on TN12 |
| Trustless mainnet launch | Gated on Toccata mainnet activation and limits |
| High-throughput vProg settlement | Later phase; not production-ready |

This status must be revalidated against the active Kaspa release before any
deployment.

## 2. Design goals

1. ZKAS has one canonical, Kaspa-enforced supply.
2. Transparent and shielded ZKAS are two states of the same asset.
3. Private transfers hide sender, recipient, value, and transaction graph.
4. No operator can steal, freeze, redirect, or inflate ZKAS.
5. Encrypted note data is recoverable without a proprietary service.
6. Invalid proofs, duplicate nullifiers, and forged covenant outputs are
   rejected by Kaspa.
7. The safety path remains usable even if batch builders or provers disappear.
8. Protocol upgrades cannot silently replace the accepted proving program.

## 3. Canonical asset model

Create one covenant instance with a consensus-tracked covenant ID:

```text
ZKAS_COVENANT_ID
```

The covenant lineage recognizes two application-level output classes.

### 3.1 Transparent output

```text
TransparentZkasV1 {
    domain: ZKAS_TRANSPARENT_V1,
    covenant_id: Hash32,
    amount: u64,
    owner_script_hash: Hash32,
}
```

The amount and ownership condition are public. Public transfers must conserve
the sum of canonical transparent inputs and outputs.

### 3.2 Shielded pool state

```text
ShieldedPoolStateV1 {
    domain: ZKAS_POOL_STATE_V1,
    covenant_id: Hash32,
    protocol_version: u32,
    verifier_id: Hash32,
    note_root: Field,
    nullifier_root: Field,
    note_count: u64,
    shielded_supply: u64,
    cumulative_shielded: u128,
    cumulative_unshielded: u128,
}
```

The exact encoding must be canonical, domain-separated, and covered by the
transaction ID and proof public inputs. Counters wider than the token amount
avoid lifetime overflow.

## 4. Supply invariants

At all accepted states:

```text
transparent_supply + shielded_supply = fixed_total_supply

shielded_supply = cumulative_shielded - cumulative_unshielded

cumulative_unshielded <= cumulative_shielded
```

State changes are restricted to:

| Operation | Transparent supply | Shielded supply |
|---|---:|---:|
| Public transfer | 0 | 0 |
| Shield `x` | `-x` | `+x` |
| Private transfer | 0 | 0 |
| Unshield `x` | `+x` | `-x` |

Consensus must reject a canonical transparent ZKAS output unless it is either:

- a value-conserving continuation of canonical transparent inputs;
- an unshield output authorized by the shielded-pool transition;
- part of the uniquely defined genesis distribution.

The public turnstile limits extraction after a private-state inflation error,
but it does not make a broken circuit safe. Circuit soundness remains a
monetary-consensus assumption.

## 5. Private note model

Use a single-asset shielded note protocol derived from corrected, audited
Orchard/Penumbra concepts. Do not copy a historical circuit verbatim.

```text
NoteV1 {
    domain: ZKAS_NOTE_V1,
    protocol_version: u32,
    asset_id: ZKAS_COVENANT_ID,
    value: u64,
    recipient_key: Point,
    rho: Field,
    rseed: Bytes32,
}
```

The note commitment binds every field:

```text
cm = NoteCommit(
    domain,
    protocol_version,
    asset_id,
    value,
    recipient_key,
    rho,
    note_randomness(rseed)
)
```

Requirements:

- `asset_id` is constrained inside the proof, not merely supplied as an
  unchecked witness.
- Values are range-constrained as unsigned 64-bit integers.
- Address and curve points reject invalid or identity encodings.
- All hash, KDF, commitment, and signature uses have separate domains.
- Dummy notes are unspendable or provably zero-valued.

## 6. Commitment tree

Maintain one logical append-only commitment tree for all shielded ZKAS notes.
One pool provides the largest anonymity set.

The state transition proves:

1. the old frontier hashes to `old_note_root`;
2. output commitments are appended in canonical action order;
3. the resulting frontier hashes to `new_note_root`;
4. `new_note_count = old_note_count + output_count`;
5. no counter or tree-capacity overflow occurred.

Wallets retain authentication paths for their unspent notes and update those
paths as new commitments arrive. A checkpointed/sharded witness structure is
required for practical long histories even though the logical anonymity pool
remains global.

Permanent independent pool shards are not the initial scaling strategy because
they divide the anonymity set and make cross-shard movement observable.

## 7. Nullifier accumulator

A nullifier deterministically identifies the spend of a note without revealing
the note commitment:

```text
nf = Nullifier(
    domain,
    nullifier_key,
    note_commitment,
    note_position
)
```

Use a sparse Merkle set or another proof-friendly authenticated dictionary.
For every real spend, the circuit proves:

1. the nullifier is derived from the witnessed note and authorized key;
2. the note commitment is a member of an accepted note root;
3. the nullifier was absent under the old nullifier root;
4. it is present under the new nullifier root;
5. multiple nullifiers in the same action set are distinct;
6. the sequential update yields exactly the published new root.

Including the note position in derivation prevents duplicate commitments from
sharing one nullifier and makes each committed note instance unique.

## 8. Note encryption and discovery

Every output publishes:

- note commitment;
- ephemeral encryption key;
- recipient ciphertext;
- outgoing-view ciphertext where supported;
- fixed-size memo ciphertext.

Only the recipient's incoming viewing key should successfully decrypt the
recipient ciphertext. The sender may retain an outgoing viewing key to recover
sent-payment history.

Ciphertexts should be fixed-size and placed in the Kaspa transaction payload.
Off-chain-only delivery is not acceptable for the canonical safety path
because withholding or losing the ciphertext could make a valid note
undiscoverable.

## 9. Operations

### 9.1 Public transfer

Consumes transparent ZKAS covenant UTXOs and creates transparent ZKAS covenant
UTXOs with equal total value. No shielded state transition occurs.

### 9.2 Shield

Consumes:

- transparent ZKAS worth `x`;
- the current shielded pool state;
- optional ordinary KAS fee inputs.

Creates:

- a successor shielded state;
- private output commitments totalling `x` minus any explicitly authorized
  private fee;
- encrypted output notes;
- ordinary KAS change.

The public proof inputs expose `x`, while recipient ownership and note split
remain hidden.

### 9.3 Private transfer

Consumes the old shielded state and proves ownership of hidden input notes.
It publishes nullifiers and encrypted output notes without publishing input
commitments, recipients, or values.

For real notes:

```text
sum(inputs) = sum(outputs) + private_relayer_fee
```

### 9.4 Unshield

Proves ownership of private notes, advances the roots, decreases
`shielded_supply`, and creates exactly the declared canonical transparent ZKAS
outputs. The withdrawal values and public recipient scripts are visible.

### 9.5 Consolidation

Consumes multiple private notes and creates fewer private notes. It follows the
same private-transfer circuit and leaks no special operation type if action
padding and transaction encoding are standardized.

## 10. Private-transition statement

The circuit or proven program must establish all of the following:

1. The network, covenant ID, protocol version, and verifier identity match.
2. Every real input note has the canonical ZKAS asset ID.
3. Every real input note is included under an accepted note root.
4. The prover knows the spend authority for every real input.
5. Every nullifier is derived correctly and was previously absent.
6. The new nullifier root is the exact result of inserting all real spends.
7. Every output note is well formed and has the canonical asset ID.
8. The new note root is the exact result of appending all outputs.
9. Inputs, outputs, public value balance, and fees conserve value.
10. All amounts and counters are in range and do not overflow.
11. Dummy actions have zero value and cannot create spendable counterfeit
    notes.
12. Ciphertext commitments correspond to the output notes where the selected
    encryption design requires in-proof binding.
13. The transition is bound to the intended Kaspa transaction fields.

## 11. Public inputs and transaction binding

Recommended public inputs:

```text
network_id
covenant_id
protocol_version
verifier_id
operation_class
old_note_root
new_note_root
old_nullifier_root
new_nullifier_root
old_note_count
new_note_count
old_shielded_supply
new_shielded_supply
public_value_in
public_value_out
application_payload_hash
authorized_public_outputs_hash
```

The covenant must independently reconstruct or inspect these values from the
actual transaction and compare them with the proof inputs. Otherwise, an
attacker may attach a valid proof to a transaction with different public
outputs.

Avoid circular commitment definitions. Specify exactly which transaction
fields are included in `application_payload_hash`, which fee fields remain
mutable, and how ordinary KAS sponsorship inputs and change are authorized.

## 12. Covenant validation

The shielded state covenant must:

1. verify that the authorizing state input has `ZKAS_COVENANT_ID`;
2. require exactly one authorized successor state for a normal transition;
3. require the successor covenant ID to remain unchanged;
4. validate the canonical successor-state encoding;
5. pin the accepted proof tag and verification program/key identity;
6. execute `OpZkPrecompile` with the exact proof inputs;
7. bind proof inputs to the transaction payload and authorized outputs;
8. enforce public ZKAS input/output conservation;
9. prevent unknown transition and protocol versions;
10. reject unauthorized verifier upgrades or alternate successor scripts.

The covenant should not accept an arbitrary verifying key supplied by the
spender. An accepted verifier or program image must be pinned by the covenant
state and governed by an explicit version-migration transaction.

## 13. Proof-system strategy

KIP-16 specifies Groth16 and RISC Zero succinct verification paths. It does not
provide a native Halo 2/Pasta verifier, so an Orchard Halo 2 proof cannot be
assumed to verify directly on Kaspa.

| Candidate | Benefit | Cost/risk | Role |
|---|---|---|---|
| RISC Zero guest | Deterministic Rust program and fast design iteration | Proving cost; receipt size | First TN12 prototype |
| Custom Groth16 circuit | Compact proof and efficient verification | Circuit rewrite and trusted setup | Production candidate |
| RISC Zero proof compressed to Groth16 | General program with compact settlement | More proving infrastructure | Strong batching candidate |
| Halo 2 proof verified inside a zkVM | Potential reuse of Orchard work | Potentially extreme prover cost | Benchmark, not assumption |
| Future native Halo 2 precompile | Directer reuse | Requires Kaspa consensus support | Long-term option |

Required bake-off:

1. Implement one deterministic transition specification.
2. Build a RISC Zero guest against it.
3. Build the equivalent purpose-specific circuit.
4. Benchmark 2-in/2-out and larger padded action sets.
5. Measure prover RAM, latency, proof bytes, verifier mass, and mobile impact.
6. Select only after independent review of both implementations.

## 14. Transaction layout

Conceptual private transition:

```text
Inputs
  0: current ShieldedPoolState covenant UTXO
  1..n: ordinary KAS sponsorship/fee inputs
  optional: transparent ZKAS inputs for shield

Outputs
  0: successor ShieldedPoolState covenant UTXO
  optional: transparent ZKAS outputs for unshield
  optional: ordinary KAS sponsor change

Payload
  protocol and operation version
  nullifiers
  new note commitments
  encrypted note ciphertexts
  old/new roots and counters
  public balance fields
  ZK proof
```

The exact limits must be tested against Kaspa transaction mass and script
element limits rather than inferred from the script-engine maximums.

## 15. Fees and relayers

A private user should not need a publicly linked KAS fee wallet.

Recommended flow:

1. The wallet creates and proves a ZKAS transition.
2. It sends the request through Tor or another privacy transport.
3. A permissionless relayer adds ordinary KAS fee inputs.
4. The private transition creates a ZKAS fee note for the relayer.
5. The covenant permits only the explicitly defined fee-input and KAS-change
   mutations without invalidating the application proof.

Anti-replay data must bind the request to the old state root, network,
covenant, expiry window, and relayer terms. Multiple relayers prevent a single
gateway from learning all transaction timing and IP metadata.

## 16. Concurrency and batching

### 16.1 Initial single-state limitation

Two transactions consuming the same pool-state UTXO conflict:

```text
R0 -> R1a
  \-> R1b   (conflicts with R1a)
```

This makes a direct covenant safe and simple but serializes state advancement.
It is appropriate for a prototype, not the final high-volume system.

### 16.2 Permissionless batches

Batch multiple user actions into one transition:

```text
R0 -> prove(actions[0..N]) -> R1
```

Builders cannot forge validity, but can delay inclusion. Require:

- multiple builders and provers;
- bounded batch delay;
- deterministic action ordering;
- direct fallback or forced inclusion;
- proof and builder fee markets;
- no proprietary encrypted-note storage.

### 16.3 vProg lane

The long-term model places ZKAS operations in a dedicated Kaspa application
lane. Kaspa sequencing commitments determine the canonical operation order;
provers batch that lane's activity and settle a new state commitment.

This preserves one logical anonymity pool while allowing proof work to scale
with ZKAS activity. It must not be treated as production-ready until KIP-21 and
vProg behavior, exits, reorgs, pricing, and mainnet activation are stable.

## 17. Wallet requirements

The wallet must implement:

- spending, full-viewing, incoming-viewing, and outgoing-viewing keys;
- diversified one-time addresses;
- encrypted note trial decryption;
- note and nullifier databases;
- checkpointed commitment witnesses;
- reorg-safe Kaspa synchronization;
- proof construction or anti-blind remote proving;
- relayer discovery and privacy-preserving submission;
- encrypted local backup and deterministic recovery;
- transparent/shielded balance separation;
- explicit warnings about public entry/exit correlation.

Wallet scanning should consume a common compact stream. Per-address server
queries would reveal wallet activity even when the cryptography is correct.

## 18. Data availability and pruning

Canonical transactions publish encrypted output notes on Kaspa. Practical
recovery additionally requires:

- independent archival/compact-note servers;
- authenticated checkpoints;
- multiple providers;
- downloadable note ranges rather than address queries;
- local wallet backups;
- a specified recovery procedure after long offline periods.

Consensus commitments prove the accepted state, but pruning can remove bulk
historical transaction data needed by a newly restored wallet. The protocol
must specify who retains it and how clients verify it.

## 19. Privacy analysis

| Observable information | Mitigation |
|---|---|
| Shield amount and source | Batch shielding; avoid immediate spends |
| Unshield amount and destination | Batch/split withdrawals; fresh addresses |
| Deposit-to-withdraw timing | Random delays and withdrawal queues |
| Transaction input/output count | Fixed padded action shapes |
| User IP | Tor and multi-relayer submission |
| KAS fee wallet | Relayer sponsorship |
| Wallet ownership queries | Common compact-note downloads |
| Quiet pool or shard | One global logical anonymity pool |
| Software/proof fingerprint | Standard transaction and proof versions |

Zero-knowledge transaction privacy does not automatically provide network
privacy. Relaying and scanning are part of the privacy protocol, not optional
wallet polish.

## 20. Upgrades and emergency handling

Verifier upgrades are monetary-consensus events. Define before launch:

- immutable version identifiers;
- old-to-new state migration proofs;
- an announced activation window;
- prevention of downgrade transitions;
- reproducible verifier/program artifacts;
- explicit handling of unspent notes under an old version;
- emergency halt scope that cannot redirect or confiscate funds;
- a user exit/migration route;
- public supply and pool-turnstile monitoring.

The May 2026 Orchard soundness incident demonstrates that a private inflation
bug can be difficult or impossible to audit retroactively. ZKAS therefore
requires independent circuit review, redundant implementations, public
turnstile accounting, and a tested migration path before it carries value.

## 21. Testing and security requirements

### State-machine properties

- Supply is conserved for every accepted operation.
- A nullifier cannot be accepted twice.
- No noncanonical asset ID can balance as ZKAS.
- No field wraparound represents a valid u64 amount.
- Dummy actions cannot create spendable value.
- Public output value equals the proven unshield value exactly.
- A proof cannot be replayed on another network, covenant, version, root, or
  transaction.

### Adversarial covenant tests

- forged covenant ID;
- extra successor state;
- missing successor state;
- alternate successor script;
- arbitrary verifying key;
- reordered public outputs;
- sponsor-input mutation outside the permitted envelope;
- proof attached to a different payload;
- parent-state race and reorg;
- oversized proof/payload denial of service.

### Cryptographic assurance

- two independent circuit audits;
- review of the Kaspa precompile integration;
- differential state-machine and circuit implementations;
- property-based and mutation testing;
- malformed point and field-element corpus;
- proving-key/program reproducibility;
- trusted-setup ceremony and transcript verification if Groth16 is selected;
- public testnet attack and bounty program.

## 22. Delivery plan

### Phase 0: freeze the specification

- Token supply, decimals, and genesis distribution.
- Covenant state and canonical encodings.
- Notes, commitments, nullifiers, and encryption.
- Transition statement and public inputs.
- Fee sponsorship and transaction-binding rules.
- Upgrade and emergency model.

### Phase 1: deterministic state machine

- Implement `genesis`, `public_transfer`, `shield`, `private_transfer`, and
  `unshield` as pure deterministic logic.
- Build test vectors and invariant/property tests.
- Implement independent supply accounting.

### Phase 2: TN12 covenant

- Create the covenant genesis and stable ID.
- Implement transparent outputs and the pool-state continuation.
- Pin the verifier/program identity.
- Bind proof results to exact transaction fields.
- Exercise reorgs and conflicting state transitions.

### Phase 3: proof implementations

- Build the RISC Zero transition guest.
- Build the purpose-specific circuit.
- Implement the authenticated note and nullifier structures.
- Run the proof-system bake-off.

### Phase 4: private wallet

- Address and key formats.
- Note encryption and scanning.
- Witness maintenance and recovery.
- Local and anti-blind proving modes.
- Sponsored fees and private broadcasting.

### Phase 5: permissionless batching

- Action request format and mempool.
- Multiple builders and provers.
- Deterministic ordering and fee market.
- Bounded delay and forced fallback.
- Aggregate/recursive proof settlement.

### Phase 6: vProg integration

- Dedicated ZKAS lane.
- Lane-based sequencing proofs.
- Based batch proving.
- Settlement and escape behavior.
- Multi-prover interoperability.

### Phase 7: production readiness

- External audits and remediation.
- Load and denial-of-service tests.
- Reproducible artifacts.
- Monitoring and supply dashboards.
- Mainnet capability revalidation.
- Long-running public testnet and bug bounty.

## 23. Rejected shortcuts

| Shortcut | Reason for rejection |
|---|---|
| Indexer token plus mixer | Indexer/social consensus, not Kaspa-enforced privacy |
| Federated vault | Custodial or bounded-trust rather than trustless |
| Centralized private ledger | Operator can observe, freeze, or steal |
| Permanent independent shards | Divides anonymity and exposes cross-shard movement |
| Off-chain-only note ciphertexts | Data withholding can make funds unrecoverable |
| Arbitrary user-provided verifier key | Allows attacker-defined validity rules |
| Copy an old Orchard circuit | Ignores corrections and project-specific invariants |
| Call vProgs production-ready | Current upstream repository labels itself prototype-stage |

## 24. Final architecture

```text
Kaspa consensus
  |
  +-- canonical ZKAS covenant ID
       |
       +-- transparent ZKAS UTXOs
       |
       +-- global shielded pool state
            |
            +-- append-only note commitments
            +-- authenticated nullifier set
            +-- encrypted output notes
            +-- Kaspa-verified transition proof
            +-- explicit shielded supply turnstile
            +-- permissionless relayers
            +-- direct safety transition
            +-- recursive/vProg batching for scale
```

This design provides strong privacy without a separate chain while preserving
Kaspa as the settlement and validity authority. Its main unresolved deployment
questions are Toccata mainnet activation, proof-system economics, state
concurrency, and the maturity of Kaspa lane/vProg tooling.

## Primary sources

- [Kaspa build and Toccata status](https://kaspa.org/build)
- [KIP-16: ZK precompile](https://github.com/kaspanet/kips/blob/master/kip-0016.md)
- [KIP-17: covenants and scripting](https://github.com/kaspanet/kips/blob/master/kip-0017.md)
- [KIP-20: covenant IDs](https://github.com/kaspanet/kips/blob/master/kip-0020.md)
- [KIP-21: sequencing commitments](https://github.com/kaspanet/kips/blob/master/kip-0021.md)
- [Kaspa vProgs](https://github.com/kaspanet/vprogs)
- [Orchard commitment tree](https://zcash.github.io/orchard/design/commitment-tree.html)
- [Orchard nullifiers](https://zcash.github.io/orchard/design/nullifiers.html)
- [Orchard Actions](https://zcash.github.io/orchard/design/actions.html)
- [Penumbra shielded pool](https://protocol.penumbra.zone/main/shielded_pool.html)
- [Penumbra nullifiers](https://protocol.penumbra.zone/main/sct/nullifiers.html)
- [Zcash Foundation Orchard incident report](https://zfnd.org/zebra-4-5-3-and-5-0-0-emergency-soft-fork-and-nu6-2-activation/)

