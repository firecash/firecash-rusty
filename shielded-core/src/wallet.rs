//! Wallet-side shielded transaction construction — the prover, the inverse of
//! [`crate::verify`] (PLAN §2.10 / §3 wallet).
//!
//! This is what *produces* a shielded transaction: it derives keys, builds an
//! Orchard bundle, creates the Halo 2 proof, and signs the binding + spend-auth
//! signatures over the firecash sighash — emitting a [`ShieldedBundle`] in our
//! canonical wire format, ready to carry in a transaction payload and be
//! accepted by the consensus verifier.
//!
//! The whole module requires the `circuit` feature (proving needs the proving
//! key). Proving is the heavy operation; PLAN §2.10 anticipates GPU-assisted and
//! delegated proving for light wallets — by Orchard's key separation, a delegated
//! prover never gains spend authority. This module is the local-proving core.

/// Wallet scanning — the receive side (§2.10). Trial-decrypts a bundle's outputs
/// with an incoming viewing key to recover notes sent to the holder. Pure
/// decryption; no proving circuit required, so this is available without the
/// `circuit` feature. (Under mandatory privacy, everyone always scans — this is
/// the hot path a light-wallet indexer accelerates.)
pub mod scan {
    use crate::bundle::{ActionWire, ShieldedBundle};
    use orchard::{
        Action,
        keys::{FullViewingKey, IncomingViewingKey, Scope, SpendingKey},
        note::{ExtractedNoteCommitment, Note, Nullifier, TransmittedNoteCiphertext},
        note_encryption::OrchardDomain,
        primitives::redpallas::{Signature, SpendAuth, VerificationKey},
        value::ValueCommitment,
    };
    use zcash_note_encryption::try_note_decryption;

    /// A note recovered from a bundle: which action carried it (its position
    /// offset within the block's outputs, needed to build a witness later) and
    /// the recovered [`Note`], which the wallet can subsequently spend.
    pub struct ReceivedNote {
        /// Index of the action within the bundle that carried this output.
        pub action_index: usize,
        /// The recovered note (spendable via `wallet::build_spend_bundle`).
        pub note: Note,
    }

    impl ReceivedNote {
        /// The note's value in the base unit.
        pub fn value(&self) -> u64 {
            self.note.value().inner()
        }
    }

    /// Derive an external incoming viewing key from a wallet seed.
    pub fn ivk_from_seed(seed: [u8; 32]) -> Option<IncomingViewingKey> {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(seed))?;
        Some(FullViewingKey::from(&sk).to_ivk(Scope::External))
    }

    /// Derive the raw 43-byte external Orchard address for a wallet seed — the
    /// bytes a miner puts in a shielded-coinbase reward's `script_public_key` so
    /// consensus pays the block reward to this wallet as a coinbase note (§2.7).
    pub fn address_bytes_from_seed(seed: [u8; 32]) -> Option<[u8; 43]> {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(seed))?;
        Some(FullViewingKey::from(&sk).address_at(0u32, Scope::External).to_raw_address_bytes())
    }

    /// Reconstruct an Orchard action from its wire form (auth = its spend-auth
    /// signature). Returns `None` if any field is malformed (such an action can
    /// carry no note for us). This mirrors the verifier's reconstruction and thus
    /// enforces the identity `rk`/`epk` rules via `Action::from_parts`.
    fn reconstruct_action(a: &ActionWire) -> Option<Action<Signature<SpendAuth>>> {
        let nf: Nullifier = Option::from(Nullifier::from_bytes(&a.nullifier))?;
        let rk = VerificationKey::<SpendAuth>::try_from(a.rk).ok()?;
        let cmx: ExtractedNoteCommitment = Option::from(ExtractedNoteCommitment::from_bytes(&a.cmx))?;
        let cv: ValueCommitment = Option::from(ValueCommitment::from_bytes(&a.cv_net))?;
        let ct = TransmittedNoteCiphertext {
            epk_bytes: a.ephemeral_key,
            enc_ciphertext: a.enc_ciphertext,
            out_ciphertext: a.out_ciphertext,
        };
        let sig = Signature::<SpendAuth>::from(a.spend_auth_sig);
        Action::from_parts(nf, rk, cmx, ct, cv, sig).ok()
    }

    /// Scan a bundle with an incoming viewing key, returning every note addressed
    /// to the key's holder (trial decryption, §2.10).
    pub fn scan_bundle(ivk: &IncomingViewingKey, bundle: &ShieldedBundle) -> Vec<ReceivedNote> {
        let prepared = ivk.prepare();
        let mut received = Vec::new();
        for (i, a) in bundle.actions.iter().enumerate() {
            let Some(action) = reconstruct_action(a) else { continue };
            let domain = OrchardDomain::for_action(&action);
            if let Some((note, _addr, _memo)) = try_note_decryption(&domain, &prepared, &action) {
                received.push(ReceivedNote { action_index: i, note });
            }
        }
        received
    }
}

pub use scan::{ReceivedNote, address_bytes_from_seed, ivk_from_seed, scan_bundle};

#[cfg(feature = "circuit")]
pub mod build {
    use crate::bundle::{ActionWire, ShieldedBundle};
    use crate::verify::sighash;
    use orchard::{
        Action, Address, Anchor, Bundle,
        builder::{Builder, BundleType},
        bundle::{Authorization, Authorized},
        circuit::ProvingKey,
        keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
        note::{ExtractedNoteCommitment, Note},
        tree::MerklePath,
        value::NoteValue,
    };
    use rand::{CryptoRng, RngCore};

    /// A wallet's Orchard keys, derived from a 32-byte seed.
    pub struct ShieldedKeys {
        sk: SpendingKey,
        fvk: FullViewingKey,
    }

    impl ShieldedKeys {
        /// Derive keys from a seed. Returns `None` if the seed is not a valid
        /// Orchard spending key (negligibly rare).
        pub fn from_seed(seed: [u8; 32]) -> Option<Self> {
            let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(seed))?;
            let fvk = FullViewingKey::from(&sk);
            Some(Self { sk, fvk })
        }

        /// The wallet's default external receiving address.
        pub fn address(&self) -> Address {
            self.fvk.address_at(0u32, Scope::External)
        }
    }

    /// Errors building a shielded bundle.
    #[derive(Debug)]
    pub enum BuildError {
        /// The Orchard bundle builder failed (e.g. unsatisfiable bundle type).
        Builder(String),
        /// Proof creation failed.
        Proof(String),
        /// The builder produced no bundle (nothing to spend or output).
        Empty,
    }

    /// Serialize an authorized/proven Orchard bundle into our wire format, using
    /// `spend_auth_sig` to extract each action's signature (zeroed before signing)
    /// and the given bundle-level `proof` / `binding_sig`.
    pub fn to_wire<T: Authorization>(
        bundle: &Bundle<T, i64>,
        spend_auth_sig: impl Fn(&Action<T::SpendAuth>) -> [u8; 64],
        proof: Vec<u8>,
        binding_sig: [u8; 64],
    ) -> ShieldedBundle {
        let actions = bundle
            .actions()
            .iter()
            .map(|a| {
                let ct = a.encrypted_note();
                ActionWire {
                    nullifier: a.nullifier().to_bytes(),
                    rk: <[u8; 32]>::from(a.rk()),
                    cmx: a.cmx().to_bytes(),
                    cv_net: a.cv_net().to_bytes(),
                    ephemeral_key: ct.epk_bytes,
                    enc_ciphertext: ct.enc_ciphertext,
                    out_ciphertext: ct.out_ciphertext,
                    spend_auth_sig: spend_auth_sig(a),
                }
            })
            .collect();
        ShieldedBundle {
            actions,
            flags: bundle.flags().to_byte(),
            value_balance: *bundle.value_balance(),
            anchor: bundle.anchor().to_bytes(),
            proof,
            binding_sig,
        }
    }

    /// Build an **output-only** shielded bundle that mints `value` to
    /// `recipient` (spends disabled — the coinbase / value-entry case, §2.7), with
    /// a real proof and signatures over the sighash derived from `tx_context`.
    ///
    /// Output-only bundles have a negative `value_balance` (value enters the
    /// pool); they balance under the binding signature exactly as any bundle.
    pub fn build_output_only_bundle(
        pk: &ProvingKey,
        recipient: Address,
        value: u64,
        network_domain: &[u8; 32],
        tx_context: &[u8],
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<ShieldedBundle, BuildError> {
        let mut builder = Builder::new(BundleType::DEFAULT, Anchor::empty_tree());
        builder
            .add_output(None, recipient, NoteValue::from_raw(value), [0u8; 512])
            .map_err(|e| BuildError::Builder(format!("{e:?}")))?;

        let (unauth, _meta) =
            builder.build::<i64>(&mut rng).map_err(|e| BuildError::Builder(format!("{e:?}")))?.ok_or(BuildError::Empty)?;
        let proven = unauth.create_proof(pk, &mut rng).map_err(|e| BuildError::Proof(format!("{e:?}")))?;

        // Compute the sighash over the effects (proof/sigs excluded), then sign.
        let effects = to_wire(&proven, |_| [0u8; 64], Vec::new(), [0u8; 64]);
        let msg = sighash(&effects, network_domain, tx_context);
        let authorized: Bundle<Authorized, i64> =
            proven.apply_signatures(&mut rng, msg, &[]).map_err(|e| BuildError::Proof(format!("{e:?}")))?;

        Ok(to_wire(
            &authorized,
            |a| <[u8; 64]>::from(a.authorization()),
            authorized.authorization().proof().as_ref().to_vec(),
            <[u8; 64]>::from(authorized.authorization().binding_signature()),
        ))
    }

    /// Build a **spending** shielded transaction: spend `note` (with its
    /// `merkle_path` proving membership at the anchor it roots to) and send
    /// `output_value` to `recipient`. The remainder, `note.value −
    /// output_value`, becomes the public fee (`value_balance`), collected by the
    /// miner. Proven and signed (with the real spend authority) over the sighash.
    ///
    /// The wallet is responsible for tracking each note's `merkle_path` witness as
    /// the global tree finalizes (PLAN §2.5/§2.10); here it is supplied.
    pub fn build_spend_bundle(
        pk: &ProvingKey,
        keys: &ShieldedKeys,
        note: Note,
        merkle_path: MerklePath,
        recipient: Address,
        output_value: u64,
        network_domain: &[u8; 32],
        tx_context: &[u8],
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<ShieldedBundle, BuildError> {
        // The anchor is the root the supplied path proves the note into.
        let anchor = merkle_path.root(ExtractedNoteCommitment::from(note.commitment()));
        let mut builder = Builder::new(BundleType::DEFAULT, anchor);
        builder.add_spend(keys.fvk.clone(), note, merkle_path).map_err(|e| BuildError::Builder(format!("{e:?}")))?;
        builder
            .add_output(None, recipient, NoteValue::from_raw(output_value), [0u8; 512])
            .map_err(|e| BuildError::Builder(format!("{e:?}")))?;

        let (unauth, _meta) =
            builder.build::<i64>(&mut rng).map_err(|e| BuildError::Builder(format!("{e:?}")))?.ok_or(BuildError::Empty)?;
        let proven = unauth.create_proof(pk, &mut rng).map_err(|e| BuildError::Proof(format!("{e:?}")))?;

        let effects = to_wire(&proven, |_| [0u8; 64], Vec::new(), [0u8; 64]);
        let msg = sighash(&effects, network_domain, tx_context);
        // The real spend is authorized with the spend authorizing key.
        let ask = SpendAuthorizingKey::from(&keys.sk);
        let authorized: Bundle<Authorized, i64> =
            proven.apply_signatures(&mut rng, msg, &[ask]).map_err(|e| BuildError::Proof(format!("{e:?}")))?;

        Ok(to_wire(
            &authorized,
            |a| <[u8; 64]>::from(a.authorization()),
            authorized.authorization().proof().as_ref().to_vec(),
            <[u8; 64]>::from(authorized.authorization().binding_signature()),
        ))
    }

    /// Build a **payment** shielded transaction with change: spend `note`, pay
    /// `amount` to `recipient`, return the remainder minus `fee` to `change_addr`
    /// (the sender's own address), and leave `fee` as the public `value_balance`
    /// collected by the miner. This is the real wallet spend shape — unlike
    /// [`build_spend_bundle`], the sender keeps the change instead of burning it
    /// into an oversized fee.
    ///
    /// Requires `note.value == amount + change + fee`; the caller (the wallet
    /// facade) sizes `change` from the selected note. Proven and signed with the
    /// sender's spend authority over the sighash.
    #[allow(clippy::too_many_arguments)]
    pub fn build_payment_bundle(
        pk: &ProvingKey,
        keys: &ShieldedKeys,
        note: Note,
        merkle_path: MerklePath,
        recipient: Address,
        amount: u64,
        change_addr: Address,
        fee: u64,
        network_domain: &[u8; 32],
        tx_context: &[u8],
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<ShieldedBundle, BuildError> {
        let change = note.value().inner().checked_sub(amount).and_then(|v| v.checked_sub(fee)).ok_or(BuildError::Empty)?;

        let anchor = merkle_path.root(ExtractedNoteCommitment::from(note.commitment()));
        let mut builder = Builder::new(BundleType::DEFAULT, anchor);
        builder.add_spend(keys.fvk.clone(), note, merkle_path).map_err(|e| BuildError::Builder(format!("{e:?}")))?;
        builder
            .add_output(None, recipient, NoteValue::from_raw(amount), [0u8; 512])
            .map_err(|e| BuildError::Builder(format!("{e:?}")))?;
        // The change output back to the sender keeps the remainder shielded. Even a
        // zero-value change output is a real note, preserving a uniform 2-output
        // shape (better for privacy than a variable output count).
        builder
            .add_output(None, change_addr, NoteValue::from_raw(change), [0u8; 512])
            .map_err(|e| BuildError::Builder(format!("{e:?}")))?;

        let (unauth, _meta) =
            builder.build::<i64>(&mut rng).map_err(|e| BuildError::Builder(format!("{e:?}")))?.ok_or(BuildError::Empty)?;
        let proven = unauth.create_proof(pk, &mut rng).map_err(|e| BuildError::Proof(format!("{e:?}")))?;

        let effects = to_wire(&proven, |_| [0u8; 64], Vec::new(), [0u8; 64]);
        let msg = sighash(&effects, network_domain, tx_context);
        let ask = SpendAuthorizingKey::from(&keys.sk);
        let authorized: Bundle<Authorized, i64> =
            proven.apply_signatures(&mut rng, msg, &[ask]).map_err(|e| BuildError::Proof(format!("{e:?}")))?;

        Ok(to_wire(
            &authorized,
            |a| <[u8; 64]>::from(a.authorization()),
            authorized.authorization().proof().as_ref().to_vec(),
            <[u8; 64]>::from(authorized.authorization().binding_signature()),
        ))
    }

    /// End-to-end wallet helper: build a real, proven spend of a coinbase note
    /// that is the SINGLE leaf (position 0) of the finalized global tree, and
    /// return the shielded-bundle wire bytes ready to drop into a version-2
    /// transaction's `payload`.
    ///
    /// The note is reconstructed from its public coinbase description exactly as
    /// consensus recomputes it (`derive_coinbase_note_desc` over
    /// `coinbase_txid || out_index`), so the wallet and consensus agree on the
    /// commitment. The witness is the single-leaf authentication path, so the
    /// bundle's anchor equals the minting block's (finalized) anchor. Builds its
    /// own `ProvingKey`; this is a heavy call (real Halo 2 proof).
    #[allow(clippy::too_many_arguments)]
    pub fn build_singleleaf_coinbase_spend(
        owner_seed: [u8; 32],
        coinbase_txid: [u8; 32],
        out_index: u32,
        note_value: u64,
        recipient_addr: [u8; 43],
        output_value: u64,
        network_domain: &[u8; 32],
        tx_context: &[u8],
    ) -> Result<Vec<u8>, BuildError> {
        use crate::coinbase::derive_coinbase_note_desc;
        use incrementalmerkletree::{Hashable, Level};
        use orchard::note::{RandomSeed, Rho};
        use orchard::tree::MerkleHashOrchard;

        let keys = ShieldedKeys::from_seed(owner_seed).ok_or(BuildError::Empty)?;

        // Reconstruct the coinbase note deterministically (same derivation consensus uses).
        let mut seed = Vec::with_capacity(36);
        seed.extend_from_slice(&coinbase_txid);
        seed.extend_from_slice(&out_index.to_le_bytes());
        let desc = derive_coinbase_note_desc(keys.address().to_raw_address_bytes(), &seed);
        let rho = Option::<Rho>::from(Rho::from_bytes(&desc.rho)).ok_or(BuildError::Empty)?;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(desc.rseed, &rho)).ok_or(BuildError::Empty)?;
        let note = Option::<Note>::from(Note::from_parts(keys.address(), NoteValue::from_raw(note_value), rho, rseed))
            .ok_or(BuildError::Empty)?;

        // Single-leaf witness: position 0, siblings are the empty-subtree roots.
        let auth_path: [MerkleHashOrchard; 32] =
            core::array::from_fn(|i| <MerkleHashOrchard as Hashable>::empty_root(Level::from(i as u8)));
        let merkle_path = MerklePath::from_parts(0, auth_path);

        let recipient = Option::<Address>::from(Address::from_raw_address_bytes(&recipient_addr)).ok_or(BuildError::Empty)?;
        let pk = ProvingKey::build();
        let wire =
            build_spend_bundle(&pk, &keys, note, merkle_path, recipient, output_value, network_domain, tx_context, rand::rngs::OsRng)?;
        Ok(wire.to_bytes())
    }

    /// End-to-end wallet payment spending one or more **arbitrary** owned notes
    /// (PLAN §2.10): spend every `(note, merkle_path)` in `inputs`, pay `amount` to
    /// `recipient_addr`, return the remainder minus `fee` as change to the sender,
    /// and leave `fee` as the public value balance. Returns the shielded-bundle wire
    /// bytes ready to drop into a version-2 transaction `payload`.
    ///
    /// All inputs must root to the **same finalized anchor** — the caller (a
    /// [`crate::walletdb::WalletDb`]) supplies live witnesses taken at one tree
    /// state, so this holds. Every spend is authorized by the sender's single spend
    /// authority. Builds its own `ProvingKey`; heavy (a real Halo 2 proof whose cost
    /// grows with the number of inputs).
    #[allow(clippy::too_many_arguments)]
    pub fn build_wallet_payment(
        owner_seed: [u8; 32],
        inputs: Vec<(Note, MerklePath)>,
        recipient_addr: [u8; 43],
        amount: u64,
        fee: u64,
        network_domain: &[u8; 32],
        tx_context: &[u8],
    ) -> Result<Vec<u8>, BuildError> {
        let (first_note, first_path) = inputs.first().ok_or(BuildError::Empty)?;
        let keys = ShieldedKeys::from_seed(owner_seed).ok_or(BuildError::Empty)?;
        let recipient = Option::<Address>::from(Address::from_raw_address_bytes(&recipient_addr)).ok_or(BuildError::Empty)?;
        let change_addr = keys.address();

        let total_in: u64 = inputs.iter().map(|(n, _)| n.value().inner()).sum();
        let change = total_in.checked_sub(amount).and_then(|v| v.checked_sub(fee)).ok_or(BuildError::Empty)?;

        // The shared anchor: all supplied witnesses were taken at one tree state.
        let anchor = first_path.root(ExtractedNoteCommitment::from(first_note.commitment()));
        let mut builder = Builder::new(BundleType::DEFAULT, anchor);
        for (note, merkle_path) in inputs {
            builder.add_spend(keys.fvk.clone(), note, merkle_path).map_err(|e| BuildError::Builder(format!("{e:?}")))?;
        }
        builder
            .add_output(None, recipient, NoteValue::from_raw(amount), [0u8; 512])
            .map_err(|e| BuildError::Builder(format!("{e:?}")))?;
        builder
            .add_output(None, change_addr, NoteValue::from_raw(change), [0u8; 512])
            .map_err(|e| BuildError::Builder(format!("{e:?}")))?;

        let pk = ProvingKey::build();
        let mut rng = rand::rngs::OsRng;
        let (unauth, _meta) =
            builder.build::<i64>(&mut rng).map_err(|e| BuildError::Builder(format!("{e:?}")))?.ok_or(BuildError::Empty)?;
        let proven = unauth.create_proof(&pk, &mut rng).map_err(|e| BuildError::Proof(format!("{e:?}")))?;

        let effects = to_wire(&proven, |_| [0u8; 64], Vec::new(), [0u8; 64]);
        let msg = sighash(&effects, network_domain, tx_context);
        let ask = SpendAuthorizingKey::from(&keys.sk);
        let authorized: Bundle<Authorized, i64> =
            proven.apply_signatures(&mut rng, msg, &[ask]).map_err(|e| BuildError::Proof(format!("{e:?}")))?;

        Ok(to_wire(
            &authorized,
            |a| <[u8; 64]>::from(a.authorization()),
            authorized.authorization().proof().as_ref().to_vec(),
            <[u8; 64]>::from(authorized.authorization().binding_signature()),
        )
        .to_bytes())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use incrementalmerkletree::{Hashable, Level};
        use orchard::{
            note::{RandomSeed, Rho},
            tree::MerkleHashOrchard,
        };

        fn canon(seed: u8) -> [u8; 32] {
            let mut b = [0u8; 32];
            b[0] = seed;
            b
        }

        /// The transfer loop: the wallet spends a note it owns and the consensus
        /// verifier accepts the resulting bundle. The note sits alone at position
        /// 0 of the tree, so its authentication path is the empty-subtree roots.
        #[test]
        fn wallet_spend_bundle_verifies() {
            let pk = ProvingKey::build();
            let keys = ShieldedKeys::from_seed([5u8; 32]).expect("valid seed");
            let ctx = b"firecash-spend";

            // A note worth 10_000 owned by the wallet.
            let rho = Option::<Rho>::from(Rho::from_bytes(&canon(1))).unwrap();
            let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(canon(2), &rho)).unwrap();
            let note = Option::<Note>::from(Note::from_parts(keys.address(), NoteValue::from_raw(10_000), rho, rseed)).unwrap();

            // Single-leaf tree at position 0: siblings are the empty-subtree roots.
            let auth_path: [MerkleHashOrchard; 32] =
                core::array::from_fn(|i| <MerkleHashOrchard as Hashable>::empty_root(Level::from(i as u8)));
            let merkle_path = MerklePath::from_parts(0, auth_path);

            let recipient = ShieldedKeys::from_seed([6u8; 32]).unwrap().address();
            let net = [0x11u8; 32];
            let wire =
                build_spend_bundle(&pk, &keys, note, merkle_path, recipient, 8_000, &net, ctx, rand::rngs::OsRng).expect("build");

            let msg = sighash(&wire, &net, ctx);
            crate::verify::verify_bundle(&wire, &msg).expect("wallet spend bundle must verify");
            // Fee = 10_000 spent − 8_000 output = 2_000 (positive value balance).
            assert_eq!(wire.value_balance, 2_000);
        }

        /// The full loop: the wallet builds a real shielded bundle, and the
        /// consensus verifier accepts it under the same sighash.
        #[test]
        fn wallet_built_bundle_verifies() {
            let pk = ProvingKey::build();
            let keys = ShieldedKeys::from_seed([3u8; 32]).expect("valid seed");
            let ctx = b"firecash-wallet-roundtrip";
            let net = [0x22u8; 32];

            let wire = build_output_only_bundle(&pk, keys.address(), 1_000, &net, ctx, rand::rngs::OsRng).expect("build");

            let msg = sighash(&wire, &net, ctx);
            crate::verify::verify_bundle(&wire, &msg).expect("wallet-built bundle must verify");

            // A different tx context must not verify under the wallet's sighash.
            let other = sighash(&wire, &net, b"different-context");
            assert!(crate::verify::verify_bundle(&wire, &other).is_err());

            // A different network domain must not verify either (replay protection):
            // this bundle signed for network `net` is invalid on another chain.
            let other_net = sighash(&wire, &[0x23u8; 32], ctx);
            assert!(crate::verify::verify_bundle(&wire, &other_net).is_err());
        }

        /// Send → receive: a bundle built to a recipient's address is recovered by
        /// that recipient's incoming viewing key (and by no one else's).
        #[test]
        fn scan_recovers_sent_note() {
            let pk = ProvingKey::build();
            let recipient = ShieldedKeys::from_seed([2u8; 32]).expect("valid seed");
            let wire =
                build_output_only_bundle(&pk, recipient.address(), 4242, &[0x33u8; 32], b"ctx", rand::rngs::OsRng).expect("build");

            let ivk = crate::wallet::ivk_from_seed([2u8; 32]).unwrap();
            let received = crate::wallet::scan_bundle(&ivk, &wire);
            assert_eq!(received.len(), 1, "recipient recovers exactly the note sent to it");
            assert_eq!(received[0].value(), 4242);

            // A stranger's viewing key recovers nothing.
            let stranger = crate::wallet::ivk_from_seed([9u8; 32]).unwrap();
            assert!(crate::wallet::scan_bundle(&stranger, &wire).is_empty());
        }
    }
}

#[cfg(feature = "circuit")]
pub use build::{BuildError, ShieldedKeys, build_output_only_bundle, build_payment_bundle, build_spend_bundle, to_wire};
