//! Wallet-side shielded transaction construction — the prover, the inverse of
//! [`crate::verify`] (PLAN §2.10 / §3 wallet).
//!
//! This is what *produces* a shielded transaction: it derives keys, builds an
//! Orchard bundle, creates the Halo 2 proof, and signs the binding + spend-auth
//! signatures over the kasprivate sighash — emitting a [`ShieldedBundle`] in our
//! canonical wire format, ready to carry in a transaction payload and be
//! accepted by the consensus verifier.
//!
//! The whole module requires the `circuit` feature (proving needs the proving
//! key). Proving is the heavy operation; PLAN §2.10 anticipates GPU-assisted and
//! delegated proving for light wallets — by Orchard's key separation, a delegated
//! prover never gains spend authority. This module is the local-proving core.

#[cfg(feature = "circuit")]
mod build {
    use crate::bundle::{ActionWire, ShieldedBundle};
    use crate::verify::sighash;
    use orchard::{
        builder::{Builder, BundleType},
        bundle::{Authorization, Authorized},
        circuit::ProvingKey,
        keys::{FullViewingKey, Scope, SpendingKey},
        value::NoteValue,
        Action, Address, Anchor, Bundle,
    };
    use rand::{CryptoRng, RngCore};

    /// A wallet's Orchard keys, derived from a 32-byte seed.
    pub struct ShieldedKeys {
        #[allow(dead_code)]
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
        let msg = sighash(&effects, tx_context);
        let authorized: Bundle<Authorized, i64> =
            proven.apply_signatures(&mut rng, msg, &[]).map_err(|e| BuildError::Proof(format!("{e:?}")))?;

        Ok(to_wire(
            &authorized,
            |a| <[u8; 64]>::from(a.authorization()),
            authorized.authorization().proof().as_ref().to_vec(),
            <[u8; 64]>::from(authorized.authorization().binding_signature()),
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The full loop: the wallet builds a real shielded bundle, and the
        /// consensus verifier accepts it under the same sighash.
        #[test]
        fn wallet_built_bundle_verifies() {
            let pk = ProvingKey::build();
            let keys = ShieldedKeys::from_seed([3u8; 32]).expect("valid seed");
            let ctx = b"kasprivate-wallet-roundtrip";

            let wire = build_output_only_bundle(&pk, keys.address(), 1_000, ctx, rand::rngs::OsRng).expect("build");

            let msg = sighash(&wire, ctx);
            crate::verify::verify_bundle(&wire, &msg).expect("wallet-built bundle must verify");

            // A different tx context must not verify under the wallet's sighash.
            let other = sighash(&wire, b"different-context");
            assert!(crate::verify::verify_bundle(&wire, &other).is_err());
        }
    }
}

#[cfg(feature = "circuit")]
pub use build::{build_output_only_bundle, to_wire, BuildError, ShieldedKeys};
