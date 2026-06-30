//! Cryptographic verification of a shielded bundle — the audit-critical layer
//! (PLAN §2.1, §3; non-negotiable #4 in §5).
//!
//! A bundle is *sound* iff three independent checks pass. Together they are what
//! make the private value layer trustworthy: no value is created, every spent
//! note really exists and is authorized, and nothing can be replayed.
//!
//! 1. **Balance (no inflation).** The binding signature verifies under the
//!    *binding validating key*
//!    ```text
//!    bvk = ( Σ_actions cv_net )  −  ValueCommit(value_balance, 0)
//!    ```
//!    Value commitments are Pedersen commitments `cv = [v]·V + [rcv]·R`, additively
//!    homomorphic in both the value `v` and the trapdoor `rcv`. So
//!    `Σ cv_net = [Σv]·V + [Σrcv]·R`, and subtracting `ValueCommit(value_balance,0)
//!    = [value_balance]·V` leaves `[Σv − value_balance]·V + [Σrcv]·R`. The binding
//!    signature is a Schnorr signature whose public key is `bvk` and whose secret
//!    key the prover only knows when the `V` component vanishes, i.e. when
//!    `Σ v_net = value_balance`. A valid binding signature therefore *proves the
//!    bundle balances* — the homomorphic anti-inflation guarantee (§2.6).
//!
//! 2. **Membership + authority + nullifier integrity (the Halo 2 proof).** For
//!    each action the action circuit proves, in zero knowledge, that: the spent
//!    note's commitment is in the note-commitment tree with root `anchor`; the
//!    spender knows the spend authority (`rk = ak + [α]·G`); the value commitment
//!    `cv_net` opens to `v_old − v_new`; the new commitment `cmx` is well formed;
//!    and the revealed nullifier `nf` is the correct PRF output for the spent
//!    note. Verified by `Proof::verify` against the per-action public inputs
//!    (`Instance`). This is the part a missing constraint broke in Orchard for
//!    four years — we verify against the audited upstream circuit, unmodified.
//!
//! 3. **Spend authorization.** Each action's `spend_auth_sig` verifies under its
//!    randomized key `rk` over the [`sighash`], binding the authorization to this
//!    exact bundle and transaction.
//!
//! ## Encoding consensus rules (Zcash April-2026 disclosure; spec §5.4.9.4)
//!
//! Every action's randomized key `rk` and ephemeral key `epk` MUST encode
//! non-identity points on Pallas. A crafted identity `rk` could panic a verifier
//! and split consensus (it did, latently, across zcashd/Zebra). We reject such
//! bundles while parsing, before any proof work.

use blake2b_simd::Params;

use crate::bundle::ShieldedBundle;

/// Personalization for the shielded-transaction sighash (must be 16 bytes).
const SIGHASH_PERSONALIZATION: &[u8; 16] = b"kasprivate_sigh1";

/// Why a shielded bundle failed cryptographic verification. Any of these makes
/// the carrying transaction invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleVerifyError {
    /// The bundle carries no actions.
    NoActions,
    /// A 32-byte field was not a canonical encoding of its type.
    NonCanonicalField(&'static str),
    /// An action's randomized key `rk` is the identity point (consensus rule).
    IdentityRk,
    /// An action's ephemeral key `epk` is the identity point (consensus rule).
    IdentityEpk,
    /// The flags byte has bits set outside the two defined flags (non-canonical).
    NonCanonicalFlags,
    /// The proof length is not the canonical length for this action count
    /// (rejects padded / malleated proofs).
    BadProofLength { expected: usize, got: usize },
    /// The Halo 2 proof did not verify.
    ProofInvalid,
    /// The binding signature did not verify (the bundle does not balance).
    BindingSigInvalid,
    /// An action's spend-authorization signature did not verify.
    SpendAuthSigInvalid(usize),
}

/// The canonical message that a shielded bundle's spend-auth and binding
/// signatures commit to.
///
/// It is a BLAKE2b-256 commitment to the bundle's **effects** — every field
/// except the proof and the signatures themselves (which sign this digest, so
/// including them would be circular) — together with the caller-supplied
/// `tx_context`. Committing to the effects (nullifiers, note commitments, value
/// commitments, `rk`, ciphertexts, anchor, value balance, flags) binds the
/// signatures to *this* bundle; `tx_context` (e.g. the transaction's version,
/// subnetwork, lock-time and gas) binds them to *this* transaction, so a valid
/// bundle cannot be lifted into a different one.
pub fn sighash(bundle: &ShieldedBundle, tx_context: &[u8]) -> [u8; 32] {
    let mut h = Params::new().hash_length(32).personal(SIGHASH_PERSONALIZATION).to_state();
    h.update(&[bundle.flags]);
    h.update(&bundle.value_balance.to_le_bytes());
    h.update(&bundle.anchor);
    h.update(&(bundle.actions.len() as u32).to_le_bytes());
    for a in &bundle.actions {
        h.update(&a.nullifier);
        h.update(&a.rk);
        h.update(&a.cmx);
        h.update(&a.cv_net);
        h.update(&a.ephemeral_key);
        h.update(&a.enc_ciphertext);
        h.update(&a.out_ciphertext);
        // NB: spend_auth_sig is intentionally excluded — it signs this digest.
    }
    h.update(&(tx_context.len() as u32).to_le_bytes());
    h.update(tx_context);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

#[cfg(feature = "circuit")]
mod circuit_verify {
    use super::*;
    use group::{Group, GroupEncoding};
    use orchard::{
        circuit::{Instance, VerifyingKey},
        note::{ExtractedNoteCommitment, Nullifier},
        primitives::redpallas::{Binding, Signature, SpendAuth, VerificationKey},
        tree::Anchor,
        value::ValueCommitment,
        Proof,
    };
    use pasta_curves::pallas;
    use std::sync::OnceLock;

    /// The Orchard action-circuit verifying key. Building it is expensive (it
    /// regenerates the circuit's verifying key), so it is built once and cached.
    /// Pinned to the audited upstream circuit version (PLAN §5).
    pub fn verifying_key() -> &'static VerifyingKey {
        static VK: OnceLock<VerifyingKey> = OnceLock::new();
        VK.get_or_init(VerifyingKey::build)
    }

    /// Verify a shielded bundle's full cryptography against `sighash` using the
    /// cached verifying key. See the module docs for the three checks and the
    /// encoding rules. Returns `Ok(())` iff the bundle is sound.
    pub fn verify_bundle(bundle: &ShieldedBundle, sighash: &[u8; 32]) -> Result<(), BundleVerifyError> {
        verify_bundle_with_vk(bundle, sighash, verifying_key())
    }

    /// As [`verify_bundle`], but with a caller-provided verifying key (e.g. for
    /// batching across many bundles without re-fetching the static).
    pub fn verify_bundle_with_vk(
        bundle: &ShieldedBundle,
        sighash: &[u8; 32],
        vk: &VerifyingKey,
    ) -> Result<(), BundleVerifyError> {
        if bundle.actions.is_empty() {
            return Err(BundleVerifyError::NoActions);
        }

        let anchor: Anchor = Option::from(Anchor::from_bytes(bundle.anchor)).ok_or(BundleVerifyError::NonCanonicalField("anchor"))?;
        // Orchard flag bits: bit 0 = spends enabled, bit 1 = outputs enabled. Any
        // other bit set is a non-canonical encoding (matches Orchard `Flags::from_byte`).
        if bundle.flags & !0b11 != 0 {
            return Err(BundleVerifyError::NonCanonicalFlags);
        }
        let enable_spend = bundle.flags & 0b01 != 0;
        let enable_output = bundle.flags & 0b10 != 0;

        let mut instances = Vec::with_capacity(bundle.actions.len());
        let mut rks = Vec::with_capacity(bundle.actions.len());
        let mut cv_sum: Option<ValueCommitment> = None;

        for a in &bundle.actions {
            let nf: Nullifier = Option::from(Nullifier::from_bytes(&a.nullifier)).ok_or(BundleVerifyError::NonCanonicalField("nullifier"))?;
            let cmx: ExtractedNoteCommitment =
                Option::from(ExtractedNoteCommitment::from_bytes(&a.cmx)).ok_or(BundleVerifyError::NonCanonicalField("cmx"))?;
            let cv_net: ValueCommitment = Option::from(ValueCommitment::from_bytes(&a.cv_net)).ok_or(BundleVerifyError::NonCanonicalField("cv_net"))?;
            let rk = VerificationKey::<SpendAuth>::try_from(a.rk).map_err(|_| BundleVerifyError::NonCanonicalField("rk"))?;

            // Consensus encoding rules (April-2026 disclosure): rk and epk must be
            // non-identity points, else a verifier could panic / consensus split.
            if rk.is_identity() {
                return Err(BundleVerifyError::IdentityRk);
            }
            let epk: pallas::Point =
                Option::from(pallas::Point::from_bytes(&a.ephemeral_key)).ok_or(BundleVerifyError::NonCanonicalField("epk"))?;
            if bool::from(epk.is_identity()) {
                return Err(BundleVerifyError::IdentityEpk);
            }

            // `Instance::from_parts` itself returns None on an identity rk — a
            // second, independent line of defence against the same bug class.
            let instance = Instance::from_parts(anchor, cv_net.clone(), nf, rk.clone(), cmx, enable_spend, enable_output)
                .ok_or(BundleVerifyError::IdentityRk)?;
            instances.push(instance);

            cv_sum = Some(match cv_sum.take() {
                None => cv_net,
                Some(acc) => acc + &cv_net,
            });
            rks.push(rk);
        }

        // --- Check 2: the Halo 2 proof. Reject non-canonical (padded) proofs first. ---
        let expected = Proof::expected_proof_size(bundle.actions.len());
        if bundle.proof.len() != expected {
            return Err(BundleVerifyError::BadProofLength { expected, got: bundle.proof.len() });
        }
        let proof = Proof::new(bundle.proof.clone());
        proof.verify(vk, &instances).map_err(|_| BundleVerifyError::ProofInvalid)?;

        // --- Check 1: balance via the binding signature. ---
        // bvk = Σ cv_net − ValueCommit(value_balance, 0), reinterpreted as a
        // RedPallas verification key (this is exactly Orchard's into_bvk).
        let cv_sum = cv_sum.expect("actions are non-empty");
        let vb_commit = crate::turnstile::commit(bundle.value_balance, crate::turnstile::zero_trapdoor());
        let bvk_point = cv_sum - vb_commit;
        let bvk = VerificationKey::<Binding>::try_from(bvk_point.to_bytes())
            .map_err(|_| BundleVerifyError::BindingSigInvalid)?;
        let binding_sig = Signature::<Binding>::from(bundle.binding_sig);
        bvk.verify(sighash, &binding_sig).map_err(|_| BundleVerifyError::BindingSigInvalid)?;

        // --- Check 3: per-action spend authorization. ---
        for (i, (a, rk)) in bundle.actions.iter().zip(rks.iter()).enumerate() {
            let sig = Signature::<SpendAuth>::from(a.spend_auth_sig);
            rk.verify(sighash, &sig).map_err(|_| BundleVerifyError::SpendAuthSigInvalid(i))?;
        }

        Ok(())
    }
}

#[cfg(feature = "circuit")]
pub use circuit_verify::{verify_bundle, verify_bundle_with_vk, verifying_key};

/// Gold-standard end-to-end validation of the cryptographic verifier: build a
/// *real* Orchard bundle (real Halo 2 proof + real RedPallas signatures over our
/// sighash), serialize it to our wire format, and confirm [`verify_bundle`]
/// accepts it and rejects tampering. This is the test that proves the
/// verification math is actually correct (it requires the `circuit` feature, and
/// is expensive: it builds a proving key and produces a real proof).
#[cfg(all(test, feature = "circuit"))]
mod e2e {
    use super::*;
    use crate::bundle::{ActionWire, ShieldedBundle};
    use orchard::{
        builder::{Builder, BundleType},
        bundle::{Authorization, Authorized},
        circuit::ProvingKey,
        keys::{FullViewingKey, Scope, SpendingKey},
        value::NoteValue,
        Action, Anchor, Bundle,
    };

    /// Extract the effect fields shared by proven and authorized bundles, with a
    /// caller-supplied per-action spend-auth signature and bundle-level proof /
    /// binding signature (zeroed when only the sighash is needed).
    fn build_wire<T: Authorization>(
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

    #[test]
    fn real_bundle_verifies_and_rejects_tampering() {
        let mut rng = rand::rngs::OsRng;
        let ctx = b"kasprivate-e2e-tx-context";

        // 1. Keys + an output-only bundle (dummy spends are auto-signed), anchored
        //    at the empty tree (no real spend, so no Merkle path needed).
        let pk = ProvingKey::build();
        let sk: SpendingKey = Option::from(SpendingKey::from_bytes([7u8; 32])).expect("valid spending key");
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);

        let mut builder = Builder::new(BundleType::DEFAULT, Anchor::empty_tree());
        builder.add_output(None, recipient, NoteValue::from_raw(5000), [0u8; 512]).unwrap();
        let (unauth, _meta) = builder.build::<i64>(&mut rng).unwrap().unwrap();

        // 2. Produce the real Halo 2 proof.
        let proven = unauth.create_proof(&pk, &mut rng).unwrap();

        // 3. Compute our sighash over the bundle effects (sigs/proof excluded, so
        //    placeholders are fine here).
        let effects_wire = build_wire(&proven, |_| [0u8; 64], Vec::new(), [0u8; 64]);
        let msg = sighash(&effects_wire, ctx);

        // 4. Sign over our sighash (no real spend keys: output-only dummy spends).
        let authorized: Bundle<Authorized, i64> = proven.apply_signatures(&mut rng, msg, &[]).unwrap();

        // 5. Serialize the fully authorized bundle to our wire format.
        let wire = build_wire(
            &authorized,
            |a| <[u8; 64]>::from(a.authorization()),
            authorized.authorization().proof().as_ref().to_vec(),
            <[u8; 64]>::from(authorized.authorization().binding_signature()),
        );
        // Signing does not change the effects, so the sighash is stable.
        assert_eq!(sighash(&wire, ctx), msg, "effects unchanged by signing");

        // 6. THE validation: the real bundle verifies.
        verify_bundle(&wire, &msg).expect("a valid Orchard bundle must verify");

        // 7. Tamper detection.
        let mut bad_proof = wire.clone();
        bad_proof.proof[0] ^= 1;
        assert_eq!(verify_bundle(&bad_proof, &msg), Err(BundleVerifyError::ProofInvalid));

        let mut bad_balance = wire.clone();
        bad_balance.value_balance += 1; // breaks the binding-signature balance
        assert_eq!(verify_bundle(&bad_balance, &msg), Err(BundleVerifyError::BindingSigInvalid));

        let mut bad_sig = wire.clone();
        bad_sig.actions[0].spend_auth_sig[0] ^= 1;
        assert!(matches!(verify_bundle(&bad_sig, &msg), Err(BundleVerifyError::SpendAuthSigInvalid(0))));

        let mut bad_cv = wire.clone();
        bad_cv.actions[0].cv_net[0] ^= 1; // a different canonical point breaks proof+balance
        assert!(verify_bundle(&bad_cv, &msg).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{sizes, ActionWire};

    fn action(seed: u8) -> ActionWire {
        ActionWire {
            nullifier: [seed; sizes::FIELD],
            rk: [seed.wrapping_add(1); sizes::FIELD],
            cmx: [seed.wrapping_add(2); sizes::FIELD],
            cv_net: [seed.wrapping_add(3); sizes::FIELD],
            ephemeral_key: [seed.wrapping_add(4); sizes::FIELD],
            enc_ciphertext: [seed.wrapping_add(5); sizes::ENC_CIPHERTEXT],
            out_ciphertext: [seed.wrapping_add(6); sizes::OUT_CIPHERTEXT],
            spend_auth_sig: [seed.wrapping_add(7); sizes::SIG],
        }
    }

    fn bundle(n: u8) -> ShieldedBundle {
        ShieldedBundle {
            actions: (0..n).map(action).collect(),
            flags: 0b11,
            value_balance: 7,
            anchor: [1u8; 32],
            proof: vec![0u8; 100],
            binding_sig: [0u8; 64],
        }
    }

    #[test]
    fn sighash_is_deterministic_and_effect_sensitive() {
        let b = bundle(2);
        let s1 = sighash(&b, b"ctx");
        let s2 = sighash(&b, b"ctx");
        assert_eq!(s1, s2, "sighash is deterministic");

        // Changing any effect changes the sighash.
        let mut b2 = b.clone();
        b2.value_balance += 1;
        assert_ne!(sighash(&b2, b"ctx"), s1);

        let mut b3 = b.clone();
        b3.actions[0].cmx[0] ^= 1;
        assert_ne!(sighash(&b3, b"ctx"), s1);

        // Changing tx context changes the sighash.
        assert_ne!(sighash(&b, b"other"), s1);
    }

    /// The spend-auth signature is excluded from the sighash (it signs it), so
    /// flipping a signature byte must NOT change the sighash.
    #[test]
    fn sighash_excludes_authorizing_data() {
        let b = bundle(1);
        let s = sighash(&b, b"");
        let mut b2 = b.clone();
        b2.actions[0].spend_auth_sig[0] ^= 1;
        b2.binding_sig[0] ^= 1;
        b2.proof[0] ^= 1;
        assert_eq!(sighash(&b2, b""), s, "sighash must not cover proof/signatures");
    }
}
