//! The on-wire Orchard bundle carried by a shielded transaction (PLAN §2.1).
//!
//! What an observer sees per shielded transaction is a set of **Actions** (each
//! revealing a nullifier, a note commitment `cmx`, and a net value commitment
//! `cv_net`, plus the encrypted note for the receiver and a spend-authorization
//! signature), one Halo 2 **proof**, a **binding signature**, the bundle
//! **flags** and public **value balance**, and a reference to the finalized
//! **anchor** the spends prove against. Amounts, senders and receivers are
//! hidden.
//!
//! # Carriage (decision D7)
//!
//! A shielded transaction carries its bundle in the transaction `payload`,
//! gated by a dedicated transaction version. The payload is already part of the
//! transaction hash, so the bundle is committed by the block merkle root with no
//! change to the `Transaction` struct. This module owns the *canonical* byte
//! encoding used there; it must be deterministic (consensus-critical).
//!
//! This is the wire/representation layer. Converting these bytes into live
//! `orchard` types for proof / binding-signature / value-balance verification is
//! done by the validation layer (a later task), which is where the `orchard`
//! `circuit` feature gets enabled.

use crate::nullifier::NullifierBytes;

// The transaction *version* that selects this wire format is a consensus
// parameter and lives in `kaspa_consensus_core::tx::TX_VERSION_SHIELDED`; this
// crate only owns the byte format of the bundle carried in the payload.

/// Fixed sizes of the cryptographic components, per the Orchard encoding
/// (Zcash protocol spec §7.5). Kept as named constants so the reader/writer and
/// future `orchard`-type conversions agree.
pub mod sizes {
    /// Pallas base/scalar field element or group element encoding.
    pub const FIELD: usize = 32;
    /// Orchard note ciphertext (`enc_ciphertext`).
    pub const ENC_CIPHERTEXT: usize = 580;
    /// Orchard out ciphertext (`out_ciphertext`).
    pub const OUT_CIPHERTEXT: usize = 80;
    /// RedPallas signature (spend-auth and binding).
    pub const SIG: usize = 64;
}

/// Consensus upper bound on the number of Orchard actions a single shielded
/// bundle may carry.
///
/// This is a hard anti-DoS limit, not a style choice. A shielded transaction
/// carries no transparent inputs/outputs, so under KIP-9 it currently has
/// **zero storage mass** (see `consensus/core/src/mass`): nothing at the mass
/// layer bounds how much verification work one transaction can demand. Each
/// action costs one (batched) Halo 2 proof-verification, the single most
/// expensive operation on the validation path (PLAN §2.8). Without a cap, a
/// single near-free transaction could force every node to verify an unbounded
/// proof, and the aggregate over a block would be unbounded. Bounding actions
/// per bundle bounds per-transaction verification cost; block capacity then
/// bounds the rest. 512 is far above any honest bundle (a normal payment has
/// 1–4 actions) while keeping worst-case per-tx proof work finite.
pub const MAX_ACTIONS_PER_BUNDLE: usize = 512;

/// A single Orchard action, as it appears on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionWire {
    /// Nullifier of the note spent by this action (a first-class conflict key).
    pub nullifier: NullifierBytes,
    /// Randomized verification key for the spend-authorization signature (`rk`).
    pub rk: [u8; sizes::FIELD],
    /// Extracted note commitment of the note created by this action (tree leaf).
    pub cmx: [u8; sizes::FIELD],
    /// Net value commitment `cv_net` (homomorphic; feeds the turnstile).
    pub cv_net: [u8; sizes::FIELD],
    /// Ephemeral public key for note encryption (`epk_bytes`).
    pub ephemeral_key: [u8; sizes::FIELD],
    /// Encrypted note plaintext for the receiver.
    pub enc_ciphertext: [u8; sizes::ENC_CIPHERTEXT],
    /// Encrypted note plaintext recoverable with the outgoing viewing key.
    pub out_ciphertext: [u8; sizes::OUT_CIPHERTEXT],
    /// Spend-authorization signature over the action.
    pub spend_auth_sig: [u8; sizes::SIG],
}

impl ActionWire {
    /// Serialized size of one action.
    pub const SERIALIZED_LEN: usize =
        sizes::FIELD * 4 + sizes::ENC_CIPHERTEXT + sizes::OUT_CIPHERTEXT + sizes::SIG;
}

/// An Orchard bundle as carried in a shielded transaction's payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldedBundle {
    /// The actions (merged spend+output units).
    pub actions: Vec<ActionWire>,
    /// Bundle flags (spends-enabled / outputs-enabled bits).
    pub flags: u8,
    /// Public net value balance of the bundle (positive = value leaving the
    /// shielded pool as a fee; negative = value entering, e.g. coinbase).
    pub value_balance: i64,
    /// The finalized anchor the spends prove against (PLAN §2.5).
    pub anchor: [u8; sizes::FIELD],
    /// The Halo 2 proof attesting to the whole bundle.
    pub proof: Vec<u8>,
    /// The binding signature tying the value commitments to `value_balance`.
    pub binding_sig: [u8; sizes::SIG],
}

/// Error decoding a [`ShieldedBundle`] from bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleDecodeError {
    /// Ran out of input before a field was complete.
    UnexpectedEof,
    /// A length prefix exceeded the remaining input (malformed/hostile).
    LengthOverflow,
    /// Trailing bytes remained after decoding.
    TrailingBytes,
    /// The bundle declared more actions than [`MAX_ACTIONS_PER_BUNDLE`]
    /// (anti-DoS: rejected before any parse/verification work is done).
    TooManyActions,
}

/// A minimal canonical byte writer (big-endian length prefixes).
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }
    fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    /// Length-prefixed variable bytes.
    fn var(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.bytes(b);
    }
}

/// A minimal canonical byte reader.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], BundleDecodeError> {
        let end = self.pos.checked_add(n).ok_or(BundleDecodeError::LengthOverflow)?;
        if end > self.buf.len() {
            return Err(BundleDecodeError::UnexpectedEof);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], BundleDecodeError> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, BundleDecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, BundleDecodeError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }
    fn i64(&mut self) -> Result<i64, BundleDecodeError> {
        Ok(i64::from_be_bytes(self.array::<8>()?))
    }
    fn var(&mut self) -> Result<Vec<u8>, BundleDecodeError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn finished(&self) -> bool {
        self.pos == self.buf.len()
    }
}

impl ShieldedBundle {
    /// Encode to the canonical payload byte form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.flags);
        w.i64(self.value_balance);
        w.bytes(&self.anchor);
        w.var(&self.binding_sig);
        w.u32(self.actions.len() as u32);
        for a in &self.actions {
            w.bytes(&a.nullifier);
            w.bytes(&a.rk);
            w.bytes(&a.cmx);
            w.bytes(&a.cv_net);
            w.bytes(&a.ephemeral_key);
            w.bytes(&a.enc_ciphertext);
            w.bytes(&a.out_ciphertext);
            w.bytes(&a.spend_auth_sig);
        }
        w.var(&self.proof);
        w.buf
    }

    /// Decode from canonical payload bytes. Rejects malformed and trailing input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BundleDecodeError> {
        let mut r = Reader::new(bytes);
        let flags = r.u8()?;
        let value_balance = r.i64()?;
        let anchor = r.array::<{ sizes::FIELD }>()?;
        let binding_sig_vec = r.var()?;
        let binding_sig: [u8; sizes::SIG] =
            binding_sig_vec.as_slice().try_into().map_err(|_| BundleDecodeError::UnexpectedEof)?;
        let n_actions = r.u32()? as usize;
        // Anti-DoS: reject an oversized action count up front, before allocating
        // or parsing (bounds per-transaction verification work; see
        // MAX_ACTIONS_PER_BUNDLE). A shielded tx has zero storage mass, so this
        // wire-format cap is what keeps proof-verification cost per tx finite.
        if n_actions > MAX_ACTIONS_PER_BUNDLE {
            return Err(BundleDecodeError::TooManyActions);
        }
        let mut actions = Vec::with_capacity(n_actions);
        for _ in 0..n_actions {
            actions.push(ActionWire {
                nullifier: r.array::<{ sizes::FIELD }>()?,
                rk: r.array::<{ sizes::FIELD }>()?,
                cmx: r.array::<{ sizes::FIELD }>()?,
                cv_net: r.array::<{ sizes::FIELD }>()?,
                ephemeral_key: r.array::<{ sizes::FIELD }>()?,
                enc_ciphertext: r.array::<{ sizes::ENC_CIPHERTEXT }>()?,
                out_ciphertext: r.array::<{ sizes::OUT_CIPHERTEXT }>()?,
                spend_auth_sig: r.array::<{ sizes::SIG }>()?,
            });
        }
        let proof = r.var()?;
        if !r.finished() {
            return Err(BundleDecodeError::TrailingBytes);
        }
        Ok(Self { actions, flags, value_balance, anchor, proof, binding_sig })
    }

    /// The nullifiers revealed by this bundle, in action order (conflict keys).
    pub fn nullifiers(&self) -> impl Iterator<Item = &NullifierBytes> {
        self.actions.iter().map(|a| &a.nullifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_action(seed: u8) -> ActionWire {
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

    fn sample_bundle(n: u8) -> ShieldedBundle {
        ShieldedBundle {
            actions: (0..n).map(sample_action).collect(),
            flags: 0b11,
            value_balance: -123_456,
            anchor: [9u8; sizes::FIELD],
            proof: vec![0xab; 1000],
            binding_sig: [0xcd; sizes::SIG],
        }
    }

    #[test]
    fn round_trips() {
        for n in [0u8, 1, 2, 5] {
            let b = sample_bundle(n);
            let bytes = b.to_bytes();
            let decoded = ShieldedBundle::from_bytes(&bytes).expect("decode");
            assert_eq!(b, decoded);
            // Canonical: re-encoding the decoded value is identical.
            assert_eq!(bytes, decoded.to_bytes());
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = sample_bundle(1).to_bytes();
        bytes.push(0);
        assert_eq!(ShieldedBundle::from_bytes(&bytes), Err(BundleDecodeError::TrailingBytes));
    }

    #[test]
    fn rejects_truncated() {
        let bytes = sample_bundle(2).to_bytes();
        assert_eq!(ShieldedBundle::from_bytes(&bytes[..bytes.len() - 10]), Err(BundleDecodeError::UnexpectedEof));
    }

    #[test]
    fn rejects_hostile_action_count() {
        // flags + value_balance + anchor + binding_sig(len-prefixed) + huge count
        let mut w = Writer::new();
        w.u8(0);
        w.i64(0);
        w.bytes(&[0u8; sizes::FIELD]);
        w.var(&[0u8; sizes::SIG]);
        w.u32(u32::MAX); // claims 4 billion actions
        // Rejected by the anti-DoS action cap before any allocation/parse work.
        assert_eq!(ShieldedBundle::from_bytes(&w.buf), Err(BundleDecodeError::TooManyActions));
    }

    #[test]
    fn rejects_action_count_over_cap() {
        // A count one past the cap is rejected up front; the cap itself decodes
        // structurally (here it fails later on EOF since no action bytes follow).
        let mut w = Writer::new();
        w.u8(0);
        w.i64(0);
        w.bytes(&[0u8; sizes::FIELD]);
        w.var(&[0u8; sizes::SIG]);
        w.u32(MAX_ACTIONS_PER_BUNDLE as u32 + 1);
        assert_eq!(ShieldedBundle::from_bytes(&w.buf), Err(BundleDecodeError::TooManyActions));

        // A real bundle at exactly the cap round-trips (the cap is inclusive).
        let at_cap = ShieldedBundle {
            actions: (0..MAX_ACTIONS_PER_BUNDLE).map(|i| sample_action(i as u8)).collect(),
            flags: 0b11,
            value_balance: 0,
            anchor: [0u8; sizes::FIELD],
            proof: vec![],
            binding_sig: [0u8; sizes::SIG],
        };
        assert_eq!(ShieldedBundle::from_bytes(&at_cap.to_bytes()).map(|b| b.actions.len()), Ok(MAX_ACTIONS_PER_BUNDLE));
    }

    #[test]
    fn nullifiers_iter_in_order() {
        let b = sample_bundle(3);
        let nfs: Vec<_> = b.nullifiers().copied().collect();
        assert_eq!(nfs, vec![[0u8; 32], [1u8; 32], [2u8; 32]]);
    }
}
