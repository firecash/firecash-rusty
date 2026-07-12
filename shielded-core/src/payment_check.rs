//! Device-side payment verification — the guard against a malicious prover.
//!
//! In the non-custodial (mobile) flow a daemon builds and proves a payment from the
//! wallet's viewing key, then asks the device to sign it. If the device signs the
//! bare sighash the daemon hands back, a compromised daemon can substitute the
//! sighash of a payment to *itself* — the device would be blind-signing. This module
//! lets the device instead verify, from the daemon's disclosure and the unsigned
//! bundle, that the payment really is the one the user asked for, using only note and
//! value commitments — no proving circuit, so it is available to a WASM light wallet.

use crate::bundle::ShieldedBundle;
use orchard::{
    Address,
    keys::{FullViewingKey, Scope},
    note::{ExtractedNoteCommitment, Note},
    value::NoteValue,
};

/// What the prover must disclose about one action so the device can check the
/// payment **before** signing it. Every field is already in the PCZT the prover
/// built; disclosing them lets the device recompute the action's note commitment
/// and value commitment and compare them against the bundle it is about to
/// authorize. Without this the device signs a bare 32-byte hash it cannot
/// interpret — and a malicious prover can get a signature over a payment to
/// itself (blind signing).
///
/// None of it is secret to the device: it is the plaintext of a payment the
/// device's own key is about to authorize.
#[derive(Clone, Copy, Debug)]
pub struct ActionDisclosure {
    /// Value of the note this action spends (0 for a padding dummy).
    pub spend_value: u64,
    /// Value of the note this action creates.
    pub out_value: u64,
    /// Raw address the created note pays.
    pub out_recipient: [u8; 43],
    /// The created note's random seed — with the recipient, value and rho it
    /// reproduces the note commitment exactly.
    pub out_rseed: [u8; 32],
    /// Value-commitment trapdoor, so `cv_net` can be recomputed from the values.
    pub rcv: [u8; 32],
}

/// Why a device refused to sign a prepared payment. Every variant means the prover
/// handed over a bundle that does not match the payment the user asked for — i.e. a
/// buggy or malicious daemon — and the device must not sign.
#[derive(Debug, PartialEq, Eq)]
pub enum PaymentCheckError {
    /// Disclosure does not cover every action in the bundle.
    ActionCountMismatch,
    /// An action's output note commitment does not match the disclosed
    /// (recipient, value, rseed): the bundle pays something other than what the
    /// prover claims.
    CommitmentMismatch(usize),
    /// An action's `cv_net` does not match the disclosed values: the prover lied
    /// about an amount.
    ValueCommitmentMismatch(usize),
    /// Spends minus outputs does not equal the bundle's public value balance.
    ValueImbalance,
    /// The public value balance is not the fee the user agreed to.
    FeeMismatch { got: i64, want: u64 },
    /// No action pays the intended recipient the intended amount.
    RecipientNotPaid,
    /// The bundle pays someone who is neither the recipient nor this wallet.
    UnexpectedRecipient(usize),
    /// A disclosed field is not a valid Orchard value.
    Malformed(usize),
}

impl core::fmt::Display for PaymentCheckError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ActionCountMismatch => write!(f, "prover disclosed the wrong number of actions"),
            Self::CommitmentMismatch(i) => write!(f, "action {i}: the note it creates is not the one disclosed"),
            Self::ValueCommitmentMismatch(i) => write!(f, "action {i}: value commitment does not match the disclosed amounts"),
            Self::ValueImbalance => write!(f, "spends minus outputs does not equal the bundle's value balance"),
            Self::FeeMismatch { got, want } => write!(f, "bundle pays a fee of {got}, not the {want} agreed"),
            Self::RecipientNotPaid => write!(f, "no output pays the intended recipient the intended amount"),
            Self::UnexpectedRecipient(i) => write!(f, "action {i} pays an address that is neither the recipient nor this wallet"),
            Self::Malformed(i) => write!(f, "action {i}: disclosed note fields are not valid"),
        }
    }
}

/// **The device's guard against a malicious prover.** Verifies that `wire` — the
/// unsigned bundle a daemon prepared — really is the payment the user asked for,
/// using only the wallet's own viewing key and the prover's disclosure. Call this
/// before signing anything; on `Ok`, sign the sighash **recomputed locally** from
/// `wire`, never a hash the prover supplies.
///
/// The prover cannot lie about anything that matters:
///
/// - Each action's output note commitment (`cmx`) is recomputed from the disclosed
///   `(recipient, value, rseed)` and rho (= that action's nullifier). `cmx` is in
///   the bundle and binds the note, so a hidden output paying an attacker cannot
///   masquerade as a zero-value dummy.
/// - Each `cv_net` is recomputed from the disclosed values and `rcv`, so the amounts
///   are pinned too.
/// - The declared values must sum to the bundle's public `value_balance`, which must
///   be exactly the agreed fee.
/// - Every created note must therefore pay either the intended recipient (exactly
///   once, exactly `amount`) or this wallet (change), or be worth zero.
///
/// A prover that forges any of these produces a bundle whose proof consensus
/// rejects, so the worst it can do is waste its own time.
pub fn check_prepared_payment(
    wire: &ShieldedBundle,
    disclosure: &[ActionDisclosure],
    fvk: &FullViewingKey,
    to: &[u8; 43],
    amount: u64,
    fee: u64,
) -> Result<(), PaymentCheckError> {
    use orchard::{
        note::{RandomSeed, Rho},
        value::{ValueCommitTrapdoor, ValueCommitment},
    };

    if disclosure.len() != wire.actions.len() {
        return Err(PaymentCheckError::ActionCountMismatch);
    }
    let mine = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();

    let mut spent_total: i128 = 0;
    let mut out_total: i128 = 0;
    let mut paid_recipient = 0usize;

    for (i, (act, d)) in wire.actions.iter().zip(disclosure).enumerate() {
        // rho of the note an action creates IS the nullifier of the note it spends,
        // and the wire carries that nullifier — so the device derives rho from the
        // bundle itself, not from anything the prover asserts.
        let rho = Option::<Rho>::from(Rho::from_bytes(&act.nullifier)).ok_or(PaymentCheckError::Malformed(i))?;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(d.out_rseed, &rho)).ok_or(PaymentCheckError::Malformed(i))?;
        let recipient =
            Option::<Address>::from(Address::from_raw_address_bytes(&d.out_recipient)).ok_or(PaymentCheckError::Malformed(i))?;
        let out_value = NoteValue::from_raw(d.out_value);
        let note = Option::<Note>::from(Note::from_parts(recipient, out_value, rho, rseed)).ok_or(PaymentCheckError::Malformed(i))?;

        // (1) The note this action really creates is the note the prover disclosed.
        if ExtractedNoteCommitment::from(note.commitment()).to_bytes() != act.cmx {
            return Err(PaymentCheckError::CommitmentMismatch(i));
        }

        // (2) ...and it moves exactly the disclosed amounts.
        let rcv =
            Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes(d.rcv)).ok_or(PaymentCheckError::Malformed(i))?;
        let spend_value = NoteValue::from_raw(d.spend_value);
        if ValueCommitment::derive(spend_value - out_value, rcv).to_bytes() != act.cv_net {
            return Err(PaymentCheckError::ValueCommitmentMismatch(i));
        }

        // (3) Every created note goes to the recipient, back to us, or nowhere.
        if d.out_recipient == *to && d.out_value == amount {
            paid_recipient += 1;
        } else if d.out_recipient != mine && d.out_value != 0 {
            return Err(PaymentCheckError::UnexpectedRecipient(i));
        }

        spent_total += d.spend_value as i128;
        out_total += d.out_value as i128;
    }

    // (4) Nothing leaks: what we spend, minus what the notes above carry, is the fee.
    let balance = spent_total - out_total;
    if balance != wire.value_balance as i128 {
        return Err(PaymentCheckError::ValueImbalance);
    }
    if wire.value_balance != fee as i64 {
        return Err(PaymentCheckError::FeeMismatch { got: wire.value_balance, want: fee });
    }
    if paid_recipient == 0 {
        return Err(PaymentCheckError::RecipientNotPaid);
    }
    Ok(())
}
