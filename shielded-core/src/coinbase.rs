//! Coinbase note issuance — the one transparent seam (PLAN §2.7).
//!
//! Mining rewards are created from nothing, so a coinbase note has no input note
//! to prove. Instead it is a note commitment with a **publicly stated value** —
//! the block subsidy, which consensus checks against the emission schedule. The
//! coinbase transaction states the note's recipient and randomness publicly, so
//! consensus can **deterministically recompute** the note commitment and add it
//! to the global tree. After the miner spends it once (with a normal Orchard
//! proof) it is indistinguishable from any other note.
//!
//! ## Why this is sound
//!
//! For a *private* output, the value is hidden and is bound to the bundle by the
//! binding signature. A coinbase note is different: its value is **public**, and
//! consensus recomputes the commitment from `(recipient, value, ρ, rseed)`. The
//! commitment is a binding commitment to the value, so a miner cannot have the
//! recorded commitment open to anything other than the stated subsidy — there is
//! no freedom to mint extra value into the note. The subsidy enters the turnstile
//! accounting exactly once, as `cumulative_coinbase += subsidy` (§2.6).
//!
//! `ρ` (rho) must be unique per coinbase note so that the note's eventual
//! nullifier is unique; consensus derives it deterministically from the coinbase
//! transaction (e.g. its id), which this module treats as an opaque input.

use orchard::{
    note::{ExtractedNoteCommitment, Note, RandomSeed, Rho},
    value::NoteValue,
    Address,
};

use crate::state::CoinbaseMint;

/// The public description of a coinbase note: everything besides the public value
/// (the subsidy) needed to recompute its commitment. Carried by the coinbase
/// transaction; consensus supplies the subsidy from the emission schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseNoteDesc {
    /// Raw Orchard address of the reward recipient (the miner).
    pub recipient: [u8; 43],
    /// The note's `ρ`, derived deterministically from the coinbase transaction so
    /// that the resulting note (and its future nullifier) is unique.
    pub rho: [u8; 32],
    /// The note's random seed.
    pub rseed: [u8; 32],
}

/// Why a coinbase note description could not be turned into a commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinbaseNoteError {
    /// `recipient` is not a canonical Orchard address.
    BadRecipient,
    /// `rho` is not a canonical encoding.
    BadRho,
    /// `rseed` is not valid for this `rho`.
    BadRseed,
    /// The resulting note has no valid commitment.
    BadNote,
}

/// Recompute the coinbase note's extracted commitment from its public description
/// and public value (the subsidy). Consensus uses this to derive the global-tree
/// leaf and to bind the commitment to the emission-checked subsidy.
pub fn coinbase_note_commitment(desc: &CoinbaseNoteDesc, subsidy: u64) -> Result<ExtractedNoteCommitment, CoinbaseNoteError> {
    let recipient: Address =
        Option::from(Address::from_raw_address_bytes(&desc.recipient)).ok_or(CoinbaseNoteError::BadRecipient)?;
    let rho: Rho = Option::from(Rho::from_bytes(&desc.rho)).ok_or(CoinbaseNoteError::BadRho)?;
    let rseed: RandomSeed = Option::from(RandomSeed::from_bytes(desc.rseed, &rho)).ok_or(CoinbaseNoteError::BadRseed)?;
    let note: Note = Option::from(Note::from_parts(recipient, NoteValue::from_raw(subsidy), rho, rseed))
        .ok_or(CoinbaseNoteError::BadNote)?;
    Ok(ExtractedNoteCommitment::from(note.commitment()))
}

/// Build the [`CoinbaseMint`] for the shielded state transition from a coinbase
/// note description and the emission-checked subsidy.
pub fn coinbase_mint(desc: &CoinbaseNoteDesc, subsidy: u64) -> Result<CoinbaseMint, CoinbaseNoteError> {
    Ok(CoinbaseMint { subsidy, commitment: coinbase_note_commitment(desc, subsidy)? })
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};

    fn canon32(seed: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = seed;
        b
    }

    fn test_recipient() -> Address {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([9u8; 32])).expect("valid sk");
        FullViewingKey::from(&sk).address_at(0u32, Scope::External)
    }

    /// Our consensus-side recomputation yields exactly the commitment Orchard's
    /// own `Note::commitment` produces — so a node and the miner agree on the leaf.
    #[test]
    fn matches_orchard_note_commitment() {
        let recipient = test_recipient();
        let rho: Rho = Option::from(Rho::from_bytes(&canon32(1))).unwrap();
        let rseed: RandomSeed = Option::from(RandomSeed::from_bytes(canon32(2), &rho)).unwrap();
        let subsidy = 5_000_000_000u64;

        let note: Note = Option::from(Note::from_parts(recipient, NoteValue::from_raw(subsidy), rho, rseed)).unwrap();
        let expected = ExtractedNoteCommitment::from(note.commitment());

        let desc = CoinbaseNoteDesc { recipient: recipient.to_raw_address_bytes(), rho: canon32(1), rseed: canon32(2) };
        let got = coinbase_note_commitment(&desc, subsidy).unwrap();
        assert_eq!(got.to_bytes(), expected.to_bytes());
    }

    /// The commitment is deterministic and **binds the public value**: changing
    /// the subsidy changes the commitment, so a miner cannot claim a value other
    /// than the one consensus checked against emission.
    #[test]
    fn deterministic_and_binds_value() {
        let desc = CoinbaseNoteDesc { recipient: test_recipient().to_raw_address_bytes(), rho: canon32(1), rseed: canon32(2) };
        let a = coinbase_note_commitment(&desc, 100).unwrap();
        let b = coinbase_note_commitment(&desc, 100).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes(), "deterministic");
        let c = coinbase_note_commitment(&desc, 101).unwrap();
        assert_ne!(a.to_bytes(), c.to_bytes(), "commitment binds the public value");
    }

    #[test]
    fn rejects_bad_recipient() {
        let desc = CoinbaseNoteDesc { recipient: [0xff; 43], rho: canon32(1), rseed: canon32(2) };
        assert!(matches!(coinbase_note_commitment(&desc, 100), Err(CoinbaseNoteError::BadRecipient)));
    }

    /// A coinbase note feeds the state transition as a mint of exactly the subsidy.
    #[test]
    fn coinbase_mint_carries_subsidy() {
        let desc = CoinbaseNoteDesc { recipient: test_recipient().to_raw_address_bytes(), rho: canon32(3), rseed: canon32(4) };
        let mint = coinbase_mint(&desc, 12_345).unwrap();
        assert_eq!(mint.subsidy, 12_345);
    }
}
