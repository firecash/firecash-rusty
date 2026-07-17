//! Software signing policy shared by native and WASM ZKas clients.
//!
//! The signer never proves transactions. It verifies a prover's disclosed
//! payment against the unsigned bundle, recomputes the sighash locally, and only
//! then authorizes the real Orchard spends.

use kaspa_shielded_core::{
    bundle::ShieldedBundle,
    message::{FVK_LEN, SignedMessage, fvk_bytes_from_seed, sign_message, sign_spend_auth_from_seed},
    payment_check::{ActionDisclosure, PaymentCheckError, check_prepared_payment},
    verify::sighash,
    wallet::address_bytes_from_seed,
};
use orchard::keys::FullViewingKey;
use zeroize::Zeroizing;

/// Payment the user explicitly approved in the application UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentIntent {
    pub recipient: [u8; 43],
    pub amount: u64,
    pub fee: u64,
}

/// One real Orchard spend authorization requested by the prover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendAuthRequest {
    pub action_index: usize,
    pub alpha: [u8; 32],
}

/// Versioned, typed material a prover gives to a signer.
///
/// Bindings may encode this as JSON, CBOR, or another versioned wire format, but
/// all of them must construct this type before invoking signing policy.
#[derive(Clone, Debug)]
pub struct PreparedPayment {
    pub version: u16,
    pub network_domain: [u8; 32],
    pub tx_context: Vec<u8>,
    pub bundle: ShieldedBundle,
    pub disclosure: Vec<ActionDisclosure>,
    pub spend_auth: Vec<SpendAuthRequest>,
}

impl PreparedPayment {
    pub const VERSION: u16 = 1;
}

/// Signature returned for one action. The prover/finalizer applies it only at
/// the corresponding action index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceSignature {
    pub action_index: usize,
    pub signature: [u8; 64],
}

#[derive(Debug)]
pub enum SignerError {
    InvalidSeed,
    UnsupportedPreparedVersion(u16),
    WrongNetwork,
    InvalidViewingKey,
    PaymentRejected(PaymentCheckError),
    InvalidSpendRandomizer { action_index: usize },
    DuplicateAction { action_index: usize },
    MissingAction { action_index: usize },
}

impl core::fmt::Display for SignerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSeed => f.write_str("seed is not a valid Orchard spending key"),
            Self::UnsupportedPreparedVersion(version) => write!(f, "unsupported prepared-payment version {version}"),
            Self::WrongNetwork => f.write_str("prepared payment belongs to a different network"),
            Self::InvalidViewingKey => f.write_str("derived full viewing key is invalid"),
            Self::PaymentRejected(error) => write!(f, "refusing to sign: {error}"),
            Self::InvalidSpendRandomizer { action_index } => write!(f, "action {action_index} has an invalid spend randomizer"),
            Self::DuplicateAction { action_index } => write!(f, "action {action_index} is requested more than once"),
            Self::MissingAction { action_index } => write!(f, "bundle action {action_index} does not exist"),
        }
    }
}

impl std::error::Error for SignerError {}

/// In-memory software signer. Bindings should keep this object inside the
/// smallest available security boundary and avoid repeatedly converting seeds
/// to strings. Seed bytes are zeroized when it is dropped.
pub struct SoftwareSigner {
    seed: Zeroizing<[u8; 32]>,
}

impl SoftwareSigner {
    pub fn new(seed: [u8; 32]) -> Result<Self, SignerError> {
        address_bytes_from_seed(seed).ok_or(SignerError::InvalidSeed)?;
        Ok(Self { seed: Zeroizing::new(seed) })
    }

    pub fn address_bytes(&self) -> [u8; 43] {
        address_bytes_from_seed(*self.seed).expect("seed was validated at construction")
    }

    pub fn full_viewing_key(&self) -> [u8; FVK_LEN] {
        fvk_bytes_from_seed(*self.seed).expect("seed was validated at construction")
    }

    pub fn sign_message(&self, domain: &[u8], message: &[u8]) -> SignedMessage {
        sign_message(*self.seed, domain, message, rand::rngs::OsRng).expect("seed was validated at construction")
    }

    /// Verify user intent and authorize a prepared payment. `expected_network`
    /// comes from trusted application configuration, never from the prover.
    pub fn verify_and_sign(
        &self,
        expected_network: &[u8; 32],
        intent: &PaymentIntent,
        prepared: &PreparedPayment,
    ) -> Result<Vec<DeviceSignature>, SignerError> {
        if prepared.version != PreparedPayment::VERSION {
            return Err(SignerError::UnsupportedPreparedVersion(prepared.version));
        }
        if &prepared.network_domain != expected_network {
            return Err(SignerError::WrongNetwork);
        }

        let fvk = FullViewingKey::from_bytes(&self.full_viewing_key()).ok_or(SignerError::InvalidViewingKey)?;
        check_prepared_payment(&prepared.bundle, &prepared.disclosure, &fvk, &intent.recipient, intent.amount, intent.fee)
            .map_err(SignerError::PaymentRejected)?;

        let action_count = prepared.bundle.actions.len();
        let mut seen = vec![false; action_count];
        let message = sighash(&prepared.bundle, &prepared.network_domain, &prepared.tx_context);
        let mut signatures = Vec::with_capacity(prepared.spend_auth.len());
        for request in &prepared.spend_auth {
            if request.action_index >= action_count {
                return Err(SignerError::MissingAction { action_index: request.action_index });
            }
            if core::mem::replace(&mut seen[request.action_index], true) {
                return Err(SignerError::DuplicateAction { action_index: request.action_index });
            }
            let signature = sign_spend_auth_from_seed(*self.seed, request.alpha, message)
                .ok_or(SignerError::InvalidSpendRandomizer { action_index: request.action_index })?;
            signatures.push(DeviceSignature { action_index: request.action_index, signature });
        }
        Ok(signatures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_derives_stable_public_material() {
        let signer = SoftwareSigner::new([7; 32]).unwrap();
        assert_eq!(signer.address_bytes(), address_bytes_from_seed([7; 32]).unwrap());
        assert_eq!(signer.full_viewing_key(), fvk_bytes_from_seed([7; 32]).unwrap());
    }

    #[test]
    fn message_signing_is_bound_to_domain_and_message() {
        use kaspa_shielded_core::message::verify_message;

        let signer = SoftwareSigner::new([9; 32]).unwrap();
        let signed = signer.sign_message(b"zkas-mainnet", b"approved");
        assert!(verify_message(&signed.address, b"zkas-mainnet", b"approved", &signed.fvk, &signed.sig).is_ok());
        assert!(verify_message(&signed.address, b"zkas-mainnet", b"changed", &signed.fvk, &signed.sig).is_err());
    }
}
