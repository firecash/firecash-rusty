//! Stable public Rust facade for ZKas wallet integrations.
//!
//! Unlike a linear-chain light wallet, ZKas follows Kaspa's selected chain in a
//! BlockDAG. Synchronization therefore uses hash cursors, DAA/blue scores,
//! explicit reorg signals and a settlement margin before Orchard effects are
//! committed to the append-only wallet tree.

pub mod address;
pub mod chain;
pub mod engine;
pub mod network;
pub mod prepared;
pub mod store;

pub use address::{AddressError, ShieldedAddress};
pub use chain::{BlockBatch, ChainIdentity, ChainSource, ChainTip, ShieldedChainBlock, TransactionState};
pub use engine::{SdkError, SyncEvent, SyncReport, Wallet, WalletBalance, WalletConfig};
pub use network::{Network, NetworkConfig};
pub use prepared::{PreparedPaymentV1, WireError};
pub use store::{FileStore, MemoryStore, StoredWallet, WalletStore};
pub use zkas_signer::{DeviceSignature, PaymentIntent, PreparedPayment, SignerError, SoftwareSigner, SpendAuthRequest};
pub use zkas_wallet_engine::{PaymentPlan, PlanError};
