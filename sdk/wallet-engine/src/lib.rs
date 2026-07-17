//! Transport-independent wallet policy and state machinery for ZKas.
//!
//! This crate is the reusable layer underneath walletd, native applications and
//! future WASM/mobile bindings. It deliberately has no HTTP, node-RPC, UI or
//! runtime dependency. Those are adapters around this engine.

pub mod payment;

pub use payment::{
    DEFAULT_FEE_SOMPI, PaymentChunk, PaymentPlan, PlanError, chunk_fee, max_spends_per_tx, min_relay_fee_for_spends, plan_payment,
    select_spend_count,
};
