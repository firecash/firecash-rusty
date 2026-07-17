use serde::{Deserialize, Serialize};

/// Supported ZKas network names. Custom networks must supply their own trusted
/// genesis domain through [`NetworkConfig::custom`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
    Simnet,
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkConfig {
    pub network: Network,
    /// Trusted shielded sighash domain (the chain genesis hash).
    pub genesis: [u8; 32],
    /// Hold this many blue-score units behind the sink before committing wallet
    /// effects. The current production default is 200.
    pub settlement_blue_score: u64,
    /// Consensus shielded-anchor maturity depth. Current mainnet value is 600.
    pub anchor_depth: u64,
}

impl NetworkConfig {
    pub const MAINNET_GENESIS: [u8; 32] = [
        0xd6, 0xf3, 0xa5, 0x89, 0xe1, 0x97, 0x2a, 0x65, 0xa8, 0x67, 0x2b, 0xa0, 0x94, 0x67, 0x74, 0x9a, 0xba, 0xe5, 0x20, 0xa5, 0xaf,
        0x2e, 0x5d, 0x1d, 0xee, 0xa7, 0xe4, 0x3d, 0x95, 0x90, 0xa6, 0xc6,
    ];

    pub const fn mainnet() -> Self {
        Self { network: Network::Mainnet, genesis: Self::MAINNET_GENESIS, settlement_blue_score: 200, anchor_depth: 600 }
    }

    pub fn custom(name: impl Into<String>, genesis: [u8; 32], settlement_blue_score: u64, anchor_depth: u64) -> Self {
        Self { network: Network::Custom(name.into()), genesis, settlement_blue_score, anchor_depth }
    }
}
