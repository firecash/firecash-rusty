use core::{fmt, str::FromStr};

use kaspa_addresses::{Address, Prefix, Version};

use crate::network::Network;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldedAddress(Address);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressError {
    Invalid(String),
    NotShieldedOrchard,
    UnsupportedCustomNetwork,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for AddressError {}

impl ShieldedAddress {
    pub fn from_raw(network: &Network, raw: [u8; 43]) -> Result<Self, AddressError> {
        let prefix = match network {
            Network::Mainnet => Prefix::Mainnet,
            Network::Testnet => Prefix::Testnet,
            Network::Devnet => Prefix::Devnet,
            Network::Simnet => Prefix::Simnet,
            Network::Custom(_) => return Err(AddressError::UnsupportedCustomNetwork),
        };
        Ok(Self(Address::new(prefix, Version::ShieldedOrchard, &raw)))
    }

    pub fn raw(&self) -> [u8; 43] {
        self.0.payload.as_slice().try_into().expect("constructor/parser enforces Orchard address size")
    }

    pub fn prefix(&self) -> Prefix {
        self.0.prefix
    }
}

impl FromStr for ShieldedAddress {
    type Err = AddressError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let address = Address::try_from(value.trim()).map_err(|error| AddressError::Invalid(error.to_string()))?;
        if address.version != Version::ShieldedOrchard || address.payload.len() != 43 {
            return Err(AddressError::NotShieldedOrchard);
        }
        Ok(Self(address))
    }
}

impl fmt::Display for ShieldedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_address_roundtrips_all_supported_networks() {
        for network in [Network::Mainnet, Network::Testnet, Network::Devnet, Network::Simnet] {
            let address = ShieldedAddress::from_raw(&network, [7; 43]).unwrap();
            assert_eq!(address.to_string().parse::<ShieldedAddress>().unwrap().raw(), [7; 43]);
        }
    }
}
