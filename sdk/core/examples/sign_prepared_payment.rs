use std::{env, fs, str::FromStr};

use zkas_sdk::{NetworkConfig, PaymentIntent, PreparedPaymentV1, ShieldedAddress, SoftwareSigner};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 6 {
        return Err("usage: sign_prepared_payment <prepared.json> <seed-hex> <recipient> <amount-sompi> <fee-sompi>".into());
    }
    let wire: PreparedPaymentV1 = serde_json::from_slice(&fs::read(&args[1])?)?;
    let prepared = wire.to_typed()?;
    let seed: [u8; 32] = hex::decode(&args[2])?.try_into().map_err(|_| "seed must be exactly 32 bytes")?;
    let recipient = ShieldedAddress::from_str(&args[3])?;
    let intent = PaymentIntent { recipient: recipient.raw(), amount: args[4].parse()?, fee: args[5].parse()? };
    let signatures = SoftwareSigner::new(seed)?.verify_and_sign(&NetworkConfig::mainnet().genesis, &intent, &prepared)?;
    for signature in signatures {
        println!("{}:{}", signature.action_index, hex::encode(signature.signature));
    }
    Ok(())
}
