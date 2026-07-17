use zkas_sdk::{NetworkConfig, PaymentIntent, SoftwareSigner};
use zkas_wallet_engine::{DEFAULT_FEE_SOMPI, max_spends_per_tx, plan_payment};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = SoftwareSigner::new([7; 32])?;
    let recipient = SoftwareSigner::new([8; 32])?.address_bytes();
    let intent = PaymentIntent { recipient, amount: 29_000_000_000, fee: DEFAULT_FEE_SOMPI };
    let plan = plan_payment(vec![6_000_000_000; 6], intent.amount, intent.fee, max_spends_per_tx())?;

    println!("network domain: {}", hex::encode(NetworkConfig::mainnet().genesis));
    println!("sender address bytes: {}", hex::encode(signer.address_bytes()));
    println!("transactions: {}, total fee: {}", plan.chunks.len(), plan.total_fee);
    Ok(())
}
