use std::{env, fs, path::Path};

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_shielded_core::walletdb::WalletDb;
use serde_json::Value;

fn decode_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn main() {
    let mut args = env::args().skip(1);
    let dir = args.next().expect("usage: find_address WALLET_DIR ZKAS_ADDRESS");
    let wanted = args.next().expect("usage: find_address WALLET_DIR ZKAS_ADDRESS");

    for entry in fs::read_dir(&dir).expect("read wallet directory").flatten() {
        let path = entry.path();
        if path.extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        let Ok(raw) = fs::read(&path) else { continue };
        let Ok(file) = serde_json::from_slice::<Value>(&raw) else { continue };
        if file.get("encrypted").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let db = file
            .get("fvk_hex")
            .and_then(Value::as_str)
            .and_then(decode_hex::<96>)
            .and_then(|fvk| WalletDb::from_fvk(&fvk))
            .or_else(|| {
                file.get("seed_hex")
                    .and_then(Value::as_str)
                    .and_then(decode_hex::<32>)
                    .and_then(WalletDb::from_seed)
            });
        let Some(db) = db else { continue };
        let address = String::from(&Address::new(Prefix::Mainnet, Version::ShieldedOrchard, &db.my_address_bytes()));
        if address == wanted {
            println!("{}", Path::new(&path).file_stem().unwrap().to_string_lossy());
        }
    }
}
