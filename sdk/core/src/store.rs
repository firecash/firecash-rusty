use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::chain::Hash;

/// Atomic durable wallet snapshot. `wallet_checkpoint` is the current
/// migration-compatible `WalletDb` checkpoint; its schema is independently
/// versioned by shielded-core.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredWallet {
    pub schema_version: u16,
    pub cursor: Option<Hash>,
    pub blue_score: u64,
    pub daa_score: u64,
    pub wallet_checkpoint: Vec<u8>,
}

impl StoredWallet {
    pub const SCHEMA_VERSION: u16 = 1;
}

#[async_trait]
pub trait WalletStore: Send + Sync {
    async fn load(&self, wallet_id: &str) -> Result<Option<StoredWallet>, String>;
    /// Implementations must replace the complete snapshot atomically.
    async fn save(&self, wallet_id: &str, snapshot: &StoredWallet) -> Result<(), String>;
    async fn remove(&self, wallet_id: &str) -> Result<(), String>;
}

#[derive(Default)]
pub struct MemoryStore {
    wallets: Mutex<HashMap<String, StoredWallet>>,
}

#[async_trait]
impl WalletStore for MemoryStore {
    async fn load(&self, wallet_id: &str) -> Result<Option<StoredWallet>, String> {
        Ok(self.wallets.lock().map_err(|_| "memory store lock poisoned")?.get(wallet_id).cloned())
    }

    async fn save(&self, wallet_id: &str, snapshot: &StoredWallet) -> Result<(), String> {
        self.wallets.lock().map_err(|_| "memory store lock poisoned")?.insert(wallet_id.to_owned(), snapshot.clone());
        Ok(())
    }

    async fn remove(&self, wallet_id: &str) -> Result<(), String> {
        self.wallets.lock().map_err(|_| "memory store lock poisoned")?.remove(wallet_id);
        Ok(())
    }
}

/// Dependency-free durable store for CLI/desktop integrations. Snapshots are
/// written to a sibling temporary file, synced, and atomically renamed so a
/// crash cannot pair a new selected-chain cursor with an old Orchard tree.
pub struct FileStore {
    directory: PathBuf,
    gate: Mutex<()>,
}

impl FileStore {
    pub fn new(directory: impl Into<PathBuf>) -> Result<Self, String> {
        let directory = directory.into();
        fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        Ok(Self { directory, gate: Mutex::new(()) })
    }

    fn path(&self, wallet_id: &str) -> PathBuf {
        let id = blake3::hash(wallet_id.as_bytes()).to_hex();
        self.directory.join(format!("{id}.wallet.json"))
    }

    fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
        let temporary = path.with_extension("wallet.json.tmp");
        {
            use std::io::Write;
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary).map_err(|error| error.to_string())?;
            file.write_all(bytes).map_err(|error| error.to_string())?;
            file.sync_all().map_err(|error| error.to_string())?;
        }
        fs::rename(&temporary, path).map_err(|error| error.to_string())?;
        if let Some(parent) = path.parent() {
            let _ = fs::File::open(parent).and_then(|directory| directory.sync_all());
        }
        Ok(())
    }
}

#[async_trait]
impl WalletStore for FileStore {
    async fn load(&self, wallet_id: &str) -> Result<Option<StoredWallet>, String> {
        let _guard = self.gate.lock().map_err(|_| "file store lock poisoned")?;
        let path = self.path(wallet_id);
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|error| error.to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn save(&self, wallet_id: &str, snapshot: &StoredWallet) -> Result<(), String> {
        let _guard = self.gate.lock().map_err(|_| "file store lock poisoned")?;
        let bytes = serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
        Self::write_atomic(&self.path(wallet_id), &bytes)
    }

    async fn remove(&self, wallet_id: &str) -> Result<(), String> {
        let _guard = self.gate.lock().map_err(|_| "file store lock poisoned")?;
        match fs::remove_file(self.path(wallet_id)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn file_store_roundtrips_and_does_not_use_wallet_id_as_a_path() {
        let directory = std::env::temp_dir().join(format!("zkas-sdk-store-{}", std::process::id()));
        let store = FileStore::new(&directory).unwrap();
        let snapshot = StoredWallet {
            schema_version: StoredWallet::SCHEMA_VERSION,
            cursor: Some([3; 32]),
            blue_score: 10,
            daa_score: 9,
            wallet_checkpoint: vec![1, 2, 3],
        };
        store.save("../../alice", &snapshot).await.unwrap();
        assert_eq!(store.load("../../alice").await.unwrap(), Some(snapshot));
        store.remove("../../alice").await.unwrap();
        assert_eq!(store.load("../../alice").await.unwrap(), None);
        let _ = fs::remove_dir_all(directory);
    }
}
