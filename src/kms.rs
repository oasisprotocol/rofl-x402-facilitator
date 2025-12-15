//! ROFL KMS integration for generating private keys on startup
//!
//! This module provides a KMS client wrapper around the oasis-rofl-client library
//! that communicates with the ROFL service via Unix socket to derive application-specific keys.

use anyhow::{anyhow, Result};
pub use oasis_rofl_client::KeyKind;
use oasis_rofl_client::RoflClient;
use std::path::PathBuf;
use tokio::sync::OnceCell;

/// Default Unix socket path for ROFL KMS service
const DEFAULT_ROFL_SOCKET: &str = "/run/rofl-appd.sock";

/// Trait for KMS clients to enable testing and mocking
pub trait KmsClient: Send + Sync {
    /// Generate an Ed25519 key for Solana
    fn generate_solana_key(&self, key_id: &str) -> impl std::future::Future<Output = Result<String>> + Send;

    /// Generate a Secp256k1 key for EVM chains
    fn generate_evm_key(&self, key_id: &str) -> impl std::future::Future<Output = Result<String>> + Send;
}

/// ROFL KMS client wrapper for key generation
/// Wraps the oasis-rofl-client library with application-specific conveniences
pub struct RoflKmsClient {
    client: OnceCell<RoflClient>,
    socket_path: PathBuf,
}

impl RoflKmsClient {
    /// Create a new ROFL KMS client with the default socket path
    /// or from the ROFL_SOCKET_PATH environment variable if set
    ///
    /// Note: This creates the client lazily - the socket is not checked until first use
    pub fn new() -> Self {
        let socket_path = std::env::var("ROFL_SOCKET_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_ROFL_SOCKET));

        Self {
            client: OnceCell::new(),
            socket_path,
        }
    }

    /// Create a new ROFL KMS client with a custom socket path
    pub fn with_socket_path(socket_path: PathBuf) -> Self {
        Self {
            client: OnceCell::new(),
            socket_path,
        }
    }

    /// Get or create the underlying RoflClient
    async fn get_client(&self) -> Result<&RoflClient> {
        self.client.get_or_try_init(|| async {
            RoflClient::with_socket_path(&self.socket_path)
                .map_err(|e| anyhow!("Failed to connect to ROFL socket at {:?}: {}", self.socket_path, e))
        }).await
    }

    /// Generate a key using the ROFL KMS service
    ///
    /// # Arguments
    /// * `key_id` - Domain separator / identifier for the key
    /// * `kind` - Type of key to generate
    ///
    /// # Returns
    /// The generated key as a hex string
    pub async fn generate_key(&self, key_id: &str, kind: KeyKind) -> Result<String> {
        let client = self.get_client().await?.clone();
        client
            .generate_key(key_id, kind)
            .await
            .map_err(|e| anyhow!("Failed to generate key: {}", e))
    }

    /// Generate an Ed25519 key for Solana
    ///
    /// # Arguments
    /// * `key_id` - Domain separator / identifier for the key
    ///
    /// # Returns
    /// The generated key as a hex string (can be converted to Base58)
    pub async fn generate_solana_key(&self, key_id: &str) -> Result<String> {
        self.generate_key(key_id, KeyKind::Ed25519).await
    }

    /// Generate a Secp256k1 key for EVM chains
    ///
    /// # Arguments
    /// * `key_id` - Domain separator / identifier for the key
    ///
    /// # Returns
    /// The generated key as a hex string with "0x" prefix
    pub async fn generate_evm_key(&self, key_id: &str) -> Result<String> {
        let key = self.generate_key(key_id, KeyKind::Secp256k1).await?;
        // Ensure 0x prefix
        if key.starts_with("0x") {
            Ok(key)
        } else {
            Ok(format!("0x{}", key))
        }
    }

    /// Set metadata key-value pairs via ROFL appd
    ///
    /// This replaces all existing app-provided metadata. Will trigger a registration
    /// refresh if the metadata has changed.
    ///
    /// # Arguments
    /// * `metadata` - HashMap of metadata key-value pairs to set
    pub async fn set_metadata(&self, metadata: std::collections::HashMap<String, String>) -> Result<()> {
        let client = self.get_client().await?.clone();
        client
            .set_metadata(&metadata)
            .await
            .map_err(|e| anyhow!("Failed to set metadata: {}", e))
    }
}

impl Default for RoflKmsClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_kind_display() {
        assert_eq!(KeyKind::Ed25519.to_string(), "ed25519");
        assert_eq!(KeyKind::Secp256k1.to_string(), "secp256k1");
        assert_eq!(KeyKind::Raw256.to_string(), "raw-256");
        assert_eq!(KeyKind::Raw384.to_string(), "raw-384");
    }
}

/// Mock KMS client for testing
pub mod mock {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// Mock KMS client that returns deterministic keys for testing
    #[derive(Clone)]
    pub struct MockKmsClient {
        keys: Arc<Mutex<HashMap<String, String>>>,
    }

    impl MockKmsClient {
        /// Create a new mock KMS client
        pub fn new() -> Self {
            Self {
                keys: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        /// Pre-configure a key for a given key_id
        pub fn with_key(self, key_id: &str, key: &str) -> Self {
            self.keys.lock().unwrap().insert(key_id.to_string(), key.to_string());
            self
        }

        /// Get all generated keys (for assertions)
        pub fn get_keys(&self) -> HashMap<String, String> {
            self.keys.lock().unwrap().clone()
        }
    }

    impl Default for MockKmsClient {
        fn default() -> Self {
            Self::new()
        }
    }

    impl KmsClient for MockKmsClient {
        fn generate_solana_key(&self, key_id: &str) -> impl std::future::Future<Output = Result<String>> + Send {
            let keys = self.keys.clone();
            let key_id = key_id.to_string();

            async move {
                let mut keys = keys.lock().unwrap();

                if let Some(key) = keys.get(&key_id) {
                    return Ok(key.clone());
                }

                // Generate deterministic test key based on key_id
                let test_key = format!("{:0<64}", format!("solana_{}", key_id));
                keys.insert(key_id.to_string(), test_key.clone());
                Ok(test_key)
            }
        }

        fn generate_evm_key(&self, key_id: &str) -> impl std::future::Future<Output = Result<String>> + Send {
            let keys = self.keys.clone();
            let key_id = key_id.to_string();

            async move {
                let mut keys = keys.lock().unwrap();

                if let Some(key) = keys.get(&key_id) {
                    return Ok(key.clone());
                }

                // Generate deterministic test key based on key_id
                let test_key = format!("0x{:0<64}", format!("evm_{}", key_id));
                keys.insert(key_id.to_string(), test_key.clone());
                Ok(test_key)
            }
        }
    }

    #[tokio::test]
    async fn test_mock_kms_solana_key() {
        let mock = MockKmsClient::new();
        let key = mock.generate_solana_key("test-solana").await.unwrap();
        assert!(key.len() == 64);

        // Should return same key on second call
        let key2 = mock.generate_solana_key("test-solana").await.unwrap();
        assert_eq!(key, key2);
    }

    #[tokio::test]
    async fn test_mock_kms_evm_key() {
        let mock = MockKmsClient::new();
        let key = mock.generate_evm_key("test-evm").await.unwrap();
        assert!(key.starts_with("0x"));
        assert!(key.len() == 66); // 0x + 64 chars

        // Should return same key on second call
        let key2 = mock.generate_evm_key("test-evm").await.unwrap();
        assert_eq!(key, key2);
    }

    #[tokio::test]
    async fn test_mock_kms_with_preconfigured_key() {
        let mock = MockKmsClient::new()
            .with_key("custom-evm", "0x1234567890abcdef");

        let key = mock.generate_evm_key("custom-evm").await.unwrap();
        assert_eq!(key, "0x1234567890abcdef");
    }
}
