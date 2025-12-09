/// ROFL KMS integration for generating private keys on startup
///
/// This module provides a simplified KMS client that communicates with the ROFL
/// service via Unix socket to derive application-specific keys.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

/// Default Unix socket path for ROFL KMS service
const DEFAULT_ROFL_SOCKET: &str = "/run/rofl-appd.sock";

/// Key kinds supported by ROFL KMS
#[derive(Debug, Clone, Copy)]
pub enum KeyKind {
    /// Raw 256-bit entropy
    Raw256,
    /// Raw 384-bit entropy
    Raw384,
    /// Ed25519 signing key (for Solana)
    Ed25519,
    /// Secp256k1 signing key (for EVM chains)
    Secp256k1,
}

impl KeyKind {
    fn as_str(&self) -> &'static str {
        match self {
            KeyKind::Raw256 => "raw-256",
            KeyKind::Raw384 => "raw-384",
            KeyKind::Ed25519 => "ed25519",
            KeyKind::Secp256k1 => "secp256k1",
        }
    }
}

/// Request to generate a key (matches ROFL HTTP API format)
#[derive(Debug, Serialize)]
struct KeyGenerationRequest<'a> {
    /// Domain separator / key identifier
    key_id: &'a str,
    /// Type of key to generate (raw-256, raw-384, ed25519, secp256k1)
    kind: &'a str,
}

/// Response from key generation (matches ROFL HTTP API format)
#[derive(Debug, Deserialize)]
struct KeyGenerationResponse {
    /// The generated key in hex format
    key: String,
}

/// Trait for KMS clients to enable testing and mocking
pub trait KmsClient: Send + Sync {
    /// Generate an Ed25519 key for Solana
    fn generate_solana_key(&self, key_id: &str) -> impl std::future::Future<Output = Result<String>> + Send;

    /// Generate a Secp256k1 key for EVM chains
    fn generate_evm_key(&self, key_id: &str) -> impl std::future::Future<Output = Result<String>> + Send;
}

/// ROFL KMS client for key generation
pub struct RoflKmsClient {
    socket_path: PathBuf,
}

impl RoflKmsClient {
    /// Create a new ROFL KMS client with the default socket path
    /// or from the ROFL_SOCKET_PATH environment variable if set
    pub fn new() -> Self {
        let socket_path = std::env::var("ROFL_SOCKET_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_ROFL_SOCKET));

        Self { socket_path }
    }

    /// Create a new ROFL KMS client with a custom socket path
    pub fn with_socket_path(socket_path: PathBuf) -> Self {
        Self { socket_path }
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
        // Connect to ROFL Unix socket
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| anyhow!("Failed to connect to ROFL socket at {:?}: {}", self.socket_path, e))?;

        // Prepare JSON body
        let request = KeyGenerationRequest {
            key_id,
            kind: kind.as_str(),
        };
        let body = serde_json::to_string(&request)?;

        // Build HTTP request manually (ROFL daemon expects HTTP over Unix socket)
        let http_request = format!(
            "POST /rofl/v1/keys/generate HTTP/1.1\r\n\
             Host: localhost\r\n\
             Connection: close\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            body.len(),
            body
        );

        // Send HTTP request
        stream.write_all(http_request.as_bytes()).await?;
        stream.flush().await?;

        // Read HTTP response
        let mut buf_reader = BufReader::new(stream);
        let mut response_data = String::new();

        // Read all response data
        loop {
            let mut line = String::new();
            match buf_reader.read_line(&mut line).await {
                Ok(0) => break, // EOF
                Ok(_) => response_data.push_str(&line),
                Err(e) => return Err(anyhow!("Failed to read ROFL KMS response: {}", e)),
            }
        }

        if response_data.is_empty() {
            return Err(anyhow!("ROFL KMS returned empty response"));
        }

        // Parse HTTP response - find the body after \r\n\r\n
        let body_start = response_data
            .find("\r\n\r\n")
            .ok_or_else(|| anyhow!("Invalid HTTP response from ROFL KMS: no body separator"))?;
        let body = &response_data[body_start + 4..];

        // Check HTTP status line
        let status_line = response_data.lines().next().unwrap_or("");
        if !status_line.contains("200") {
            return Err(anyhow!("ROFL KMS HTTP error: {} (body: {})", status_line, body.trim()));
        }

        // Parse JSON response body
        let response: KeyGenerationResponse = serde_json::from_str(body.trim())
            .map_err(|e| anyhow!("Failed to parse ROFL KMS response: {} (raw: {})", e, body.trim()))?;

        Ok(response.key)
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
        // Connect to ROFL Unix socket
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| anyhow!("Failed to connect to ROFL socket at {:?}: {}", self.socket_path, e))?;

        // Prepare JSON body
        let body = serde_json::to_string(&metadata)?;

        // Build HTTP request
        let http_request = format!(
            "POST /rofl/v1/metadata HTTP/1.1\r\n\
             Host: localhost\r\n\
             Connection: close\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            body.len(),
            body
        );

        // Send HTTP request
        stream.write_all(http_request.as_bytes()).await?;
        stream.flush().await?;

        // Read HTTP response
        let mut buf_reader = BufReader::new(stream);
        let mut response_data = String::new();

        // Read all response data
        loop {
            let mut line = String::new();
            match buf_reader.read_line(&mut line).await {
                Ok(0) => break, // EOF
                Ok(_) => response_data.push_str(&line),
                Err(e) => return Err(anyhow!("Failed to read ROFL metadata response: {}", e)),
            }
        }

        // Check HTTP status line
        let status_line = response_data.lines().next().unwrap_or("");
        if !status_line.contains("200") && !status_line.contains("204") {
            return Err(anyhow!("ROFL set_metadata HTTP error: {}", status_line));
        }

        Ok(())
    }
}

impl Default for RoflKmsClient {
    fn default() -> Self {
        Self::new()
    }
}

impl KmsClient for RoflKmsClient {
    fn generate_solana_key(&self, key_id: &str) -> impl std::future::Future<Output = Result<String>> + Send {
        self.generate_key(key_id, KeyKind::Ed25519)
    }

    fn generate_evm_key(&self, key_id: &str) -> impl std::future::Future<Output = Result<String>> + Send {
        async move {
            let key = self.generate_key(key_id, KeyKind::Secp256k1).await?;
            // Ensure 0x prefix
            if key.starts_with("0x") {
                Ok(key)
            } else {
                Ok(format!("0x{}", key))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_kind_as_str() {
        assert_eq!(KeyKind::Ed25519.as_str(), "ed25519");
        assert_eq!(KeyKind::Secp256k1.as_str(), "secp256k1");
        assert_eq!(KeyKind::Raw256.as_str(), "raw-256");
        assert_eq!(KeyKind::Raw384.as_str(), "raw-384");
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
