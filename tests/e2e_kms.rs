/// E2E tests for KMS integration
///
/// These tests verify the KMS integration with mocks, ensuring that:
/// - Keys can be generated from the mock KMS
/// - Environment variables are properly set
/// - The system works in both ROFL and standalone modes

mod common;

use anyhow::Result;
use std::env;

// Import the mock KMS client for testing
#[cfg(test)]
use trustless_x402_facilitator::kms::{mock::MockKmsClient, KmsClient};

#[tokio::test]
async fn test_generate_evm_key_from_mock_kms() -> Result<()> {
    let mock_kms = MockKmsClient::new();

    let key = mock_kms.generate_evm_key("test-evm-key").await?;

    // Verify key has correct format
    assert!(key.starts_with("0x"), "EVM key should start with 0x");
    assert!(key.len() >= 66, "EVM key should be at least 66 chars (0x + 64)");

    // Verify deterministic behavior
    let key2 = mock_kms.generate_evm_key("test-evm-key").await?;
    assert_eq!(key, key2, "Same key_id should produce same key");

    // Verify different key_id produces different key
    let different_key = mock_kms.generate_evm_key("different-key").await?;
    assert_ne!(key, different_key, "Different key_id should produce different key");

    Ok(())
}

#[tokio::test]
async fn test_generate_solana_key_from_mock_kms() -> Result<()> {
    let mock_kms = MockKmsClient::new();

    let key = mock_kms.generate_solana_key("test-solana-key").await?;

    // Verify key format (should be 64 chars - mock uses test prefix + key_id)
    assert_eq!(key.len(), 64, "Solana key should be 64 chars");
    // Note: Mock keys contain alphanumeric chars for testing, real keys are hex

    // Verify deterministic behavior
    let key2 = mock_kms.generate_solana_key("test-solana-key").await?;
    assert_eq!(key, key2, "Same key_id should produce same key");

    Ok(())
}

#[tokio::test]
async fn test_mock_kms_with_preconfigured_keys() -> Result<()> {
    let mock_kms = MockKmsClient::new()
        .with_key("preset-evm", "0xabcdef1234567890")
        .with_key("preset-solana", "fedcba0987654321");

    let evm_key = mock_kms.generate_evm_key("preset-evm").await?;
    assert_eq!(evm_key, "0xabcdef1234567890");

    let solana_key = mock_kms.generate_solana_key("preset-solana").await?;
    assert_eq!(solana_key, "fedcba0987654321");

    Ok(())
}

#[tokio::test]
async fn test_rofl_kms_mode_simulation() -> Result<()> {
    let mut test_env = common::TestEnv::new();

    // Simulate ROFL KMS mode
    test_env.set("USE_ROFL_KMS", "true");

    // Clear any existing keys
    test_env.remove("EVM_PRIVATE_KEY");
    test_env.remove("SOLANA_PRIVATE_KEY");

    // Create mock KMS
    let mock_kms = MockKmsClient::new()
        .with_key("x402-facilitator-evm", "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        .with_key("x402-facilitator-solana", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");

    // Simulate key generation as done in main.rs
    // SAFETY: Test environment, called before any threads read these vars
    if env::var("EVM_PRIVATE_KEY").is_err() {
        let evm_key = mock_kms.generate_evm_key("x402-facilitator-evm").await?;
        unsafe { env::set_var("EVM_PRIVATE_KEY", &evm_key) };
    }

    // SAFETY: Test environment, called before any threads read these vars
    if env::var("SOLANA_PRIVATE_KEY").is_err() {
        let solana_key = mock_kms.generate_solana_key("x402-facilitator-solana").await?;
        unsafe { env::set_var("SOLANA_PRIVATE_KEY", &solana_key) };
    }

    // Verify keys are set
    assert!(env::var("EVM_PRIVATE_KEY").is_ok());
    assert!(env::var("SOLANA_PRIVATE_KEY").is_ok());

    let evm_key = env::var("EVM_PRIVATE_KEY")?;
    assert!(evm_key.starts_with("0x"));

    // Cleanup happens automatically via TestEnv drop
    Ok(())
}

#[tokio::test]
async fn test_standalone_mode_with_existing_keys() -> Result<()> {
    let mut test_env = common::TestEnv::new();

    // Simulate standalone mode (ROFL disabled)
    test_env.set("USE_ROFL_KMS", "false");

    // Pre-set keys as in standalone mode
    let preset_evm_key = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let preset_solana_key = "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe";

    test_env.set("EVM_PRIVATE_KEY", preset_evm_key);
    test_env.set("SOLANA_PRIVATE_KEY", preset_solana_key);

    // Verify in standalone mode, keys are not generated from KMS
    let use_rofl = env::var("USE_ROFL_KMS")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);

    assert!(!use_rofl, "ROFL KMS should be disabled");

    // Verify keys are available from environment
    assert_eq!(env::var("EVM_PRIVATE_KEY")?, preset_evm_key);
    assert_eq!(env::var("SOLANA_PRIVATE_KEY")?, preset_solana_key);

    Ok(())
}

#[tokio::test]
async fn test_kms_key_persistence_across_calls() -> Result<()> {
    let mock_kms = MockKmsClient::new();

    // First call generates key
    let key1 = mock_kms.generate_evm_key("persistent-key").await?;

    // Subsequent calls should return the same key
    let key2 = mock_kms.generate_evm_key("persistent-key").await?;
    let key3 = mock_kms.generate_evm_key("persistent-key").await?;

    assert_eq!(key1, key2);
    assert_eq!(key2, key3);

    // Verify the mock tracks all keys
    let keys = mock_kms.get_keys();
    assert!(keys.contains_key("persistent-key"));

    Ok(())
}

#[tokio::test]
async fn test_multiple_key_ids_isolation() -> Result<()> {
    let mock_kms = MockKmsClient::new();

    // Generate keys for different purposes
    let evm_mainnet = mock_kms.generate_evm_key("mainnet-evm").await?;
    let evm_testnet = mock_kms.generate_evm_key("testnet-evm").await?;
    let solana_mainnet = mock_kms.generate_solana_key("mainnet-solana").await?;
    let solana_testnet = mock_kms.generate_solana_key("testnet-solana").await?;

    // All keys should be different
    assert_ne!(evm_mainnet, evm_testnet);
    assert_ne!(solana_mainnet, solana_testnet);

    // Verify all keys are tracked
    let keys = mock_kms.get_keys();
    assert_eq!(keys.len(), 4);
    assert!(keys.contains_key("mainnet-evm"));
    assert!(keys.contains_key("testnet-evm"));
    assert!(keys.contains_key("mainnet-solana"));
    assert!(keys.contains_key("testnet-solana"));

    Ok(())
}
