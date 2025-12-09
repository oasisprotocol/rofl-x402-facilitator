mod kms;

use alloy::signers::local::PrivateKeySigner;
use anyhow::Result;
use axum::Router;
use ed25519_dalek::SigningKey;
use std::{env, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;
use x402_rs::{facilitator_local::FacilitatorLocal, handlers, provider_cache::ProviderCache};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Load environment variables from .env file if it exists
    dotenvy::dotenv().ok();

    info!("Starting x402 Facilitator Server...");

    // Check if mock KMS mode is enabled (for local development/testing)
    // By default, ROFL KMS is used. Set DEBUG_MOCK_KMS=true to use environment variables instead.
    let use_mock_kms = env::var("DEBUG_MOCK_KMS")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);

    // Create provider cache for blockchain RPC connections
    let provider_cache = if use_mock_kms {
        info!("DEBUG_MOCK_KMS enabled - using private keys from environment variables");
        ProviderCache::from_env()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to initialize provider cache: {}", e))?
    } else {
        info!("ROFL KMS mode - generating keys from TEE");
        create_provider_cache_from_rofl().await?
    };

    // Create the facilitator wrapped in Arc for sharing across handlers
    let facilitator = Arc::new(FacilitatorLocal::new(provider_cache));

    // Build the router with x402 handlers
    let app = Router::new()
        .merge(handlers::routes())
        .layer(TraceLayer::new_for_http())
        .with_state(facilitator);

    // Get bind address from environment
    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;

    info!("Listening on {}", addr);

    // Start the server
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Create provider cache with keys from ROFL KMS
async fn create_provider_cache_from_rofl() -> Result<ProviderCache> {
    let kms_client = kms::RoflKmsClient::new();

    info!("Generating EVM private key from ROFL KMS...");
    let evm_key = kms_client.generate_evm_key("x402-facilitator-evm").await?;

    // Log EVM address
    let evm_signer: PrivateKeySigner = evm_key.parse()?;
    info!("EVM facilitator address: {}", evm_signer.address());

    info!("Generating Solana private key from ROFL KMS...");
    let solana_key = kms_client
        .generate_solana_key("x402-facilitator-solana")
        .await?;

    // Log Solana address (KMS returns hex, decode to bytes)
    let solana_key_hex = solana_key.strip_prefix("0x").unwrap_or(&solana_key);
    let solana_seed_bytes = hex::decode(solana_key_hex)?;
    let solana_signing_key = SigningKey::from_bytes(
        solana_seed_bytes[..32]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid Solana key length"))?,
    );
    let solana_pubkey = solana_signing_key.verifying_key();
    let solana_address = bs58::encode(solana_pubkey.as_bytes()).into_string();
    info!("Solana facilitator address: {}", solana_address);

    // Convert to base58 keypair format for x402-rs (64 bytes: seed + pubkey)
    let mut solana_keypair_bytes = Vec::with_capacity(64);
    solana_keypair_bytes.extend_from_slice(&solana_seed_bytes);
    solana_keypair_bytes.extend_from_slice(solana_pubkey.as_bytes());
    let solana_keypair_base58 = bs58::encode(&solana_keypair_bytes).into_string();

    // Set metadata with facilitator addresses (for on-chain discovery)
    // Supported networks can be queried via the /health endpoint
    let evm_address = format!("{}", evm_signer.address());
    let mut metadata = std::collections::HashMap::new();
    metadata.insert("evm_address".to_string(), evm_address.clone());
    metadata.insert("solana_address".to_string(), solana_address);

    info!("Publishing facilitator metadata to ROFL registry...");
    if let Err(e) = kms_client.set_metadata(metadata).await {
        // Don't fail startup if metadata update fails - it's not critical
        tracing::warn!("Failed to set ROFL metadata: {}", e);
    } else {
        info!("Facilitator metadata published to ROFL registry");
    }

    // TODO: x402-rs currently only supports from_env(). Ideally we should add
    // a from_keys() method to x402-rs to avoid this env var workaround.
    // For now, we set env vars as a workaround since x402-rs reads from env.
    // SAFETY: Called at startup before any threads are spawned
    unsafe {
        env::set_var("EVM_PRIVATE_KEY", &evm_key);
        env::set_var("SOLANA_PRIVATE_KEY", &solana_keypair_base58);
    }

    ProviderCache::from_env()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to initialize provider cache: {}", e))
}
