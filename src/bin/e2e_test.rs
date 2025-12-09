//! E2E test for x402 facilitator using the official x402-reqwest client
//!
//! This test:
//! 1. Checks facilitator health/connectivity
//! 2. Creates a payment request using the x402-reqwest client
//! 3. Verifies and settles the payment on-chain
//!
//! Prerequisites:
//! - Facilitator running (defaults to https://x402.updev.si)
//! - Test account funded with USDC on Base Sepolia
//! - Set FACILITATOR_URL env var to test a different instance
//!
//! Run with: cargo run --bin e2e_test

use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use x402_reqwest::chains::{evm::EvmSenderWallet, SenderWallet};
use x402_rs::{
    network::Network,
    types::{EvmAddress, MixedAddress, PaymentRequirements, Scheme, TokenAmount},
};

// Default to live deployment, override with FACILITATOR_URL env var
fn get_facilitator_url() -> String {
    std::env::var("FACILITATOR_URL").unwrap_or_else(|_| "https://x402.updev.si".to_string())
}

// USDC on Base Sepolia
const USDC_ADDRESS: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
// Test recipient (Hardhat account #1)
const RECIPIENT: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
// Get payer private key from environment or use default
// NOTE: The default Hardhat key may be an EIP-7702 smart account on some networks
// Use EVM_PAYER_KEY env var to specify a pure EOA for testing
fn get_payer_private_key() -> String {
    std::env::var("EVM_PAYER_KEY").unwrap_or_else(|_| {
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string()
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct SupportedResponse {
    kinds: Vec<SupportedKind>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SupportedKind {
    network: String,
    scheme: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let facilitator_url = get_facilitator_url();

    println!("=== x402 Facilitator E2E Test ===\n");
    println!("Facilitator: {}", facilitator_url);
    println!();

    let client = reqwest::Client::new();

    // Step 1: Check facilitator is running
    println!("1. Checking facilitator status...");
    let supported: SupportedResponse = client
        .get(format!("{}/health", facilitator_url))
        .send()
        .await
        .context("Failed to connect to facilitator - is it running?")?
        .json()
        .await?;

    println!("   ✓ Facilitator running");
    println!(
        "   Networks: {:?}",
        supported
            .kinds
            .iter()
            .map(|k| &k.network)
            .collect::<Vec<_>>()
    );
    println!();

    // Step 2: Create payment payload using x402-reqwest client
    println!("2. Creating signed payment authorization...");

    let payer_key = get_payer_private_key();
    let signer = PrivateKeySigner::from_str(&payer_key)?;
    let payer_address = signer.address();
    println!("   Payer: {}", payer_address);
    println!("   Recipient: {}", RECIPIENT);

    // Create the EVM wallet
    let wallet = EvmSenderWallet::new(signer);

    // Create payment requirements (what the server would send)
    let requirements = PaymentRequirements {
        scheme: Scheme::Exact,
        network: Network::BaseSepolia,
        max_amount_required: TokenAmount::from(10000u64), // 0.01 USDC
        resource: "https://example.com/api/test".parse()?,
        description: "E2E Test Payment".to_string(),
        mime_type: "application/json".to_string(),
        output_schema: None,
        pay_to: MixedAddress::Evm(EvmAddress::from_str(RECIPIENT)?),
        max_timeout_seconds: 300,
        asset: MixedAddress::Evm(EvmAddress::from_str(USDC_ADDRESS)?),
        extra: Some(serde_json::json!({
            "name": "USDC",
            "version": "2"
        })),
    };

    // Generate the signed payment payload
    let payment_payload = wallet.payment_payload(requirements.clone()).await
        .map_err(|e| anyhow::anyhow!("Failed to create payment payload: {:?}", e))?;

    println!("   ✓ Payment payload created");

    // Print the payload for debugging
    println!("   Payload: {}", serde_json::to_string_pretty(&payment_payload)?);
    println!();

    // Step 3: Verify with facilitator
    println!("3. Verifying payment with facilitator...");

    let verify_request = x402_rs::types::VerifyRequest {
        x402_version: x402_rs::types::X402Version::V1,
        payment_payload: payment_payload.clone(),
        payment_requirements: requirements.clone(),
    };

    let verify_response = client
        .post(format!("{}/verify", facilitator_url))
        .json(&verify_request)
        .send()
        .await?;

    let verify_status = verify_response.status();
    let verify_text = verify_response.text().await?;

    println!("   Status: {}", verify_status);

    let verify_body: serde_json::Value = serde_json::from_str(&verify_text)
        .context(format!("Failed to parse response: {}", verify_text))?;

    println!("   Response: {}", serde_json::to_string_pretty(&verify_body)?);

    let is_valid = verify_body
        .get("isValid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !is_valid {
        println!();
        println!("   ✗ Verification failed");
        if let Some(reason) = verify_body.get("invalidReason") {
            println!("   Reason: {}", reason);
        }
        if let Some(error) = verify_body.get("error") {
            println!("   Error: {}", error);
        }
        println!();
        println!("   Common issues:");
        println!("   - Payer account needs USDC on Base Sepolia");
        println!("   - Get testnet USDC from: https://faucet.circle.com/");
        return Ok(());
    }

    println!("   ✓ Payment verified!");
    println!();

    // Step 4: Settle the payment
    println!("4. Settling payment on-chain...");

    let settle_request = x402_rs::types::SettleRequest {
        x402_version: x402_rs::types::X402Version::V1,
        payment_payload,
        payment_requirements: requirements,
    };

    let settle_response = client
        .post(format!("{}/settle", facilitator_url))
        .json(&settle_request)
        .send()
        .await?;

    let settle_status = settle_response.status();
    let settle_body: serde_json::Value = settle_response.json().await?;

    println!("   Status: {}", settle_status);
    println!(
        "   Response: {}",
        serde_json::to_string_pretty(&settle_body)?
    );

    if let Some(tx_hash) = settle_body.get("txHash").and_then(|v| v.as_str()) {
        println!();
        println!("   ✓ Payment settled!");
        println!("   Transaction: {}", tx_hash);
        println!(
            "   View on BaseScan: https://sepolia.basescan.org/tx/{}",
            tx_hash
        );
    }

    println!();
    println!("=== E2E Test Complete ===");

    Ok(())
}
