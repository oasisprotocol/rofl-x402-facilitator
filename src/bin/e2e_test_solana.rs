//! E2E test for x402 facilitator using Solana Devnet
//!
//! This test:
//! 1. Checks facilitator health/connectivity
//! 2. Creates a payment request using the x402-reqwest client for Solana
//! 3. Verifies and settles the payment on-chain
//!
//! Prerequisites:
//! - Facilitator running (defaults to https://x402.updev.si)
//! - Test account funded with USDC on Solana Devnet
//! - Set FACILITATOR_URL env var to test a different instance
//! - Set SOLANA_PAYER_KEY env var to specify payer keypair (base58)
//!
//! Run with: cargo run --bin e2e_test_solana

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use std::str::FromStr;
use x402_reqwest::chains::{solana::SolanaSenderWallet, SenderWallet};
use x402_rs::{
    network::Network,
    types::{MixedAddress, PaymentRequirements, Scheme, TokenAmount},
};

// Default to live deployment, override with FACILITATOR_URL env var
fn get_facilitator_url() -> String {
    std::env::var("FACILITATOR_URL").unwrap_or_else(|_| "https://x402.updev.si".to_string())
}

// USDC on Solana Devnet
const USDC_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
// Solana Devnet RPC
const SOLANA_RPC: &str = "https://api.devnet.solana.com";

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

    println!("=== x402 Facilitator Solana E2E Test ===\n");
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

    println!("   Facilitator running");
    println!(
        "   Networks: {:?}",
        supported
            .kinds
            .iter()
            .map(|k| &k.network)
            .collect::<Vec<_>>()
    );

    // Check if solana-devnet is supported
    let solana_supported = supported
        .kinds
        .iter()
        .any(|k| k.network == "solana-devnet");
    if !solana_supported {
        println!();
        println!("   ERROR: solana-devnet not supported by facilitator");
        println!("   Supported networks: {:?}", supported.kinds.iter().map(|k| &k.network).collect::<Vec<_>>());
        return Ok(());
    }
    println!("   solana-devnet is supported!");
    println!();

    // Step 2: Create or load keypair
    println!("2. Setting up Solana wallet...");

    let keypair = if let Ok(key_b58) = std::env::var("SOLANA_PAYER_KEY") {
        // Decode base58 keypair
        let key_bytes = bs58::decode(&key_b58)
            .into_vec()
            .context("Invalid base58 key in SOLANA_PAYER_KEY")?;
        Keypair::try_from(key_bytes.as_slice()).context("Invalid keypair bytes")?
    } else {
        // Generate a new keypair for testing
        println!("   No SOLANA_PAYER_KEY set, generating new keypair...");
        Keypair::new()
    };

    let payer_pubkey = keypair.pubkey();
    println!("   Payer: {}", payer_pubkey);

    // Check facilitator address (this will be the fee payer for Solana)
    let health_response: serde_json::Value = client
        .get(format!("{}/health", facilitator_url))
        .send()
        .await?
        .json()
        .await?;

    // Find solana-devnet facilitator fee payer address
    let facilitator_solana_address = health_response
        .get("kinds")
        .and_then(|k| k.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|k| k.get("network").and_then(|n| n.as_str()) == Some("solana-devnet"))
                .and_then(|k| k.get("extra"))
                .and_then(|e| e.get("feePayer"))
                .and_then(|a| a.as_str())
        });

    let fee_payer = if let Some(addr) = facilitator_solana_address {
        println!("   Facilitator (fee payer): {}", addr);
        addr.to_string()
    } else {
        println!("   ERROR: Could not find facilitator Solana fee payer address");
        println!("   Health response: {}", serde_json::to_string_pretty(&health_response)?);
        return Ok(());
    };

    // Create Solana RPC client
    let rpc_client = RpcClient::new(SOLANA_RPC.to_string());

    // Check payer balance
    let balance = rpc_client.get_balance(&payer_pubkey)?;
    println!("   Payer SOL balance: {} lamports ({} SOL)", balance, balance as f64 / 1e9);

    // Check USDC balance
    let usdc_mint = Pubkey::from_str(USDC_DEVNET)?;
    let payer_ata = spl_associated_token_account::get_associated_token_address(&payer_pubkey, &usdc_mint);
    let usdc_balance = match rpc_client.get_token_account_balance(&payer_ata) {
        Ok(balance) => balance.ui_amount.unwrap_or(0.0),
        Err(_) => 0.0,
    };
    println!("   Payer USDC balance: {} USDC", usdc_balance);

    if usdc_balance < 0.01 {
        println!();
        println!("   WARNING: Payer needs USDC on Solana Devnet");
        println!("   You can get test USDC from: https://faucet.circle.com/");
        println!("   Payer address: {}", payer_pubkey);
        // Continue anyway to test the flow
    }

    println!();

    // Step 3: Create payment payload
    println!("3. Creating signed payment transaction...");

    // Create the Solana wallet
    let wallet = SolanaSenderWallet::new(keypair, rpc_client);

    // Create payment requirements for Solana
    // Pay to payer's own address (self-payment) since their ATA already exists
    // This avoids the createATA instruction which includes fee_payer in accounts
    let recipient = payer_pubkey;
    println!("   Recipient (self-payment test): {}", recipient);
    let requirements = PaymentRequirements {
        scheme: Scheme::Exact,
        network: Network::SolanaDevnet,
        max_amount_required: TokenAmount::from(10000u64), // 0.01 USDC (6 decimals)
        resource: "https://example.com/api/test".parse()?,
        description: "E2E Test Payment (Solana)".to_string(),
        mime_type: "application/json".to_string(),
        output_schema: None,
        pay_to: MixedAddress::Solana(recipient),
        max_timeout_seconds: 300,
        asset: MixedAddress::Solana(usdc_mint),
        extra: Some(serde_json::json!({
            "feePayer": fee_payer
        })),
    };

    // Generate the signed payment payload
    let payment_payload = match wallet.payment_payload(requirements.clone()).await {
        Ok(payload) => payload,
        Err(e) => {
            println!("   ERROR creating payment payload: {:?}", e);
            println!();
            println!("   This might be because:");
            println!("   - Payer needs SOL for transaction fees");
            println!("   - Payer needs USDC tokens");
            println!("   - RPC endpoint issues");
            return Ok(());
        }
    };

    println!("   Payment payload created");
    println!("   Payload: {}", serde_json::to_string_pretty(&payment_payload)?);
    println!();

    // Step 4: Verify with facilitator
    println!("4. Verifying payment with facilitator...");

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
        println!("   Verification failed");
        if let Some(reason) = verify_body.get("invalidReason") {
            println!("   Reason: {}", reason);
        }
        if let Some(error) = verify_body.get("error") {
            println!("   Error: {}", error);
        }
        println!();
        println!("   Common issues:");
        println!("   - Payer account needs USDC on Solana Devnet");
        println!("   - Get testnet USDC from: https://faucet.circle.com/");
        return Ok(());
    }

    println!("   Payment verified!");
    println!();

    // Step 5: Settle the payment
    println!("5. Settling payment on-chain...");

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
        println!("   Payment settled!");
        println!("   Transaction: {}", tx_hash);
        println!(
            "   View on Solscan: https://solscan.io/tx/{}?cluster=devnet",
            tx_hash
        );
    }

    println!();
    println!("=== Solana E2E Test Complete ===");

    Ok(())
}
