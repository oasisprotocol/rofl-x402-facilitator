//! Create an ATA for the facilitator by sending a tiny USDC amount
//! Run with: cargo run --bin create_ata

use anyhow::Result;
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::transaction::Transaction;
use spl_associated_token_account::instruction::create_associated_token_account_idempotent;
use std::str::FromStr;

const SOLANA_RPC: &str = "https://api.devnet.solana.com";
const USDC_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const FACILITATOR: &str = "7krTwCQi9zK7RcYzwixnVi4YkuTrAmmZ3iDTzu58JSjo";

// Funded payer - d1MbDGEZctes6QAJs1jF3xwd8yb6zVk3rwc1nbyU2w3
const PAYER_KEY: &str = "2sBTnHpobaUCXmbmrQ71EcYvHL21iaPigoX1gKREK7AcBW2AtbmmopBc5GR9Y1QuiCdc8Uh5cSR32jxmYeh1vUSV";

fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let rpc_client = RpcClient::new(SOLANA_RPC.to_string());

    // Load payer keypair
    let key_bytes = bs58::decode(PAYER_KEY).into_vec()?;
    let payer = Keypair::try_from(key_bytes.as_slice())?;
    println!("Payer: {}", payer.pubkey());

    let usdc_mint = Pubkey::from_str(USDC_DEVNET)?;
    let facilitator = Pubkey::from_str(FACILITATOR)?;

    // Check payer's SOL balance
    let balance = rpc_client.get_balance(&payer.pubkey())?;
    println!("Payer SOL balance: {} lamports", balance);

    // Create the ATA for the facilitator
    println!("\nCreating USDC ATA for facilitator: {}", facilitator);

    let ix = create_associated_token_account_idempotent(
        &payer.pubkey(), // funding address
        &facilitator,     // wallet address (owner of the ATA)
        &usdc_mint,       // token mint
        &spl_token::id(), // token program
    );

    let recent_blockhash = rpc_client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    let sig = rpc_client.send_and_confirm_transaction(&tx)?;
    println!("Transaction: {}", sig);
    println!("View: https://solscan.io/tx/{}?cluster=devnet", sig);

    // Verify the ATA was created
    let ata = spl_associated_token_account::get_associated_token_address(&facilitator, &usdc_mint);
    println!("\nFacilitator USDC ATA: {}", ata);

    Ok(())
}
