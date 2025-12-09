//! Generate and display test keys with their addresses
//! Run with: cargo run --bin gen_test_keys

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Test Keys for E2E Testing ===\n");
    println!("WARNING: These are TEST KEYS - DO NOT USE IN PRODUCTION\n");

    // EVM: Using Hardhat/Anvil test account #0
    let evm_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    println!("EVM (Base Sepolia, Polygon Amoy, etc.):");
    println!("  Private Key: {}", evm_key);
    println!("  Address:     0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    println!("  Faucets:");
    println!("    - Base Sepolia: https://www.alchemy.com/faucets/base-sepolia");
    println!("    - Polygon Amoy: https://faucet.polygon.technology/");
    println!();

    // Solana: derive address from hex key
    let solana_hex = "4e9e5d7c8f3a2b1d6c5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c";
    println!("Solana (Devnet):");
    println!("  Private Key (hex): {}", solana_hex);

    // Derive Solana pubkey
    let seed_bytes = hex::decode(solana_hex)?;
    let keypair = ed25519_dalek::SigningKey::from_bytes(
        seed_bytes.as_slice().try_into()?
    );
    let pubkey = keypair.verifying_key();
    let address = bs58::encode(pubkey.as_bytes()).into_string();

    println!("  Address:           {}", address);
    println!("  Faucet: https://faucet.solana.com/");

    Ok(())
}
