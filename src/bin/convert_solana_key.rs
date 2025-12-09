//! Convert hex Solana seed to base58 keypair format
//! Run with: cargo run --bin convert_solana_key

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hex_seed = "4e9e5d7c8f3a2b1d6c5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c";

    // Decode hex to bytes
    let seed_bytes = hex::decode(hex_seed)?;

    // Create signing key from seed
    let signing_key = ed25519_dalek::SigningKey::from_bytes(
        seed_bytes.as_slice().try_into()?
    );

    // Get verifying (public) key
    let verifying_key = signing_key.verifying_key();

    // Solana expects 64-byte keypair: seed (32) + pubkey (32)
    let mut keypair_bytes = Vec::with_capacity(64);
    keypair_bytes.extend_from_slice(&seed_bytes);
    keypair_bytes.extend_from_slice(verifying_key.as_bytes());

    // Encode as base58
    let keypair_base58 = bs58::encode(&keypair_bytes).into_string();

    println!("Hex seed: {}", hex_seed);
    println!("Pubkey: {}", bs58::encode(verifying_key.as_bytes()).into_string());
    println!();
    println!("Base58 Keypair (for SOLANA_PRIVATE_KEY):");
    println!("{}", keypair_base58);

    Ok(())
}
