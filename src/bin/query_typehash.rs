//! Query USDC contract for TRANSFER_WITH_AUTHORIZATION_TYPEHASH

use alloy::{
    primitives::{Address, keccak256},
    providers::ProviderBuilder,
    sol,
};
use std::str::FromStr;

sol! {
    #[sol(rpc)]
    interface IUSDC {
        function TRANSFER_WITH_AUTHORIZATION_TYPEHASH() external view returns (bytes32);
        function RECEIVE_WITH_AUTHORIZATION_TYPEHASH() external view returns (bytes32);
        function CANCEL_AUTHORIZATION_TYPEHASH() external view returns (bytes32);
        function name() external view returns (string);
        function version() external view returns (string);
    }
}

const USDC_ADDRESS: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Query USDC Type Hashes ===\n");

    let rpc_url = "https://sepolia.base.org";
    let usdc_address = Address::from_str(USDC_ADDRESS)?;
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse()?);
    let usdc = IUSDC::new(usdc_address, &provider);

    // Query contract values
    println!("Querying USDC contract at {}...\n", usdc_address);

    let name = usdc.name().call().await?;
    let version = usdc.version().call().await?;
    println!("name(): {}", name);
    println!("version(): {}", version);

    match usdc.TRANSFER_WITH_AUTHORIZATION_TYPEHASH().call().await {
        Ok(typehash) => {
            println!("\nContract TRANSFER_WITH_AUTHORIZATION_TYPEHASH: 0x{}", hex::encode(typehash));

            // Compare with expected
            let expected_typestring = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";
            let expected_hash = keccak256(expected_typestring);
            println!("Expected (EIP-3009): 0x{}", hex::encode(expected_hash));

            if typehash.0 == expected_hash.0 {
                println!("✓ Type hashes MATCH");
            } else {
                println!("❌ Type hashes DIFFER!");
                println!("\nThis contract uses a different type string for TransferWithAuthorization");
            }
        }
        Err(e) => {
            println!("\nTRANSFER_WITH_AUTHORIZATION_TYPEHASH() call failed: {}", e);
            println!("This contract might not support EIP-3009 TransferWithAuthorization");
        }
    }

    // Also check other type hashes if available
    if let Ok(typehash) = usdc.RECEIVE_WITH_AUTHORIZATION_TYPEHASH().call().await {
        println!("\nRECEIVE_WITH_AUTHORIZATION_TYPEHASH: 0x{}", hex::encode(typehash));
    }

    if let Ok(typehash) = usdc.CANCEL_AUTHORIZATION_TYPEHASH().call().await {
        println!("CANCEL_AUTHORIZATION_TYPEHASH: 0x{}", hex::encode(typehash));
    }

    Ok(())
}
