//! Debug the exact call being made to the contract

use alloy::{
    primitives::{Address, FixedBytes, U256, keccak256, B256, Bytes},
    providers::ProviderBuilder,
    signers::{local::PrivateKeySigner, SignerSync},
    sol,
    sol_types::{eip712_domain, SolStruct, SolCall},
};
use std::str::FromStr;

sol! {
    #[sol(rpc)]
    interface IUSDC {
        function transferWithAuthorization(
            address from,
            address to,
            uint256 value,
            uint256 validAfter,
            uint256 validBefore,
            bytes32 nonce,
            uint8 v,
            bytes32 r,
            bytes32 s
        ) external;

        function authorizationState(address authorizer, bytes32 nonce) external view returns (bool);
        function DOMAIN_SEPARATOR() external view returns (bytes32);
    }
}

sol! {
    #[derive(Debug)]
    struct TransferWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }
}

const USDC_ADDRESS: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const RECIPIENT: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const PAYER_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Debug Contract Call ===\n");

    let usdc_address = Address::from_str(USDC_ADDRESS)?;
    let recipient = Address::from_str(RECIPIENT)?;
    let signer = PrivateKeySigner::from_str(PAYER_PRIVATE_KEY)?;
    let payer_address = signer.address();

    let rpc_url = "https://sepolia.base.org";
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse()?);
    let usdc = IUSDC::new(usdc_address, &provider);

    // Test data - use a fixed nonce for reproducibility
    let amount = U256::from(10000u64);
    let valid_after = U256::from(0u64);
    let valid_before = U256::from(1764755175u64);
    let nonce = FixedBytes::<32>::from([0u8; 32]);

    // Check if nonce is already used
    let nonce_used = usdc.authorizationState(payer_address, nonce).call().await?;
    println!("Nonce already used: {}", nonce_used);

    if nonce_used {
        println!("⚠️  This nonce has already been used! Try a different nonce.");
        return Ok(());
    }

    // Create signature
    let domain = eip712_domain! {
        name: "USDC",
        version: "2",
        chain_id: 84532,
        verifying_contract: usdc_address,
    };

    let transfer = TransferWithAuthorization {
        from: payer_address,
        to: recipient,
        value: amount,
        validAfter: valid_after,
        validBefore: valid_before,
        nonce,
    };

    let signing_hash = transfer.eip712_signing_hash(&domain);
    let signature = signer.sign_hash_sync(&signing_hash)?;
    let sig_bytes = signature.as_bytes();

    let r = FixedBytes::<32>::from_slice(&sig_bytes[0..32]);
    let s = FixedBytes::<32>::from_slice(&sig_bytes[32..64]);
    let v_raw = sig_bytes[64];
    // Use standard 27/28 format for v
    let v = v_raw;

    println!("\n=== Call Parameters ===");
    println!("from: {}", payer_address);
    println!("to: {}", recipient);
    println!("value: {}", amount);
    println!("validAfter: {}", valid_after);
    println!("validBefore: {}", valid_before);
    println!("nonce: 0x{}", hex::encode(nonce));
    println!("v: {}", v);
    println!("r: 0x{}", hex::encode(r));
    println!("s: 0x{}", hex::encode(s));

    // Get the calldata that would be sent
    let call = IUSDC::transferWithAuthorizationCall {
        from: payer_address,
        to: recipient,
        value: amount,
        validAfter: valid_after,
        validBefore: valid_before,
        nonce,
        v,
        r,
        s,
    };

    let calldata = call.abi_encode();
    println!("\n=== Encoded Calldata ({} bytes) ===", calldata.len());
    println!("0x{}", hex::encode(&calldata));

    // Try the call
    println!("\n=== Making Call ===");
    let result = usdc.transferWithAuthorization(
        payer_address,
        recipient,
        amount,
        valid_after,
        valid_before,
        nonce,
        v,
        r,
        s,
    ).call().await;

    match result {
        Ok(_) => println!("✓ Call succeeded!"),
        Err(e) => println!("❌ Call failed: {}", e),
    }

    Ok(())
}
