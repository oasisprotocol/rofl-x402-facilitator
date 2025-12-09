//! Direct verification of EIP-712 signature against USDC contract
//! Bypasses x402_rs to isolate the issue

use alloy::{
    primitives::{Address, FixedBytes, U256},
    providers::ProviderBuilder,
    signers::{local::PrivateKeySigner, SignerSync},
    sol,
    sol_types::{eip712_domain, SolStruct},
};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

// USDC contract interface
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

        function balanceOf(address account) external view returns (uint256);
        function DOMAIN_SEPARATOR() external view returns (bytes32);
    }
}

// EIP-712 struct
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
    println!("=== Direct USDC Signature Verification ===\n");

    let rpc_url = "https://sepolia.base.org";
    let usdc_address = Address::from_str(USDC_ADDRESS)?;
    let recipient = Address::from_str(RECIPIENT)?;

    let signer = PrivateKeySigner::from_str(PAYER_PRIVATE_KEY)?;
    let payer_address = signer.address();

    println!("Payer: {}", payer_address);
    println!("Recipient: {}", recipient);

    // Connect to provider
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse()?);
    let usdc = IUSDC::new(usdc_address, &provider);

    // Check balance
    let balance = usdc.balanceOf(payer_address).call().await?;
    println!("Payer USDC balance: {} (raw: {})", balance / U256::from(1_000_000), balance);

    if balance == U256::ZERO {
        println!("\n⚠️  Payer has no USDC! Get testnet USDC from: https://faucet.circle.com/");
        return Ok(());
    }

    // Get contract's domain separator
    let contract_domain_sep = usdc.DOMAIN_SEPARATOR().call().await?;
    println!("Contract DOMAIN_SEPARATOR: 0x{}", hex::encode(contract_domain_sep));

    // Create our domain
    let domain = eip712_domain! {
        name: "USDC",
        version: "2",
        chain_id: 84532,
        verifying_contract: usdc_address,
    };

    let our_domain_sep = domain.hash_struct();
    println!("Our domain separator: 0x{}", hex::encode(our_domain_sep));

    if contract_domain_sep != our_domain_sep {
        println!("❌ Domain separator MISMATCH!");
        return Ok(());
    }
    println!("✓ Domain separators match");

    // Payment params
    let amount = U256::from(10000u64); // 0.01 USDC
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let valid_after = U256::from(0u64);
    let valid_before = U256::from(now + 3600);
    let nonce_bytes: [u8; 32] = rand::random();
    let nonce = FixedBytes::<32>::from(nonce_bytes);

    println!("\n--- Creating Signature ---");
    println!("Amount: {} USDC", amount);
    println!("Valid after: {}", valid_after);
    println!("Valid before: {}", valid_before);
    println!("Nonce: 0x{}", hex::encode(nonce));

    // Create the struct
    let transfer = TransferWithAuthorization {
        from: payer_address,
        to: recipient,
        value: amount,
        validAfter: valid_after,
        validBefore: valid_before,
        nonce,
    };

    // Compute signing hash
    let signing_hash = transfer.eip712_signing_hash(&domain);
    println!("Signing hash: 0x{}", hex::encode(signing_hash));

    // Sign
    let signature = signer.sign_hash_sync(&signing_hash)?;
    let sig_bytes = signature.as_bytes();
    println!("Raw signature (65 bytes): 0x{}", hex::encode(sig_bytes));

    // Extract v, r, s
    let r = FixedBytes::<32>::from_slice(&sig_bytes[0..32]);
    let s = FixedBytes::<32>::from_slice(&sig_bytes[32..64]);
    let v = sig_bytes[64];

    println!("r: 0x{}", hex::encode(r));
    println!("s: 0x{}", hex::encode(s));
    println!("v: {}", v);

    // Recover signer to verify
    use alloy::primitives::Signature;
    // v is 27 or 28, parity is odd (v=28 means parity=true)
    let parity = v == 28;
    let sig = Signature::from_bytes_and_parity(&sig_bytes[..64], parity);
    let recovered = sig.recover_address_from_prehash(&signing_hash)?;
    println!("\n--- Signature Recovery ---");
    println!("Expected signer: {}", payer_address);
    println!("Recovered signer: {}", recovered);

    if recovered == payer_address {
        println!("✓ Signature recovery matches!");
    } else {
        println!("❌ Signature recovery MISMATCH!");
        return Ok(());
    }

    // Now try to call the contract directly (will fail if signature invalid)
    println!("\n--- Calling Contract (static call) ---");

    let call = usdc.transferWithAuthorization(
        payer_address,
        recipient,
        amount,
        valid_after,
        valid_before,
        nonce,
        v,
        r,
        s,
    );

    // Use eth_call to simulate without spending gas
    match call.call().await {
        Ok(_) => {
            println!("✓ Static call succeeded! Signature is valid.");
            println!("\nTo actually execute, run with --execute flag");
        }
        Err(e) => {
            println!("❌ Static call failed: {}", e);
        }
    }

    Ok(())
}
