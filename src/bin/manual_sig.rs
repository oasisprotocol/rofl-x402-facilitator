//! Manually compute EIP-712 signing hash step by step to find discrepancy

use alloy::{
    primitives::{Address, FixedBytes, U256, keccak256, B256},
    providers::ProviderBuilder,
    signers::{local::PrivateKeySigner, SignerSync},
    sol,
    sol_types::{eip712_domain, SolStruct, Eip712Domain},
};
use std::str::FromStr;

sol! {
    #[sol(rpc)]
    interface IUSDC {
        function DOMAIN_SEPARATOR() external view returns (bytes32);
        function TRANSFER_WITH_AUTHORIZATION_TYPEHASH() external view returns (bytes32);
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
    println!("=== Manual EIP-712 Hash Computation ===\n");

    let usdc_address = Address::from_str(USDC_ADDRESS)?;
    let recipient = Address::from_str(RECIPIENT)?;
    let signer = PrivateKeySigner::from_str(PAYER_PRIVATE_KEY)?;
    let payer_address = signer.address();

    // Query contract for comparison
    let rpc_url = "https://sepolia.base.org";
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse()?);
    let usdc = IUSDC::new(usdc_address, &provider);

    let contract_domain_sep = usdc.DOMAIN_SEPARATOR().call().await?;
    let contract_type_hash = usdc.TRANSFER_WITH_AUTHORIZATION_TYPEHASH().call().await?;

    println!("=== Contract Values ===");
    println!("DOMAIN_SEPARATOR: 0x{}", hex::encode(contract_domain_sep));
    println!("TYPE_HASH: 0x{}", hex::encode(contract_type_hash));

    // Test data
    let amount = U256::from(10000u64);
    let valid_after = U256::from(0u64);
    let valid_before = U256::from(1764755175u64);
    let nonce = FixedBytes::<32>::from([0u8; 32]);

    println!("\n=== Test Data ===");
    println!("from: {}", payer_address);
    println!("to: {}", recipient);
    println!("value: {}", amount);
    println!("validAfter: {}", valid_after);
    println!("validBefore: {}", valid_before);
    println!("nonce: 0x{}", hex::encode(nonce));

    // === MANUAL COMPUTATION ===
    println!("\n=== Manual Computation ===");

    // 1. Type hash
    let manual_type_hash = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );
    println!("Manual type hash: 0x{}", hex::encode(manual_type_hash));
    println!("Match contract: {}", manual_type_hash.0 == contract_type_hash.0);

    // 2. Encode struct data
    // In EIP-712, each value is encoded as 32 bytes
    // addresses are left-padded with zeros
    let from_encoded = B256::left_padding_from(payer_address.as_slice());
    let to_encoded = B256::left_padding_from(recipient.as_slice());
    let value_encoded = amount.to_be_bytes::<32>();
    let valid_after_encoded = valid_after.to_be_bytes::<32>();
    let valid_before_encoded = valid_before.to_be_bytes::<32>();

    println!("\nEncoded values:");
    println!("from: 0x{}", hex::encode(from_encoded));
    println!("to: 0x{}", hex::encode(to_encoded));
    println!("value: 0x{}", hex::encode(value_encoded));
    println!("validAfter: 0x{}", hex::encode(valid_after_encoded));
    println!("validBefore: 0x{}", hex::encode(valid_before_encoded));
    println!("nonce: 0x{}", hex::encode(nonce));

    // 3. Struct hash = keccak256(type_hash || encoded_data)
    let struct_data = [
        manual_type_hash.as_slice(),
        from_encoded.as_slice(),
        to_encoded.as_slice(),
        &value_encoded,
        &valid_after_encoded,
        &valid_before_encoded,
        nonce.as_slice(),
    ].concat();
    let manual_struct_hash = keccak256(&struct_data);
    println!("\nManual struct hash: 0x{}", hex::encode(manual_struct_hash));

    // 4. Domain separator (manual)
    let domain_type_hash = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    let name_hash = keccak256("USDC");
    let version_hash = keccak256("2");
    let chain_id = 84532u64;
    let chain_id_bytes = {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&chain_id.to_be_bytes());
        bytes
    };

    let manual_domain_sep = keccak256(&[
        domain_type_hash.as_slice(),
        name_hash.as_slice(),
        version_hash.as_slice(),
        &chain_id_bytes,
        B256::left_padding_from(usdc_address.as_slice()).as_slice(),
    ].concat());
    println!("Manual domain separator: 0x{}", hex::encode(manual_domain_sep));
    println!("Match contract: {}", manual_domain_sep.0 == contract_domain_sep.0);

    // 5. Final digest = keccak256(0x1901 || domain_separator || struct_hash)
    let manual_digest = keccak256(&[
        &[0x19, 0x01],
        contract_domain_sep.as_slice(),
        manual_struct_hash.as_slice(),
    ].concat());
    println!("\nManual signing hash: 0x{}", hex::encode(manual_digest));

    // === ALLOY COMPUTATION ===
    println!("\n=== Alloy Computation ===");

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

    let alloy_domain_sep = domain.hash_struct();
    let alloy_struct_hash = transfer.eip712_hash_struct();
    let alloy_signing_hash = transfer.eip712_signing_hash(&domain);

    println!("Alloy domain separator: 0x{}", hex::encode(alloy_domain_sep));
    println!("Alloy struct hash: 0x{}", hex::encode(alloy_struct_hash));
    println!("Alloy signing hash: 0x{}", hex::encode(alloy_signing_hash));

    // Compare
    println!("\n=== Comparison ===");
    println!("Domain sep match: {}", manual_domain_sep == alloy_domain_sep);
    println!("Struct hash match: {}", manual_struct_hash == alloy_struct_hash);
    println!("Signing hash match: {}", manual_digest == alloy_signing_hash);

    // Sign with both and compare
    println!("\n=== Signatures ===");
    let sig_manual = signer.sign_hash_sync(&manual_digest)?;
    let sig_alloy = signer.sign_hash_sync(&alloy_signing_hash)?;

    println!("Manual signature: 0x{}", hex::encode(sig_manual.as_bytes()));
    println!("Alloy signature: 0x{}", hex::encode(sig_alloy.as_bytes()));

    // Recover addresses
    use alloy::primitives::Signature;
    let v = sig_manual.as_bytes()[64];
    let parity = v == 28;
    let recovered = Signature::from_bytes_and_parity(&sig_manual.as_bytes()[..64], parity)
        .recover_address_from_prehash(&manual_digest)?;
    println!("\nRecovered from manual: {}", recovered);
    println!("Expected: {}", payer_address);
    println!("Match: {}", recovered == payer_address);

    Ok(())
}
