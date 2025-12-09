//! Debug EIP-712 signature computation

use alloy::{
    primitives::{Address, FixedBytes, U256, keccak256, B256},
    signers::{local::PrivateKeySigner, SignerSync},
    sol,
    sol_types::SolStruct,
};
use std::str::FromStr;

// The EIP-712 domain
sol! {
    #[derive(Debug)]
    struct EIP712Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }
}

// TransferWithAuthorization struct - must match USDC exactly
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

fn main() {
    // Test values
    let payer = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
    let recipient = Address::from_str("0x70997970C51812dc3A010C7d01b50e0d17dc79C8").unwrap();
    let usdc = Address::from_str("0x036CbD53842c5426634e7929541eC2318f3dCF7e").unwrap();
    let amount = U256::from(10000u64);
    let valid_after = U256::ZERO;
    let valid_before = U256::from(1765154180u64);
    let nonce_bytes: [u8; 32] = [0x1c, 0xe3, 0x2b, 0x41, 0xba, 0xcb, 0x16, 0x2a, 0xc0, 0x44, 0x42, 0x5b, 0x1f, 0x08, 0xd2, 0x1d, 0xb3, 0x65, 0x79, 0x09, 0xd4, 0xe8, 0x42, 0x8a, 0xc6, 0xb2, 0x83, 0x2a, 0x56, 0x93, 0x52, 0x2f];
    let nonce = FixedBytes::<32>::from(nonce_bytes);

    // Expected TRANSFER_WITH_AUTHORIZATION_TYPEHASH from contract
    let expected_typehash = "0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267";
    
    // Compute typehash from string
    let typehash_str = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";
    let computed_typehash = keccak256(typehash_str.as_bytes());
    println!("Computed typehash: 0x{}", hex::encode(computed_typehash));
    println!("Expected typehash: {}", expected_typehash);
    println!("Typehash match: {}", format!("0x{}", hex::encode(computed_typehash)) == expected_typehash);
    println!();

    // Check what alloy's SolStruct produces for typehash
    let transfer = TransferWithAuthorization {
        from: payer,
        to: recipient,
        value: amount,
        validAfter: valid_after,
        validBefore: valid_before,
        nonce,
    };
    
    // Get alloy's computed struct hash
    let alloy_struct_hash = transfer.eip712_hash_struct();
    println!("Alloy struct hash: 0x{}", hex::encode(alloy_struct_hash));
    
    // Manually compute struct hash like USDC does:
    // keccak256(abi.encode(TYPEHASH, from, to, value, validAfter, validBefore, nonce))
    let mut encoded = Vec::new();
    encoded.extend_from_slice(computed_typehash.as_slice()); // 32 bytes typehash
    encoded.extend_from_slice(&[0u8; 12]); // padding for address (12 zeros)
    encoded.extend_from_slice(payer.as_slice()); // 20 bytes address
    encoded.extend_from_slice(&[0u8; 12]); // padding for address
    encoded.extend_from_slice(recipient.as_slice()); // 20 bytes address
    encoded.extend_from_slice(&amount.to_be_bytes::<32>()); // 32 bytes uint256
    encoded.extend_from_slice(&valid_after.to_be_bytes::<32>()); // 32 bytes uint256
    encoded.extend_from_slice(&valid_before.to_be_bytes::<32>()); // 32 bytes uint256
    encoded.extend_from_slice(nonce.as_slice()); // 32 bytes bytes32
    
    let manual_struct_hash = keccak256(&encoded);
    println!("Manual struct hash: 0x{}", hex::encode(manual_struct_hash));
    println!("Struct hash match: {}", alloy_struct_hash == manual_struct_hash);
    println!();
    
    // Expected domain separator from contract
    let expected_domain_sep = "0x71f17a3b2ff373b803d70a5a07c046c1a2bc8e89c09ef722fcb047abe94c9818";
    
    // Compute domain separator manually
    let domain_typehash_str = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    let domain_typehash = keccak256(domain_typehash_str.as_bytes());
    println!("Domain typehash: 0x{}", hex::encode(domain_typehash));
    
    let name_hash = keccak256("USDC".as_bytes());
    let version_hash = keccak256("2".as_bytes());
    let chain_id = U256::from(84532u64); // Base Sepolia
    
    let mut domain_encoded = Vec::new();
    domain_encoded.extend_from_slice(domain_typehash.as_slice());
    domain_encoded.extend_from_slice(name_hash.as_slice());
    domain_encoded.extend_from_slice(version_hash.as_slice());
    domain_encoded.extend_from_slice(&chain_id.to_be_bytes::<32>());
    domain_encoded.extend_from_slice(&[0u8; 12]);
    domain_encoded.extend_from_slice(usdc.as_slice());
    
    let computed_domain_sep = keccak256(&domain_encoded);
    println!("Computed domain sep: 0x{}", hex::encode(computed_domain_sep));
    println!("Expected domain sep: {}", expected_domain_sep);
    println!("Domain sep match: {}", format!("0x{}", hex::encode(computed_domain_sep)) == expected_domain_sep);
    println!();
    
    // Compute final signing hash: keccak256("\x19\x01" || domainSeparator || structHash)
    let mut final_msg = Vec::new();
    final_msg.extend_from_slice(&[0x19, 0x01]);
    final_msg.extend_from_slice(computed_domain_sep.as_slice());
    final_msg.extend_from_slice(manual_struct_hash.as_slice());
    
    let signing_hash = keccak256(&final_msg);
    println!("Final signing hash: 0x{}", hex::encode(signing_hash));
    
    // Sign it
    let signer = PrivateKeySigner::from_str("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let signature = signer.sign_hash_sync(&signing_hash.into()).unwrap();
    println!("Signature: 0x{}", hex::encode(signature.as_bytes()));
    
    // Verify recovery
    let recovered = signature.recover_address_from_prehash(&signing_hash.into()).unwrap();
    println!("Recovered: {}", recovered);
    println!("Expected:  {}", payer);
    println!("Match: {}", recovered == payer);
}
