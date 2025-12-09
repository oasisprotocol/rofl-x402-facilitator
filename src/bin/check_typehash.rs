//! Compare EIP-712 type hashes

use alloy::{
    primitives::{keccak256, Address, FixedBytes, U256},
    sol,
    sol_types::SolStruct,
};

// Our struct definition
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
    println!("=== EIP-712 Type Hash Comparison ===\n");

    // What we expect (from EIP-3009 spec)
    let expected_type_string = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";
    let expected_type_hash = keccak256(expected_type_string);
    println!("Expected type string: {}", expected_type_string);
    println!("Expected type hash: 0x{}", hex::encode(expected_type_hash));

    // What alloy generates
    // The SolStruct trait has an eip712_encode_type() method that returns the type string
    println!("\nAlloy struct name: {}", TransferWithAuthorization::NAME);

    // We can compute the struct hash to see what alloy uses
    let test_transfer = TransferWithAuthorization {
        from: Address::ZERO,
        to: Address::ZERO,
        value: U256::ZERO,
        validAfter: U256::ZERO,
        validBefore: U256::ZERO,
        nonce: FixedBytes::<32>::ZERO,
    };

    let struct_hash = test_transfer.eip712_hash_struct();
    println!("Alloy struct hash (with zero values): 0x{}", hex::encode(struct_hash));

    // Let's manually compute what the struct hash SHOULD be with zero values
    // struct_hash = keccak256(type_hash || encoded_data)
    // For zero values, encoded_data is all zeros

    let zero_address_encoded = [0u8; 32]; // address encoded as bytes32
    let zero_uint256 = [0u8; 32];
    let zero_bytes32 = [0u8; 32];

    let manual_struct_hash = keccak256(
        &[
            expected_type_hash.as_slice(),
            &zero_address_encoded, // from
            &zero_address_encoded, // to
            &zero_uint256,         // value
            &zero_uint256,         // validAfter
            &zero_uint256,         // validBefore
            &zero_bytes32,         // nonce
        ].concat()
    );
    println!("Manual struct hash (with expected type hash): 0x{}", hex::encode(manual_struct_hash));

    if struct_hash == manual_struct_hash {
        println!("\n✓ Type hashes match!");
    } else {
        println!("\n❌ Type hashes DIFFER!");
        println!("This means alloy is using a different type string");
    }
}
