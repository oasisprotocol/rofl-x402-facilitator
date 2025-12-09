//! Query USDC contract to get correct EIP-712 domain parameters

use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    sol,
};
use std::str::FromStr;

sol! {
    #[sol(rpc)]
    interface USDC {
        function name() external view returns (string);
        function version() external view returns (string);
        function DOMAIN_SEPARATOR() external view returns (bytes32);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = "https://sepolia.base.org";
    let usdc_address = Address::from_str("0x036CbD53842c5426634e7929541eC2318f3dCF7e")?;
    
    let provider = ProviderBuilder::new().on_http(rpc_url.parse()?);
    let usdc = USDC::new(usdc_address, &provider);
    
    println!("Querying USDC contract at {} on Base Sepolia...\n", usdc_address);
    
    // Get name
    match usdc.name().call().await {
        Ok(name) => println!("name(): \"{}\"", name),
        Err(e) => println!("name() failed: {}", e),
    }
    
    // Get version
    match usdc.version().call().await {
        Ok(version) => println!("version(): \"{}\"", version),
        Err(e) => println!("version() failed: {}", e),
    }
    
    // Get domain separator
    match usdc.DOMAIN_SEPARATOR().call().await {
        Ok(separator) => println!("DOMAIN_SEPARATOR(): 0x{}", hex::encode(separator)),
        Err(e) => println!("DOMAIN_SEPARATOR() failed: {}", e),
    }
    
    // Now let's compute what we think it should be
    println!("\n--- Computing expected domain separator ---");
    
    use alloy::primitives::keccak256;
    
    // EIP-712 domain type hash
    let domain_type_hash = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    println!("Domain type hash: 0x{}", hex::encode(domain_type_hash));
    
    // Try with "USDC" and version "2" (actual contract values)
    let name_hash = keccak256("USDC");
    let version_hash = keccak256("2");
    let chain_id: [u8; 32] = {
        let mut bytes = [0u8; 32];
        bytes[31] = 84532u32.to_be_bytes()[3];
        bytes[30] = 84532u32.to_be_bytes()[2];
        bytes[29] = 84532u32.to_be_bytes()[1];
        bytes[28] = 84532u32.to_be_bytes()[0];
        bytes
    };

    let computed = keccak256(
        &[
            domain_type_hash.as_slice(),
            name_hash.as_slice(),
            version_hash.as_slice(),
            &chain_id,
            &alloy::primitives::B256::left_padding_from(usdc_address.as_slice()).0,
        ].concat()
    );
    println!("Computed with name='USDC', version='2': 0x{}", hex::encode(computed));
    
    Ok(())
}
