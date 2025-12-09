//! Check USDC contract status (paused, blacklist)

use alloy::{
    primitives::Address,
    providers::ProviderBuilder,
    sol,
};
use std::str::FromStr;

sol! {
    #[sol(rpc)]
    interface IUSDC {
        function paused() external view returns (bool);
        function isBlacklisted(address account) external view returns (bool);
        function balanceOf(address account) external view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);
    }
}

const USDC_ADDRESS: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const PAYER: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const RECIPIENT: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Check USDC Contract Status ===\n");

    let rpc_url = "https://sepolia.base.org";
    let usdc_address = Address::from_str(USDC_ADDRESS)?;
    let payer = Address::from_str(PAYER)?;
    let recipient = Address::from_str(RECIPIENT)?;

    let provider = ProviderBuilder::new().connect_http(rpc_url.parse()?);
    let usdc = IUSDC::new(usdc_address, &provider);

    // Check if paused
    let is_paused = usdc.paused().call().await?;
    println!("Contract paused: {}", is_paused);

    // Check blacklist
    let payer_blacklisted = usdc.isBlacklisted(payer).call().await?;
    let recipient_blacklisted = usdc.isBlacklisted(recipient).call().await?;
    println!("Payer blacklisted: {}", payer_blacklisted);
    println!("Recipient blacklisted: {}", recipient_blacklisted);

    // Check balances
    use alloy::primitives::U256;
    let payer_balance = usdc.balanceOf(payer).call().await?;
    let recipient_balance = usdc.balanceOf(recipient).call().await?;
    println!("\nPayer balance: {} ({})", payer_balance / U256::from(1_000_000), payer_balance);
    println!("Recipient balance: {} ({})", recipient_balance / U256::from(1_000_000), recipient_balance);

    if is_paused {
        println!("\n⚠️  Contract is PAUSED! Transfers will fail.");
    }
    if payer_blacklisted {
        println!("\n⚠️  Payer is BLACKLISTED! Transfers will fail.");
    }
    if recipient_blacklisted {
        println!("\n⚠️  Recipient is BLACKLISTED! Transfers will fail.");
    }

    Ok(())
}
