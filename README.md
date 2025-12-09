# Trustless x402 Facilitator

A trustless [x402 facilitator](https://x402.gitbook.io/x402/core-concepts/facilitator) built on [x402-rs](https://github.com/x402-rs/x402-rs) for verifying and settling blockchain payments across multiple networks.

## Why ROFL?

Running the facilitator inside a Trusted Execution Environment (TEE) via [Oasis ROFL](https://docs.oasis.io/rofl/) provides strong guarantees that make the facilitator trustless:

### Censorship Resistance
The facilitator cannot selectively block, delay, or censor valid payment transactions. The code executes exactly as written inside the TEE - the Oasis Network automatically verifies this through remote attestation. Neither the operator nor any external party can modify the behavior.

### Non-Custodial Key Management
Private keys are generated inside the TEE using [ROFL KMS](https://docs.oasis.io/build/rofl/) and never leave the secure enclave. The operator never sees or has access to the signing keys, eliminating the risk of key theft or misuse.

### Verifiable Execution
Anyone can verify exactly what code is running by checking the ROFL registry on Oasis Sapphire. To verify:

> **Note:** Requires [Oasis CLI](https://github.com/oasisprotocol/cli) version 0.18+ or commit [1323206](https://github.com/oasisprotocol/cli/commit/1323206bcc66da9cd6b6725049d78d98974a749a) or later.

```bash
# Clone this repository and verify it matches the deployed instance
oasis rofl build --verify --deployment testnet

# Example output:
# Building a ROFL application...
# App ID:     rofl1qrztf3jgz56358zld8yghmy58gvzu29xcvz0alp0
# ...
# Verification successful.
```

This command rebuilds the code reproducibly and compares the resulting enclave measurements against the on-chain registry. The on-chain state is attested by the TEE hardware, so matching measurements prove the exact source code in this repository is what's running in the enclave.

### Attested TLS (aTLS)

ROFL instances expose their TLS public key in the on-chain instance metadata. The TLS private key is generated inside the TEE and never leaves it, ensuring only the attested enclave can terminate TLS connections.

To verify the live deployment's TLS certificate matches the on-chain attestation:

```bash
# 1. Query the ROFL app to get the attested TLS public key
oasis rofl show --deployment testnet
# Look for: net.oasis.tls.pk: MFkwEwYH...

# 2. Extract the TLS public key from the live service
echo | openssl s_client -servername x402.updev.si -connect x402.updev.si:443 2>/dev/null | \
  openssl x509 -pubkey -noout | \
  openssl ec -pubin -outform DER 2>/dev/null | \
  base64
```

If both keys match, this proves:
- Your HTTPS connection terminates inside the TEE
- The TLS private key exists only inside the enclave and cannot be extracted
- No external entity (operator, proxy, network) can intercept or modify traffic

### Fair & Non-Discriminatory
All valid payments are processed equally. The facilitator cannot front-run transactions, reorder them for profit, or discriminate based on sender, recipient, or payment amount.

### Operator Protection
Because operators cannot access keys or modify execution, they cannot be coerced or compelled to censor transactions. The technical inability to interfere provides legal and practical protection.

> Note: The facilitator also works in standalone mode with manually provided keys, but you lose these trustless guarantees. Standalone mode is suitable for development, testing, or scenarios where you trust the operator.

## Supported Networks

The facilitator supports multiple blockchain networks through RPC endpoints:

### EVM Networks
- Base (Mainnet & Sepolia Testnet)
- Polygon (Mainnet & Amoy Testnet)
- Avalanche (Mainnet & Fuji Testnet)
- Sei (Mainnet & Testnet)
- XDC (Mainnet)
- XRPL EVM

### Non-EVM Networks
- Solana (Mainnet & Devnet)

## Local Development

For local development and testing, you can run the facilitator with mock keys:

```bash
docker run -p 8080:8080 \
  -e RPC_URL_BASE_SEPOLIA=https://sepolia.base.org \
  -e RPC_URL_SOLANA_DEVNET=https://api.devnet.solana.com \
  -e DEBUG_MOCK_KMS=true \
  ptrusr/trustless-x402-facilitator
```

### Configuration

Copy and edit the example environment file:

```bash
cp .env.example .env
```

Key settings:

```env
# RPC Endpoints (required - at least one network)
RPC_URL_BASE_SEPOLIA=https://sepolia.base.org
RPC_URL_SOLANA_DEVNET=https://api.devnet.solana.com

# For local development only (uses env var keys instead of ROFL KMS)
DEBUG_MOCK_KMS=true
EVM_PRIVATE_KEY=0x...
SOLANA_PRIVATE_KEY=...
```

The server starts on `http://0.0.0.0:8080` by default.

## Configuration Options

### Key Management

By default, the facilitator uses **ROFL KMS** to generate keys securely inside the TEE. Keys are derived deterministically, so the same addresses are generated across restarts.

For local development/testing, set `DEBUG_MOCK_KMS=true` to use manually provided keys instead:

| Variable | Description |
|----------|-------------|
| `DEBUG_MOCK_KMS` | Set to `true` to use environment variable keys instead of ROFL KMS |
| `EVM_PRIVATE_KEY` | Hex-formatted private key with `0x` prefix (only when `DEBUG_MOCK_KMS=true`) |
| `SOLANA_PRIVATE_KEY` | Base58-encoded keypair (only when `DEBUG_MOCK_KMS=true`) |

### Network RPC Endpoints

Configure RPC endpoints for the networks you want to support:

```env
# Testnets (recommended for development)
RPC_URL_BASE_SEPOLIA=https://sepolia.base.org
RPC_URL_POLYGON_AMOY=https://rpc-amoy.polygon.technology
RPC_URL_SOLANA_DEVNET=https://api.devnet.solana.com

# Mainnets (production)
RPC_URL_BASE=https://mainnet.base.org
RPC_URL_POLYGON=https://polygon-rpc.com
RPC_URL_SOLANA=https://api.mainnet-beta.solana.com
RPC_URL_AVALANCHE=https://api.avax.network/ext/bc/C/rpc
RPC_URL_SEI=https://evm-rpc.sei-apis.com
RPC_URL_XDC=https://rpc.xinfin.network
```

## Deployment

### Live Deployment

A live instance is running at **https://x402.updev.si** on the Oasis Testnet.

```bash
# Check health and supported networks
curl https://x402.updev.si/health
# {"kinds":[{"network":"solana-devnet","scheme":"exact","x402Version":1,...},{"network":"base-sepolia",...}]}
```

### Testing the Live Deployment

You can run E2E tests against the live deployment to verify it's working.

#### EVM (Base Sepolia)

```bash
# 1. Generate a new EVM keypair for testing
cast wallet new
# Output: Address: 0x... Private key: 0x...

# 2. Fund your test wallet with:
#    - ETH on Base Sepolia: https://www.alchemy.com/faucets/base-sepolia
#    - USDC on Base Sepolia: https://faucet.circle.com/

# 3. Run the EVM E2E test against the live deployment
EVM_PAYER_KEY="<your-private-key>" \
FACILITATOR_URL=https://x402.updev.si \
cargo run --bin e2e_test
```

Example successful output:
```
=== x402 Facilitator E2E Test ===
Facilitator: https://x402.updev.si
...
3. Verifying payment with facilitator...
   Status: 200 OK
   Response: {"isValid": true, "payer": "0x..."}
4. Settling payment on-chain...
   Status: 200 OK
   Response: {"success": true, "transaction": "0x..."}
=== E2E Test Complete ===
```

> **Note:** The default Hardhat test account (`0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`) has EIP-7702 delegation code on Base Sepolia, which causes signature verification to fail. Always use a fresh EOA for testing.

#### Solana (Devnet)

```bash
# 1. Generate a test Solana keypair (or use your own)
cargo run --bin gen_test_keys

# 2. Fund your test wallet with:
#    - SOL on Devnet: https://faucet.solana.com/
#    - USDC on Devnet: https://faucet.circle.com/

# 3. Run the Solana E2E test against the live deployment
SOLANA_PAYER_KEY="<your-base58-private-key>" \
FACILITATOR_URL=https://x402.updev.si \
cargo run --bin e2e_test_solana
```

Example successful output:
```
=== x402 Facilitator Solana E2E Test ===
Facilitator: https://x402.updev.si
...
4. Verifying payment with facilitator...
   Status: 200 OK
   Response: {"isValid": true, "payer": "..."}
5. Settling payment on-chain...
   Status: 200 OK
   Response: {"success": true, "transaction": "..."}
=== Solana E2E Test Complete ===
```

### ROFL App Deployment

When deploying as an Oasis ROFL application, the facilitator automatically uses ROFL KMS for secure key management. Deploy using the [Oasis ROFL documentation](https://docs.oasis.io/rofl/).

The facilitator will:
- Connect to ROFL KMS on startup
- Generate deterministic EVM and Solana keys
- Publish addresses to ROFL metadata for on-chain discovery
- Log the generated addresses for funding

### Funding the Facilitator

The facilitator needs funds to pay gas fees when settling payments on-chain. The facilitator addresses are published to the ROFL registry on-chain and can be discovered using the Oasis CLI:

```bash
# Query the ROFL app metadata on Sapphire Testnet
oasis rofl show --deployment testnet

# The Replicas section will show the facilitator addresses:
# === Replicas ===
# - RAK: ...
#   Metadata:
#     net.oasis.app.evm_address: 0x74093a47F007a660E79731D9AAf3AD8044Efb8F6
#     net.oasis.app.solana_address: GqBpKwHWEhM4FpfvVbuXK1jjMMsFW6efcfhVXNwiZwnq
```

You can also check the startup logs:
```
INFO trustless_x402_facilitator: EVM facilitator address: 0x...
INFO trustless_x402_facilitator: Solana facilitator address: ...
```

Fund these addresses on each network you want to support:

| Network | Token Needed | Faucet |
|---------|--------------|--------|
| Base Sepolia | ETH | [Alchemy Faucet](https://www.alchemy.com/faucets/base-sepolia) |
| Polygon Amoy | MATIC | [Polygon Faucet](https://faucet.polygon.technology/) |
| Solana Devnet | SOL | [Solana Faucet](https://faucet.solana.com/) |

For mainnet deployments, transfer native tokens (ETH, MATIC, SOL, etc.) to the facilitator addresses. The facilitator only needs enough to cover gas fees - it does not custody user funds.

### Docker Deployment (Standalone)

For standalone deployment without ROFL:

```bash
# Use the published image
docker run -p 8080:8080 --env-file .env ptrusr/trustless-x402-facilitator

# Or build your own
docker build -t trustless-x402-facilitator .
docker run -p 8080:8080 --env-file .env trustless-x402-facilitator
```

## Security Considerations

1. **Private Key Management**
   - **ROFL Mode (Recommended)**: Keys are generated inside the TEE and never exposed
   - **Standalone Mode**: Store private keys securely using secrets managers
   - Never commit `.env` files with private keys to version control

2. **Network Access**
   - Use firewall rules to restrict access to the facilitator
   - Consider using a reverse proxy (nginx, caddy) for TLS termination
   - Implement rate limiting at the infrastructure level

3. **RPC Endpoints**
   - Use authenticated RPC endpoints when available
   - Monitor RPC usage to avoid rate limits
   - Consider running your own RPC nodes for production

## License

This project uses the [x402-rs](https://github.com/x402-rs/x402-rs) library. See the x402-rs repository for licensing information.
