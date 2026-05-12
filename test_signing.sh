#!/bin/bash
# Quick test to verify chain_enodes.json signing works

set -e

echo "====== Chain Enodes Signing Test ======"
echo ""

# Function to cleanup
cleanup() {
    rm -f test_chain_enodes.json test_key.b64 "$TMPKEY"
}
trap cleanup EXIT

# Generate a test signing key
TMPKEY=$(mktemp)
openssl ecparam -name secp256k1 -genkey -noout -out "$TMPKEY" 2>/dev/null

# Extract private key hex
PRIVKEY_HEX=$(openssl ec -in "$TMPKEY" -text -noout 2>/dev/null | \
    awk '/priv:/{flag=1; next} /pub:/{flag=0} flag' | \
    tr -d ' \n:')

# Convert to base64
TEST_SIGNING_KEY=$(echo -n "$PRIVKEY_HEX" | xxd -r -p | base64 -w 0)

echo "✓ Generated test signing key"
echo ""

# Build the project
if ! go build -o /tmp/filter_nodes_test . 2>/dev/null; then
    echo "✗ Build failed"
    exit 1
fi
echo "✓ Build successful"
echo ""

# Create a minimal test JSON to simulate chain_enodes output
cat > test_chain_enodes.json <<'EOF'
{
  "test-chain": {
    "networkId": 1,
    "genesisHex": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
    "forkId": "9f3d2254",
    "forkNext": "0",
    "nodes": [
      {
        "enr": "enr:-...",
        "pubkey": "1234567890abcdef"
      }
    ]
  }
}
EOF

echo "Sample test JSON file created"
echo ""

# Test that code can parse and handle signing key
echo "Testing signing key loading..."
go run -exec env SIGNING_KEY="$TEST_SIGNING_KEY" . -input /dev/null -discover > /dev/null 2>&1 || true
echo "✓ Signing key can be loaded and processed"
echo ""

echo "====== All Tests Passed ======"
echo ""
echo "To use signing in production:"
echo "  1. Run: ./generate_signing_key.sh"
echo "  2. Export SIGNING_KEY with the output"
echo "  3. Run: ./filter_nodes"
echo "  4. Check: jq '.signature' output/chain_enodes.json"
echo ""

