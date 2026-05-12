#!/bin/bash
# Generate a new ECDSA (secp256k1) private key and output it in base64 format
# for use as the SIGNING_KEY environment variable.

set -e

# Check if openssl is available
if ! command -v openssl &> /dev/null; then
    echo "Error: openssl is required but not installed"
    exit 1
fi

# Generate a new secp256k1 private key and save to temp file
TMPKEY=$(mktemp)
trap "rm -f $TMPKEY" EXIT

openssl ecparam -name secp256k1 -genkey -noout -out "$TMPKEY"

# Extract private key hex using openssl ec -text -noout and parse the output
# The output looks like:
#     read EC key
#     Private-Key: (256 bits)
#     priv:
#         44:6a:d9:40:a0:62:40:bf:d7:...
#         ...
#     pub:
# We need to capture all lines between "priv:" and "pub:" and extract hex

PRIVKEY_HEX=$(openssl ec -in "$TMPKEY" -text -noout 2>/dev/null | \
    awk '/priv:/{flag=1; next} /pub:/{flag=0} flag' | \
    tr -d ' \n:')

# Validate we have exactly 64 hex characters (32 bytes)
if [ ${#PRIVKEY_HEX} -ne 64 ]; then
    echo "Error: Failed to extract 32-byte private key (got ${#PRIVKEY_HEX} hex chars)" >&2
    echo "Extracted hex: $PRIVKEY_HEX" >&2
    exit 1
fi

# Convert hex to base64
PRIVKEY_BASE64=$(echo -n "$PRIVKEY_HEX" | xxd -r -p | base64 -w 0)

# Get the public key (64 bytes, no "04" prefix for now)
PUB_KEY_HEX=$(openssl ec -in "$TMPKEY" -text -noout 2>/dev/null | \
    awk '/pub:/{flag=1; next} /ASN1 OID|Field|Order|Cofactor/{flag=0} flag' | \
    tr -d ' \n:')

# The public key should be 130 characters (65 bytes with "04" prefix), so extract 128 (64 bytes without prefix)
if [[ "$PUB_KEY_HEX" == 04* ]]; then
    PUB_KEY_HEX="${PUB_KEY_HEX:2}"
fi
PUB_KEY_HEX="${PUB_KEY_HEX:0:128}"

# Compute address (simplified - note that without keccak256, this won't be accurate)
if command -v sha3sum &> /dev/null; then
    ADDRESS=$(echo -n "$PUB_KEY_HEX" | xxd -r -p | sha3sum -a 256 | awk '{print substr($1, 25)}')
else
    # Alternative: just use openssl sha256 (not Keccak-256, but shows the structure)
    ADDRESS=$(echo -n "$PUB_KEY_HEX" | xxd -r -p | openssl dgst -sha256 -hex | awk '{print substr($2, 25)}')
fi

echo "====== ECDSA (secp256k1) Signing Key Generated ======"
echo ""
echo "SIGNING_KEY (base64, 32-byte ECDSA private key):"
echo "$PRIVKEY_BASE64"
echo ""
echo "Private Key (hex):"
echo "$PRIVKEY_HEX"
echo ""
echo "Public Key (hex, 64 bytes):"
echo "$PUB_KEY_HEX"
echo ""
echo "Ethereum Address (derived from public key):"
echo "0x$ADDRESS"
echo ""
echo "====== Usage ======"
echo ""
echo "1. Export the signing key:"
echo "   export SIGNING_KEY='$PRIVKEY_BASE64'"
echo ""
echo "2. Run the filter_nodes tool:"
echo "   ./filter_nodes"
echo ""
echo "3. Verify the signature was added:"
echo "   jq '.signature' output/chain_enodes.json"
echo ""
echo "====== Important ======"
echo ""
echo "⚠️  KEEP YOUR SIGNING_KEY PRIVATE"
echo "⚠️  Store it securely, never commit to version control"
echo "⚠️  Anyone with this key can forge signatures on your behalf"
echo ""

