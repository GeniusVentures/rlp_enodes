# Chain Enodes Signing

The `chain_enodes.json` file can now be cryptographically signed to prove authenticity and integrity. The signature is generated using ECDSA (secp256k1) and embedded directly in the JSON file.

## Overview

- **Algorithm**: ECDSA (secp256k1) — the same cryptography standard used by Ethereum
- **Storage**: Signature and signer address are included in the `chain_enodes.json` file itself
- **Key Management**: Private key is securely supplied via the `SIGNING_KEY` environment variable

## Setup

### 1. Generate a Signing Key

```bash
./generate_signing_key.sh
```

This creates a new ECDSA private key and outputs it in base64-encoded format suitable for the environment variable. Save the output carefully — you'll need it to sign files.

Alternatively, to just print the key from an existing private key:

```bash
# If you already have a secp256k1 private key, convert it to base64:
openssl ec -in your-key.pem -text -noout | grep -A 2 "priv:" | tr -d ' ' | tr -d '\n' | sed 's/priv://' | sed 's/pub:.*//' | xxd -r -p | base64
```

### 2. Use the Key to Sign Files

Set the environment variable and run the tool:

```bash
export SIGNING_KEY="<base64-encoded-private-key>"
./filter_nodes  # or any command that generates chain_enodes.json
```

The resulting `output/chain_enodes.json` will include:
- `signature`: A hex-encoded ECDSA signature of the JSON data (65 bytes, with "0x" prefix)
- `signerAddress`: The Ethereum address derived from the signing key

### 3. Verify the Output

The file will look like:

```json
{
  "base-mainnet": {
    "networkId": 8453,
    "genesisHex": "f712aa9241cc24369b143cf6dce85f0902a9731e70d66818a3a5845b296c73dd",
    "forkId": "...",
    "forkNext": "...",
    "nodes": [
      ...
    ]
  },
  "ethereum-mainnet": {
    ...
  },
  "signature": "0x<hex-encoded-signature>",
  "signerAddress": "0x<ethereum-address>"
}
```

**Note:** The signature is the same for all chains in the file — it signs the entire `chain_enodes.json` document.

## Running Without Signing

If `SIGNING_KEY` is not set, the tool runs normally without signing. The `signature` and `signerAddress` fields will be empty (omitted from the JSON).

## Key Rotation

To rotate to a new signing key:

1. Generate a new key: `./generate_signing_key.sh`
2. Update `SIGNING_KEY` in your CI/CD environment or secrets manager
3. Re-run the tool to regenerate `chain_enodes.json` with the new signature

## Security Notes

- Keep your `SIGNING_KEY` private. Never commit it to version control.
- Use your CI/CD platform's secret management to store and inject the key during builds.
- The signature guarantees authenticity (that the file came from someone with the private key) and integrity (that the file has not been modified since signing).
- Verification of the signature requires the signer's public key (derivable from `signerAddress` if you know the signing key).

## Example: GitHub Actions Workflow

```yaml
on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours

jobs:
  filter-nodes:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.20'
      - name: Build
        run: go build -o filter_nodes .
      - name: Run with signing
        env:
          SIGNING_KEY: ${{ secrets.SIGNING_KEY }}
        run: ./filter_nodes
      - name: Commit and push
        run: |
          git add output/
          git commit -m "Auto-update: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
          git push
```

## Implementation Details

### Signing Process

1. Create a clean copy of all chain data with `signature` and `signerAddress` fields set to empty
2. Marshal this data to deterministic JSON (canonical ordering)
3. Compute SHA-256 hash of the JSON
4. Sign the hash with the ECDSA private key (secp256k1)
5. Encode the signature (r + s components) as hex, prefixed with "0x"
6. Derive the signer address (Ethereum address) from the public key
7. Include both in the final JSON output

### Signature Format

- **r component**: 32 bytes (the first half of the 64-byte signature)
- **s component**: 32 bytes (the second half)
- **Hex format**: "0x" + 2 hex chars per byte = "0x" + 128 hex characters total

### Determinism

To ensure signatures are reproducible and verifiable:
- JSON is marshaled with standard Go `json.Marshal` (which sorts object keys alphabetically)
- The same data always produces the same signature
- Verification requires hashing the same cleaned data and comparing signatures

## Troubleshooting

**"decode base64 signing key: illegal base64 data"**
- Ensure the `SIGNING_KEY` is valid base64-encoded ECDSA private key (32 bytes)
- Use `./generate_signing_key.sh` to create a properly formatted key

**Signature is different each time**
- This should not happen. If it does, check that:
  - The same `SIGNING_KEY` is being used
  - The input `all.json` or chain configs haven't changed between runs
  - No other processes are modifying chain data between signing

**Binary won't compile**
- Ensure you have Go 1.18+ (ecdsa.Sign requires it)
- Run `go mod tidy` to fetch dependencies

