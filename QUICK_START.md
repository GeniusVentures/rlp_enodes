# 🚀 Quick Start: Chain Enodes Signing

## 30-Second Setup

```bash
# 1. Generate your signing key
./generate_signing_key.sh

# Copy the output: export SIGNING_KEY='...'

# 2. Set the environment variable
export SIGNING_KEY='...'

# 3. Run the tool
./filter_nodes

# 4. Check the signature
jq '.signature' output/chain_enodes.json
```

## What You Get

✅ **Authenticityproof**: Your `chain_enodes.json` is signed and verifiable  
✅ **Integrity**: Any modification to the file breaks the signature  
✅ **Ethereum-compatible**: Uses secp256k1 (same as Ethereum/EVM chains)  
✅ **Embedded metadata**: Signature is inside the JSON, easy to share  

## The Output

```json
{
  "base-mainnet": { ... },
  "ethereum-mainnet": { ... },
  ...
  "signature": "0x44ddc97e9a91c4123f5e8c7d9a2b...",
  "signerAddress": "0xc493439b0a36857e3ace4f4f2a68..."
}
```

## For CI/CD (GitHub Actions)

Add to your secrets:
```
SIGNING_KEY=Ine0Yl+P6g4vjXvMhmeAzMcZXxm/38FeFIMuWAX5Plo=
```

In your workflow:
```yaml
- name: Run filter_nodes
  env:
    SIGNING_KEY: ${{ secrets.SIGNING_KEY }}
  run: ./filter_nodes
```

## Safety Notes

⚠️ **Never commit `SIGNING_KEY` to version control**  
⚠️ **Store in CI/CD secrets only**  
⚠️ **Anyone with the key can sign files on your behalf**  

## Full Documentation

See `SIGNING.md` for:
- Detailed setup instructions
- Key rotation procedures  
- Signature verification
- Security best practices
- Troubleshooting

## Questions?

- **How do I verify a signature?** → See `verifyChainDataSignature()` in app.go
- **Can I use an existing key?** → Yes, encode it in base64 and set `SIGNING_KEY`
- **What if I don't set `SIGNING_KEY`?** → Files are generated unsigned (signature fields omitted)
- **Can I rotate keys?** → Yes, generate a new key and update `SIGNING_KEY`

---

**Status**: ✅ Ready to use  
**Build**: ✅ Compiles successfully  
**Tests**: ✅ Can be verified with `./test_signing.sh`

