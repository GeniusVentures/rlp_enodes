# rlp_discv4_nodes — EVM Bootstrap Node Filter

Automated system that downloads the latest
[`all.json`](https://github.com/ethereum/discv4-dns-lists) crawl from the
Ethereum discv4-dns-lists repository, filters nodes by EVM-compatible chain,
selects only those advertising the dominant (current-head) fork ID, ranks them
by score and recency, and writes clean JSON files of the top bootstrap peers
for use with your discv4 peer-discovery library.

## Output structure

Each chain produces a single file directly in `output/`:

```
output/
  ethereum-mainnet.json
  ethereum-sepolia.json
  ethereum-holesky.json
  ethereum-hoodi.json
  bnb-smart-chain.json
  bnb-smart-chain-testnet.json
  polygon-mainnet.json
  polygon-amoy.json
  base-mainnet.json
  base-sepolia.json
  gnosis-chain.json
  .state          ← SHA-256 of last processed all.json (for change detection)
```

Each `{chain}.json` is an array of objects sorted by `score` (descending) then
`lastResponse` (most recent first), capped at `topN` (default 100):

```json
[
  {
    "enr":          "enr:-...",
    "nodeId":       "04d70a61...",
    "score":        3371,
    "lastResponse": "2026-03-14T20:54:48Z",
    "forkId":       "4d518ce1",
    "forkNext":     0,
    "ip":           "162.55.86.114",
    "port":         30311
  },
  ...
]
```

## Automation

A [GitHub Actions workflow](.github/workflows/update.yml) runs every 6 hours
but **only regenerates output when `all.json` has actually changed** (SHA-256
comparison against `output/.state`).  It also triggers on pushes to `main`
that change source files, and can be run on-demand.

## Local usage

```bash
# Build
go build -o filter_nodes .

# Run (downloads all.json from the internet)
./filter_nodes

# Use a local copy of all.json (faster for development / testing)
./filter_nodes -input /path/to/all.json

# Discovery mode: print ranked fork-hash summary to identify unknown chains
./filter_nodes -discover

# Combine: discovery on a local file
./filter_nodes -input /path/to/all.json -discover
```

## Supported filter strategies

| Strategy          | Description |
|-------------------|-------------|
| `geth_network`    | Uses `go-ethereum`'s `forkid.NewStaticFilter` to accept **any** node on the same genesis chain regardless of fork level.  Supported networks: `mainnet`, `sepolia`, `holesky`, `hoodi`. |
| `enr_field`       | Accepts nodes that carry a specific ENR key (e.g. `bsc` for BNB Smart Chain). |
| `fork_hash_list`  | Accepts nodes whose `eth` fork hash is in the configured `forkHashes` list. |

### Compound AND filter

Set **both** `enrField` and `forkHashes` together with either `"enr_field"` or
`"fork_hash_list"` as `filterType` to require both conditions simultaneously.
This is used to distinguish BNB Smart Chain testnet (Chapel) from mainnet —
both advertise the `bsc` ENR key but at different fork hashes.

## Configured chains

| Chain | Chain ID | Filter |
|-------|----------|--------|
| Ethereum Mainnet | 1 | `geth_network: mainnet` |
| Ethereum Sepolia | 11155111 | `geth_network: sepolia` |
| Ethereum Holesky | 17000 | `geth_network: holesky` |
| Ethereum Hoodi | 560048 | `geth_network: hoodi` |
| BNB Smart Chain | 56 | `enr_field: bsc` |
| BNB Smart Chain Testnet | 97 | `enr_field: bsc` + `fork_hash_list` (compound) |
| Polygon PoS Mainnet | 137 | `fork_hash_list` |
| Polygon Amoy Testnet | 80002 | `fork_hash_list` |
| Base Mainnet | 8453 | `fork_hash_list` |
| Base Sepolia Testnet | 84532 | `fork_hash_list` |
| Gnosis Chain (xDai) | 100 | `fork_hash_list` |

## Adding or updating chains

1. Edit `chains_config.json`.
2. Run `./filter_nodes -discover` (or `-input` + `-discover`) to print a ranked
   table of all fork hashes observed in the crawl.  Chain-specific ENR keys
   (e.g. `bsc(2709)`) help identify which hash belongs to which chain.
3. Cross-reference the top hashes with the chain's release notes.
4. Add the hash(es) to the chain's `forkHashes` array.
5. Re-run to verify results.

### Known Ethereum fork hash progression (March 2026)

| Chain   | Fork     | Hash       | Timestamp / Block |
|---------|----------|------------|-------------------|
| Mainnet | Cancun   | `9f3d2254` | 1710338135        |
| Mainnet | Prague   | `c376cf8b` | 1746612311        |
| Mainnet | Osaka    | `5167e2a6` | 1764798551        |
| Mainnet | BPO1     | `cba2a1c0` | 1765290071        |
| Mainnet | **BPO2** | `07c9462e` | 1767747671 (current) |
| Sepolia | Cancun   | `88cf81d9` | 1706655072        |
| Sepolia | **BPO2** | `268956b6` | current           |
| Holesky | Cancun   | `9b192ad0` | 1707305664        |
| Holesky | **BPO2** | `9bc6cb31` | current           |
| Hoodi   | Prague   | `0929e24e` | 1742999832 (current) |

## Dependencies

- [`github.com/ethereum/go-ethereum`](https://github.com/ethereum/go-ethereum) —
  for ENR decoding (`p2p/enode`, `p2p/enr`), fork ID filtering (`core/forkid`),
  and chain configurations (`params`).
