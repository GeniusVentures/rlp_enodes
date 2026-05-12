# CHECKPOINT

## Files examined
- `main.go`
- `chains_config.json`
- `output/polygon-mainnet.json`
- downloaded temporary Bor config: `/tmp/polygon-bor-config-v2.7.3.go`

## Current state
- Tuple-based fork selection is implemented and working.
- Base/Gnosis local fork config support is in place.
- Polygon static `forkHashes` were removed from `chains_config.json`.
- Polygon chains now use:
  - `filterType: "polygon_bor"`
  - `network: "mainnet"` / `"amoy"`
- The code compiles and runs.

## Verified behavior
- The tool runs successfully for Ethereum, BSC, Base, and Gnosis.
- Polygon Bor-based matching currently under-matches:
  - `polygon-mainnet` matches 1 node
  - `polygon-amoy` matches 0 nodes
- A direct helper inspection confirmed the single matched Polygon mainnet ENR advertises:
  - `forkId = 0e07e722`
  - `forkNext = 0`

## Key findings about Polygon data in `all.json`
A clean helper (`tmp_polygon_tuples.go`) showed the Polygon-related tuples currently present in `all.json`:
- `0e07e722 33cdb8` -> 10 nodes
- `0e07e722 0` -> 1 node
- `be06a477 11d8c` -> 4 nodes

Interpretation:
- Mainnet has 11 Polygon-like nodes total in current `all.json`
- Amoy has 4 Polygon-like nodes total in current `all.json`
- The source dataset is sparse for Polygon regardless of filter logic
- The current Bor-derived filter only admits the `(0e07e722, 0)` node

## Why Polygon matching is still incomplete
The current Polygon Bor fork-id implementation computes fork IDs from:
- known genesis hash from Bor config
- Ethereum-style block fork schedule fields:
  - `HomesteadBlock`
  - `DAOForkBlock`
  - `EIP150Block`
  - `EIP155Block`
  - `EIP158Block`
  - `ByzantiumBlock`
  - `ConstantinopleBlock`
  - `PetersburgBlock`
  - `IstanbulBlock`
  - `MuirGlacierBlock`
  - `BerlinBlock`
  - `LondonBlock`
- Bor-specific block checkpoints:
  - `JaipurBlock`
  - `DelhiBlock`
  - `IndoreBlock`
  - `AhmedabadBlock`
  - `BhilaiBlock`
  - `RioBlock`
  - `MadhugiriBlock`
  - `MadhugiriProBlock`
  - `DandeliBlock`
  - `LisovoBlock`
  - `LisovoProBlock`
  - `GiuglianoBlock`

Even after wiring those in, Polygon remains under-matched.
This strongly suggests one of:
- Bor ENR fork ID logic differs from the simple ordered-block checksum model used here
- additional fork schedule inputs are missing
- or `all.json` is simply not a good upstream source for Polygon

## Decision taken
Use Polygon's own ENR tree as the next source of truth instead of relying on Ethereum `all.json` for Polygon.
Proposed sources:
- Mainnet: `enrtree://AKUEZKN7PSKVNR65FZDHECMKOJQSGPARGTPPBI7WS2VUL4EGR6XPC@pos.polygon-peers.io`
- Amoy: `enrtree://AKUEZKN7PSKVNR65FZDHECMKOJQSGPARGTPPBI7WS2VUL4EGR6XPC@amoy.polygon-peers.io`

## Next task for new chat
Implement ENR tree loading for Polygon.

### Goal
Add a new source type that resolves EIP-1459 ENR trees and uses those ENRs as the node source for Polygon mainnet and Polygon Amoy.

### Expected minimal changes
1. In `main.go`
   - add import:
     - `github.com/ethereum/go-ethereum/p2p/dnsdisc`
   - add new chain source handler:
     - `bootnodes_enrtree`
   - add helper:
     - `loadBootnodesENRTree(treeURL string, topN int) ([]string, error)`
   - implement with `dnsdisc.NewClient(...).NewIterator(url)`
   - iterate returned `enode.Node` values and collect `node.String()` ENRs
   - reuse existing `processBootnodeRecords(...)`
   - do not remove the tuple logic

2. In `buildFilter(...)`
   - add `bootnodes_enrtree` to the handled-before-filter-construction cases

3. In `chains_config.json`
   - change Polygon chains from `polygon_bor` to `bootnodes_enrtree`
   - set:
     - `polygon-mainnet.sourceUrl = enrtree://AKUEZKN7PSKVNR65FZDHECMKOJQSGPARGTPPBI7WS2VUL4EGR6XPC@pos.polygon-peers.io`
     - `polygon-amoy.sourceUrl = enrtree://AKUEZKN7PSKVNR65FZDHECMKOJQSGPARGTPPBI7WS2VUL4EGR6XPC@amoy.polygon-peers.io`
   - remove Polygon `network` usage once no longer needed

### Validation to run
- `go test ./...`
- `go run .`
- verify:
  - `output/polygon-mainnet.json`
  - `output/polygon-amoy.json`
  - `output/chain_enodes.json`
- compare node counts against prior sparse `all.json` results

## Notes
- `tmp_polygon_tuples.go` was created as a temporary inspection helper in repo root.
- It may be removed later if no longer needed.
- Base/Gnosis per-chain outputs are currently logged twice because they are written in their specific handler and then again in the main chain flow. This is cosmetic and not yet addressed.

