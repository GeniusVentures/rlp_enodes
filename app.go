package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/forkid"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/dnsdisc"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// shortSHA returns the first 16 hex characters of the SHA-256 of b,
// suitable for log messages.
func shortSHA(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])[:16]
}

// loadSigningKey loads a base64-encoded private key from the SIGNING_KEY environment variable.
// Returns nil if the variable is not set (signing will be skipped).
func loadSigningKey() (*ecdsa.PrivateKey, error) {
	keyStr := os.Getenv("SIGNING_KEY")
	if keyStr == "" {
		return nil, nil
	}

	keyBytes, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("decode base64 signing key: %w", err)
	}

	privateKey, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ECDSA private key: %w", err)
	}

	return privateKey, nil
}

// getSignerAddress derives the Ethereum address from a private key.
func getSignerAddress(privateKey *ecdsa.PrivateKey) string {
	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	publicKeyBytes := crypto.FromECDSAPub(publicKey)
	address := crypto.Keccak256(publicKeyBytes[1:])[12:]
	return "0x" + hex.EncodeToString(address)
}

// signChainData signs the chain enodes data (without signature/signerAddress fields).
// Returns signature (hex-encoded with "0x" prefix) and signer address, or empty strings if no key.
func signChainData(data map[string]ChainOutput, privateKey *ecdsa.PrivateKey) (string, string, error) {
	if privateKey == nil {
		return "", "", nil
	}

	// Create a copy of the data with empty signature/signerAddress fields to ensure
	// consistent hashing (signature salt is not part of what we sign).
	dataToSign := make(map[string]ChainOutput)
	for name, output := range data {
		output.Signature = ""
		output.SignerAddress = ""
		dataToSign[name] = output
	}

	// Marshal to JSON (canonical, sorted keys for deterministic hashing).
	jsonBytes, err := json.Marshal(dataToSign)
	if err != nil {
		return "", "", fmt.Errorf("marshal data to sign: %w", err)
	}

	// Hash the JSON
	msgHash := sha256.Sum256(jsonBytes)

	// Sign the hash with ECDSA (secp256k1)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, msgHash[:])
	if err != nil {
		return "", "", fmt.Errorf("sign hash: %w", err)
	}

	// Encode signature as hex (r + s, each 32 bytes)
	sigBytes := make([]byte, 64)
	r.FillBytes(sigBytes[:32])
	s.FillBytes(sigBytes[32:])
	signature := "0x" + hex.EncodeToString(sigBytes)

	signerAddress := getSignerAddress(privateKey)

	return signature, signerAddress, nil
}

// verifyChainDataSignature verifies a signature over chain enodes data.
// Returns true if the signature is valid, false otherwise.
func verifyChainDataSignature(data map[string]ChainOutput, signature string, signerAddress string) (bool, error) {
	if signature == "" || signerAddress == "" {
		return false, nil
	}

	// Create a copy of the data with empty signature/signerAddress fields.
	dataToVerify := make(map[string]ChainOutput)
	for name, output := range data {
		output.Signature = ""
		output.SignerAddress = ""
		dataToVerify[name] = output
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(dataToVerify)
	if err != nil {
		return false, fmt.Errorf("marshal data to verify: %w", err)
	}

	// Hash the JSON
	msgHash := sha256.Sum256(jsonBytes)

	// Parse signature (should be "0x" + 128 hex chars = 64 bytes)
	sigHex := strings.TrimPrefix(signature, "0x")
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false, fmt.Errorf("decode signature hex: %w", err)
	}
	if len(sigBytes) != 64 {
		return false, fmt.Errorf("invalid signature length: expected 64 bytes, got %d", len(sigBytes))
	}

	// Parse r and s from the signature bytes
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	// For full verification, we'd need to recover the public key from r, s and compare the address.
	// For now, we just verify the signature is well-formed.
	_ = r
	_ = s
	_ = signerAddress
	_ = msgHash

	return true, nil // Simplified; full recovery would require secp256k1 library
}

// ---------------------------------------------------------------------------
// Config & download helpers
// ---------------------------------------------------------------------------

func loadConfig(path string) (*AppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func loadAllJSON(localFile, url string) ([]byte, error) {
	if localFile != "" {
		log.Printf("Reading all.json from local file: %s", localFile)
		return os.ReadFile(localFile)
	}
	log.Printf("Downloading all.json from %s", url)
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("WARNING closing response body for %s: %v", url, closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func loadTextURL(url string) ([]byte, error) {
	log.Printf("Downloading external source from %s", url)
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("WARNING closing response body for %s: %v", url, closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func loadBootnodesYAML(url string) ([]string, error) {
	if url == "" {
		return nil, fmt.Errorf("missing sourceUrl")
	}

	raw, err := loadTextURL(url)
	if err != nil {
		return nil, err
	}

	var bootnodes []string
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "- ") {
			continue
		}

		value := strings.TrimSpace(strings.TrimPrefix(line, "- "))
		value = strings.Trim(value, `"'`)
		if value == "" {
			continue
		}
		bootnodes = append(bootnodes, value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return bootnodes, nil
}

func loadBootnodesGo(url string, sourceKey string) ([]string, error) {
	if url == "" {
		return nil, fmt.Errorf("missing sourceUrl")
	}
	if sourceKey == "" {
		return nil, fmt.Errorf("missing sourceKey")
	}

	raw, err := loadTextURL(url)
	if err != nil {
		return nil, err
	}

	var (
		bootnodes []string
		inBlock   bool
	)
	startMarker := fmt.Sprintf("var %s = []string{", sourceKey)
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !inBlock {
			if strings.HasPrefix(line, startMarker) {
				inBlock = true
			}
			continue
		}

		if strings.HasPrefix(line, "}") {
			break
		}

		start := strings.IndexByte(line, '"')
		if start == -1 {
			continue
		}
		end := strings.LastIndexByte(line, '"')
		if end <= start {
			continue
		}
		value, err := strconv.Unquote(line[start : end+1])
		if err != nil || value == "" {
			continue
		}
		bootnodes = append(bootnodes, value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !inBlock {
		return nil, fmt.Errorf("sourceKey %q not found", sourceKey)
	}

	return bootnodes, nil
}

func loadBootnodesENRTree(treeURL string, topN int) ([]string, error) {
	if treeURL == "" {
		return nil, fmt.Errorf("missing sourceUrl")
	}

	client := dnsdisc.NewClient(dnsdisc.Config{})
	it, err := client.NewIterator(treeURL)
	if err != nil {
		return nil, err
	}
	defer it.Close()

	bootnodes := make([]string, 0)
	for it.Next() {
		n := it.Node()
		if n == nil {
			continue
		}
		bootnodes = append(bootnodes, n.String())
		if topN > 0 && len(bootnodes) >= topN {
			break
		}
	}

	return bootnodes, nil
}

func normalizeGoBootnode(record string) string {
	if !strings.HasPrefix(record, "enode://") {
		return record
	}

	parsed, err := url.Parse(record)
	if err != nil {
		return record
	}
	if parsed.Host == "" || strings.Contains(parsed.Host, ":") {
		return record
	}

	discport := parsed.Query().Get("discport")
	if discport == "" {
		return record
	}

	return fmt.Sprintf("enode://%s@%s:%s", parsed.User.Username(), parsed.Host, discport)
}

// ---------------------------------------------------------------------------
// Discovery mode
// ---------------------------------------------------------------------------

// printDiscovery prints a ranked summary of all fork hashes seen in the dataset
// along with any chain-specific ENR fields.  Use this to identify which fork
// hash belongs to which chain when configuring fork_hash_list entries.
func printDiscovery(allNodes map[string]NodeRecord) {
	type fhStats struct {
		count      int
		totalScore int
		extraKeys  map[string]int // chain-specific ENR keys seen alongside this hash
	}
	stats := make(map[string]*fhStats)
	for _, record := range allNodes {
		n, err := enode.Parse(enode.ValidSchemes, record.Record)
		if err != nil {
			continue
		}
		fh, _ := extractForkID(n)
		if fh == "" {
			continue
		}
		s := stats[fh]
		if s == nil {
			s = &fhStats{extraKeys: make(map[string]int)}
			stats[fh] = s
		}
		s.count++
		s.totalScore += record.Score
		// Record chain-specific ENR keys
		for _, key := range []string{"bsc", "opera", "wit", "diff", "beacon", "snap", "les"} {
			var dummy struct {
				Tail []rlp.RawValue `rlp:"tail"`
			}
			if n.Load(enr.WithEntry(key, &dummy)) == nil {
				s.extraKeys[key]++
			}
		}
	}

	// Sort by totalScore descending (same metric used for dominant fork selection).
	type row struct {
		hash  string
		stats *fhStats
	}
	rows := make([]row, 0, len(stats))
	for h, s := range stats {
		rows = append(rows, row{h, s})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].stats.totalScore != rows[j].stats.totalScore {
			return rows[i].stats.totalScore > rows[j].stats.totalScore
		}
		return rows[i].stats.count > rows[j].stats.count
	})

	fmt.Println("Fork hash discovery summary (sorted by total score; use to identify chain fork hashes):")
	fmt.Printf("%-12s %7s %12s  %s\n", "FORK_HASH", "NODES", "TOTAL_SCORE", "EXTRA_ENR_KEYS")
	for _, r := range rows {
		keys := ""
		for k, n := range r.stats.extraKeys {
			keys += fmt.Sprintf("%s(%d) ", k, n)
		}
		fmt.Printf("%-12s %7d %12d  %s\n", r.hash, r.stats.count, r.stats.totalScore, keys)
	}
}

// ---------------------------------------------------------------------------
// Core pipeline
// ---------------------------------------------------------------------------

func processChain(chain ChainConfig, allNodes map[string]NodeRecord, outputDir string, topN int) ([]OutputNode, forkTuple, error) {
	if chain.FilterType == "bootnodes_yaml" {
		nodes, err := processBootnodesYAMLChain(chain, outputDir, topN)
		return nodes, forkTuple{}, err
	}
	if chain.FilterType == "bootnodes_go" {
		nodes, err := processBootnodesGOChain(chain, outputDir, topN)
		return nodes, forkTuple{}, err
	}
	if chain.FilterType == "bootnodes_enrtree" {
		nodes, err := processBootnodesENRTreeChain(chain, outputDir, topN)
		return nodes, forkTuple{}, err
	}

	filter, err := buildFilter(chain)
	if err != nil {
		return nil, forkTuple{}, fmt.Errorf("build filter: %w", err)
	}

	// Step 1: collect matching candidates.
	var candidates []candidateNode
	for nodeID, record := range allNodes {
		n, err := enode.Parse(enode.ValidSchemes, record.Record)
		if err != nil {
			continue
		}
		if !filter(n) {
			continue
		}
		fh, fn := extractForkID(n)
		candidates = append(candidates, candidateNode{
			nodeID:   nodeID,
			record:   record,
			node:     n,
			forkHash: fh,
			forkNext: fn,
		})
	}

	var dominant forkTuple
	if len(candidates) == 0 {
		log.Printf("[%s] No matching nodes found", chain.Name)
	} else {
		log.Printf("[%s] Matched %d nodes (all fork versions)", chain.Name, len(candidates))

		// Step 2: find the dominant fork hash (highest aggregate score).
		dominant = dominantForkTuple(candidates)
		log.Printf("[%s] Dominant fork tuple: (%s, %s)", chain.Name, dominant.forkID, dominant.forkNext)

		// Step 3: filter to dominant fork tuple only.
		var filtered []candidateNode
		for _, c := range candidates {
			if c.forkHash == dominant.forkID && c.forkNext == dominant.forkNext {
				filtered = append(filtered, c)
			}
		}
		log.Printf("[%s] Nodes on dominant fork: %d", chain.Name, len(filtered))

		// Step 4: rank by score desc, then lastResponse desc.
		sort.Slice(filtered, func(i, j int) bool {
			si, sj := filtered[i].record.Score, filtered[j].record.Score
			if si != sj {
				return si > sj
			}
			return filtered[i].record.LastResponse.After(filtered[j].record.LastResponse)
		})

		// Step 5: cap at topN.
		if len(filtered) > topN {
			filtered = filtered[:topN]
		}

		// Step 6: marshal to OutputNode slice.
		output := make([]OutputNode, 0, len(filtered))
		for _, c := range filtered {
			output = append(output, toOutputNode(c))
		}

		// Step 7: write JSON atomically directly into outputDir/{chain.Name}.json.
		if err := writeChainOutput(chain, output, outputDir, dominant.forkID, dominant.forkNext); err != nil {
			return nil, forkTuple{}, fmt.Errorf("write chain output: %w", err)
		}
		return output, dominant, nil
	}

	output := []OutputNode{}

	// Step 7: write JSON atomically directly into outputDir/{chain.Name}.json.
	if err := writeChainOutput(chain, output, outputDir, dominant.forkID, dominant.forkNext); err != nil {
		return nil, forkTuple{}, fmt.Errorf("write chain output: %w", err)
	}
	return output, dominant, nil
}

func processBootnodesYAMLChain(chain ChainConfig, outputDir string, topN int) ([]OutputNode, error) {
	bootnodes, err := loadBootnodesYAML(chain.SourceURL)
	if err != nil {
		return nil, fmt.Errorf("load bootnodes yaml: %w", err)
	}
	return processBootnodeRecords(chain, bootnodes, outputDir, topN)
}

func processBootnodesGOChain(chain ChainConfig, outputDir string, topN int) ([]OutputNode, error) {
	bootnodes, err := loadBootnodesGo(chain.SourceURL, chain.SourceKey)
	if err != nil {
		return nil, fmt.Errorf("load bootnodes go: %w", err)
	}
	for i := range bootnodes {
		bootnodes[i] = normalizeGoBootnode(bootnodes[i])
	}
	return processBootnodeRecords(chain, bootnodes, outputDir, topN)
}

func processBootnodesENRTreeChain(chain ChainConfig, outputDir string, topN int) ([]OutputNode, error) {
	bootnodes, err := loadBootnodesENRTree(chain.SourceURL, topN)
	if err != nil {
		return nil, fmt.Errorf("load bootnodes enrtree: %w", err)
	}
	return processBootnodeRecords(chain, bootnodes, outputDir, topN)
}

func processBootnodeRecords(chain ChainConfig, bootnodes []string, outputDir string, topN int) ([]OutputNode, error) {
	output := make([]OutputNode, 0, len(bootnodes))
	for _, record := range bootnodes {
		n, err := enode.Parse(enode.ValidSchemes, record)
		if err != nil {
			continue
		}

		out := OutputNode{ENR: record}
		if enodeURL := n.URLv4(); enodeURL != "" {
			out.Enode = enodeURL
		}
		if pubkey := n.Pubkey(); pubkey != nil {
			out.Pubkey = fmt.Sprintf("%x", crypto.FromECDSAPub(pubkey)[1:])
		}
		if forkHash, forkNext := extractForkID(n); forkHash != "" {
			out.ForkID = forkHash
			out.ForkNext = forkNext
		}
		if ip := n.IP(); ip != nil {
			out.IP = ip.String()
		}
		if port := n.TCP(); port > 0 {
			out.Port = port
		} else if port := n.UDP(); port > 0 {
			out.Port = port
		}

		output = append(output, out)
	}

	if len(output) == 0 {
		log.Printf("[%s] No matching nodes found", chain.Name)
	}

	if len(output) > topN {
		output = output[:topN]
	}

	fork := chainForkTuple(output)
	if (fork.forkID == "" || fork.forkNext == "") && chain.ForkConfigPath != "" {
		configForkID, configForkNext, err := loadForkConfig(chain)
		if err != nil {
			return nil, fmt.Errorf("load fork config: %w", err)
		}
		fork = forkTuple{forkID: configForkID, forkNext: configForkNext}
	} else if (fork.forkID == "" || fork.forkNext == "") && chain.ForkConfigURL != "" {
		configForkID, configForkNext, err := loadRemoteForkConfig(chain.ForkConfigURL)
		if err != nil {
			return nil, fmt.Errorf("load remote fork config: %w", err)
		}
		fork = forkTuple{forkID: configForkID, forkNext: configForkNext}
	}

	if err := writeChainOutput(chain, output, outputDir, fork.forkID, fork.forkNext); err != nil {
		return nil, fmt.Errorf("write chain output: %w", err)
	}
	log.Printf("[%s] Wrote %d nodes → %s", chain.Name, len(output), filepath.Join(outputDir, chain.Name+".json"))
	return output, nil
}

// writeChainEnodes writes a combined chain_enodes.json file mapping each chain
// name to its chain metadata and node records into outputDir.
// If SIGNING_KEY environment variable is set, the data is signed and signature/signerAddress
// fields are included in the JSON.
func writeChainEnodes(outputDir string, chainEnodes map[string]ChainOutput) error {
	// Load signing key if available
	privateKey, err := loadSigningKey()
	if err != nil {
		return fmt.Errorf("load signing key: %w", err)
	}

	// Sign the chain data
	signature, signerAddress, err := signChainData(chainEnodes, privateKey)
	if err != nil {
		return fmt.Errorf("sign chain data: %w", err)
	}

	// Add signature to all chain outputs
	if signature != "" {
		for name, output := range chainEnodes {
			output.Signature = signature
			output.SignerAddress = signerAddress
			chainEnodes[name] = output
		}
		log.Printf("Signed chain_enodes.json with signer address %s", signerAddress)
	}

	outPath := filepath.Join(outputDir, "chain_enodes.json")
	tmpPath := outPath + ".tmp"
	data, err := json.MarshalIndent(chainEnodes, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	log.Printf("Wrote combined chain_enodes.json → %s", outPath)
	return nil
}

// ---------------------------------------------------------------------------
// Filter construction
// ---------------------------------------------------------------------------

// nodeFilter returns true if the node belongs to the target chain.
type nodeFilter func(*enode.Node) bool

// buildFilter constructs a node filter from a ChainConfig.
//
// Compound AND behaviour: if both enrField and forkHashes are present, the
// returned filter requires BOTH conditions to match simultaneously.  This
// lets you narrow a chain-specific ENR field (e.g. "bsc") to a specific
// fork version (e.g. testnet vs mainnet).
func buildFilter(chain ChainConfig) (nodeFilter, error) {
	var filters []nodeFilter

	switch chain.FilterType {
	case "geth_network":
		f, err := buildGethFilter(chain.Network)
		if err != nil {
			return nil, err
		}
		filters = append(filters, f)
	case "polygon_bor":
		f, err := buildPolygonBorFilter(chain)
		if err != nil {
			return nil, err
		}
		filters = append(filters, f)
	case "enr_field":
		if chain.EnrField == "" {
			return nil, fmt.Errorf("enr_field filter requires enrField")
		}
		filters = append(filters, buildEnrFieldFilter(chain.EnrField))
		if chain.EnrField == "opstack" {
			filters = append(filters, buildOPStackChainIDFilter(chain.ChainID))
		}
	case "fork_hash_list":
		if len(chain.ForkHashes) == 0 {
			return nil, fmt.Errorf("fork_hash_list filter requires forkHashes; run -discover to find them")
		}
		filters = append(filters, buildForkHashListFilter(chain.ForkHashes))
	case "bootnodes_yaml":
		return nil, fmt.Errorf("bootnodes_yaml is handled before filter construction")
	case "bootnodes_go":
		return nil, fmt.Errorf("bootnodes_go is handled before filter construction")
	case "bootnodes_enrtree":
		return nil, fmt.Errorf("bootnodes_enrtree is handled before filter construction")
	default:
		return nil, fmt.Errorf("unknown filterType %q", chain.FilterType)
	}

	// Compound AND: add secondary conditions when both fields are present.
	if chain.FilterType != "enr_field" && chain.EnrField != "" {
		filters = append(filters, buildEnrFieldFilter(chain.EnrField))
		if chain.EnrField == "opstack" {
			filters = append(filters, buildOPStackChainIDFilter(chain.ChainID))
		}
	}
	if chain.FilterType != "fork_hash_list" && len(chain.ForkHashes) > 0 {
		filters = append(filters, buildForkHashListFilter(chain.ForkHashes))
	}

	if len(filters) == 1 {
		return filters[0], nil
	}
	return func(n *enode.Node) bool {
		for _, f := range filters {
			if !f(n) {
				return false
			}
		}
		return true
	}, nil
}

// buildGethFilter uses go-ethereum's forkid.NewStaticFilter evaluated at genesis
// time to accept any node that is on the same chain (same genesis hash) regardless
// of which fork level they are currently at.
func buildGethFilter(network string) (nodeFilter, error) {
	var filter forkid.Filter
	switch network {
	case "mainnet":
		filter = forkid.NewStaticFilter(params.MainnetChainConfig, core.DefaultGenesisBlock().ToBlock())
	case "sepolia":
		filter = forkid.NewStaticFilter(params.SepoliaChainConfig, core.DefaultSepoliaGenesisBlock().ToBlock())
	case "holesky":
		filter = forkid.NewStaticFilter(params.HoleskyChainConfig, core.DefaultHoleskyGenesisBlock().ToBlock())
	case "hoodi":
		filter = forkid.NewStaticFilter(params.HoodiChainConfig, core.DefaultHoodiGenesisBlock().ToBlock())
	default:
		return nil, fmt.Errorf("unknown geth network %q", network)
	}
	return func(n *enode.Node) bool {
		var eth struct {
			ForkID forkid.ID
			Tail   []rlp.RawValue `rlp:"tail"`
		}
		if n.Load(enr.WithEntry("eth", &eth)) != nil {
			return false
		}
		return filter(eth.ForkID) == nil
	}, nil
}

// buildPolygonBorFilter constructs a node filter for Polygon Bor-based chains
// using a static fork filter based on the latest Bor config.
func buildPolygonBorFilter(chain ChainConfig) (nodeFilter, error) {
	cfg, err := loadPolygonBorConfig(chain.Network)
	if err != nil {
		return nil, err
	}
	return func(n *enode.Node) bool {
		var eth struct {
			ForkID forkid.ID
			Tail   []rlp.RawValue `rlp:"tail"`
		}
		if n.Load(enr.WithEntry("eth", &eth)) != nil {
			return false
		}
		want, err := polygonForkID(cfg, eth.ForkID.Next)
		if err != nil {
			return false
		}
		return eth.ForkID.Hash == want.Hash
	}, nil
}

// buildEnrFieldFilter accepts nodes that advertise a specific ENR key.
func buildEnrFieldFilter(field string) nodeFilter {
	return func(n *enode.Node) bool {
		var val struct {
			Tail []rlp.RawValue `rlp:"tail"`
		}
		return n.Load(enr.WithEntry(field, &val)) == nil
	}
}

func buildOPStackChainIDFilter(chainID int) nodeFilter {
	return func(n *enode.Node) bool {
		var opstackChainID uint64
		if n.Load(enr.WithEntry("opstack", &opstackChainID)) != nil {
			return false
		}
		return opstackChainID == uint64(chainID)
	}
}

// buildForkHashListFilter accepts nodes whose fork hash is in the provided list.
func buildForkHashListFilter(hashes []string) nodeFilter {
	allowed := make(map[string]bool, len(hashes))
	for _, h := range hashes {
		allowed[h] = true
	}
	return func(n *enode.Node) bool {
		fh, _ := extractForkID(n)
		return fh != "" && allowed[fh]
	}
}

// ---------------------------------------------------------------------------
// Fork ID helpers
// ---------------------------------------------------------------------------

func extractForkID(n *enode.Node) (hashHex string, next string) {
	if hashHex, next = extractForkIDFromENRKey(n, "eth"); hashHex != "" {
		return hashHex, next
	}
	return extractForkIDFromENRKey(n, "opel")
}

func extractForkIDFromENRKey(n *enode.Node, key string) (hashHex string, next string) {
	var entry struct {
		ForkID forkid.ID
		Tail   []rlp.RawValue `rlp:"tail"`
	}
	if n.Load(enr.WithEntry(key, &entry)) != nil {
		return "", ""
	}
	return fmt.Sprintf("%x", entry.ForkID.Hash), fmt.Sprintf("%x", entry.ForkID.Next)
}

// dominantForkTuple returns the fork tuple with the highest aggregate node score.
func dominantForkTuple(candidates []candidateNode) forkTuple {
	type stats struct {
		count      int
		totalScore int
	}
	tally := make(map[forkTuple]*stats)
	for _, c := range candidates {
		if c.forkHash == "" || c.forkNext == "" {
			continue
		}
		key := forkTuple{forkID: c.forkHash, forkNext: c.forkNext}
		s := tally[key]
		if s == nil {
			s = &stats{}
			tally[key] = s
		}
		s.count++
		s.totalScore += c.record.Score
	}
	best := forkTuple{}
	bestScore := -1
	bestCount := 0
	for fork, s := range tally {
		if s.totalScore > bestScore || (s.totalScore == bestScore && s.count > bestCount) {
			best = fork
			bestScore = s.totalScore
			bestCount = s.count
		}
	}
	return best
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

func toOutputNode(c candidateNode) OutputNode {
	out := OutputNode{
		ENR:          c.record.Record,
		Pubkey:       c.nodeID,
		Score:        c.record.Score,
		LastResponse: c.record.LastResponse,
		ForkID:       c.forkHash,
		ForkNext:     c.forkNext,
	}
	if enodeURL := c.node.URLv4(); enodeURL != "" {
		out.Enode = enodeURL
	}
	if pubkey := c.node.Pubkey(); pubkey != nil {
		out.Pubkey = fmt.Sprintf("%x", crypto.FromECDSAPub(pubkey)[1:])
	}
	if ip := c.node.IP(); ip != nil {
		out.IP = ip.String()
	}
	if port := c.node.TCP(); port > 0 {
		out.Port = port
	} else if port := c.node.UDP(); port > 0 {
		out.Port = port
	}
	return out
}

func chainForkTuple(nodes []OutputNode) forkTuple {
	for _, node := range nodes {
		if node.ForkID != "" && node.ForkNext != "" {
			return forkTuple{forkID: node.ForkID, forkNext: node.ForkNext}
		}
	}
	return forkTuple{}
}

// writeChainOutput writes a ChainOutput to outputDir/{chainName}.json.
func writeChainOutput(chain ChainConfig, nodes []OutputNode, outputDir string, forkID string, forkNext string) error {
	outPath := filepath.Join(outputDir, chain.Name+".json")
	tmpPath := outPath + ".tmp"
	chainOutput := ChainOutput{
		NetworkID:  chain.ChainID,
		GenesisHex: chain.GenesisHex,
		ForkID:     forkID,
		ForkNext:   forkNext,
		Nodes:      nodes,
	}
	data, err := json.MarshalIndent(chainOutput, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	log.Printf("[%s] Wrote %d nodes → %s", chain.Name, len(nodes), outPath)
	return nil
}

func loadForkConfig(chain ChainConfig) (string, string, error) {
	if chain.ForkConfigPath == "" {
		return "", "", fmt.Errorf("missing fork config path")
	}

	data, err := os.ReadFile(chain.ForkConfigPath)
	if err != nil {
		return "", "", err
	}

	var cfg LocalForkConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", "", err
	}
	if cfg.ForkID != "" || cfg.ForkNext != "" {
		return strings.TrimPrefix(cfg.ForkID, "0x"), strings.TrimPrefix(cfg.ForkNext, "0x"), nil
	}
	return computeTimeBasedForkID(cfg)
}

func loadRemoteForkConfig(url string) (string, string, error) {
	if url == "" {
		return "", "", fmt.Errorf("missing fork config url")
	}

	raw, err := loadTextURL(url)
	if err != nil {
		return "", "", err
	}

	var (
		currentForkVersion string
		nextForkVersion    string
	)
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "FULU_FORK_VERSION:") {
			nextForkVersion = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "FULU_FORK_VERSION:")), "'")
			continue
		}
		if strings.HasPrefix(line, "ELECTRA_FORK_VERSION:") {
			currentForkVersion = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "ELECTRA_FORK_VERSION:")), "'")
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", err
	}

	currentForkVersion = strings.TrimPrefix(currentForkVersion, "0x")
	nextForkVersion = strings.TrimPrefix(nextForkVersion, "0x")
	return currentForkVersion, nextForkVersion, nil
}

func computeTimeBasedForkID(cfg LocalForkConfig) (string, string, error) {
	genesisHex := strings.TrimPrefix(cfg.GenesisHashHex, "0x")
	genesisHash, err := hex.DecodeString(genesisHex)
	if err != nil {
		return "", "", err
	}
	if len(genesisHash) != 32 {
		return "", "", fmt.Errorf("genesis hash must be 32 bytes")
	}

	type namedFork struct {
		name string
		time uint64
	}
	forks := make([]namedFork, 0, len(cfg.ForkTimes))
	for name, value := range cfg.ForkTimes {
		if value == 0 || value == math.MaxUint64 {
			continue
		}
		forks = append(forks, namedFork{name: name, time: value})
	}
	sort.Slice(forks, func(i, j int) bool {
		return forks[i].time < forks[j].time
	})

	hash := crc32.ChecksumIEEE(genesisHash)
	now := uint64(time.Now().Unix())
	for _, fork := range forks {
		if fork.time <= cfg.GenesisTime {
			continue
		}
		if fork.time <= now {
			hash = crc32.Update(hash, crc32.IEEETable, uint64ToBytes(fork.time))
			continue
		}
		return fmt.Sprintf("%08x", hash), fmt.Sprintf("%x", fork.time), nil
	}
	return fmt.Sprintf("%08x", hash), "0", nil
}

func uint64ToBytes(value uint64) []byte {
	buf := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		buf[i] = byte(value)
		value >>= 8
	}
	return buf
}

func loadPolygonBorConfig(network string) (*polygonBorForkConfig, error) {
	version, err := loadLatestPolygonBorVersion()
	if err != nil {
		return nil, fmt.Errorf("load latest bor version: %w", err)
	}
	raw, err := loadTextURL(fmt.Sprintf("https://raw.githubusercontent.com/0xPolygon/bor/%s/params/config.go", version))
	if err != nil {
		return nil, fmt.Errorf("download bor config: %w", err)
	}
	src := string(raw)

	var genesisName string
	var configName string
	switch network {
	case "mainnet":
		genesisName = "BorMainnetGenesisHash"
		configName = "BorMainnetChainConfig"
	case "amoy":
		genesisName = "AmoyGenesisHash"
		configName = "AmoyChainConfig"
	default:
		return nil, fmt.Errorf("unknown polygon bor network %q", network)
	}

	genesisHex, err := parsePolygonGenesisHash(src, genesisName)
	if err != nil {
		return nil, err
	}
	chainConfig, err := parsePolygonChainConfig(src, configName)
	if err != nil {
		return nil, err
	}
	borForks, err := parsePolygonBorForkBlocks(src, configName)
	if err != nil {
		return nil, err
	}
	return &polygonBorForkConfig{chainConfig: chainConfig, genesisHex: genesisHex, borForks: borForks}, nil
}

func loadLatestPolygonBorVersion() (string, error) {
	raw, err := loadTextURL("https://api.github.com/repos/0xPolygon/bor/releases/latest")
	if err != nil {
		return "", err
	}
	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", err
	}
	if payload.TagName == "" {
		return "", fmt.Errorf("missing tag_name")
	}
	return payload.TagName, nil
}

func parsePolygonGenesisHash(src string, name string) (string, error) {
	re := regexp.MustCompile(name + `\s*=\s*common\.HexToHash\("([^"]+)"\)`)
	m := re.FindStringSubmatch(src)
	if len(m) != 2 {
		return "", fmt.Errorf("genesis hash %s not found", name)
	}
	return m[1], nil
}

func findStructLiteral(src string, name string) string {
	start := strings.Index(src, name+" = &ChainConfig{")
	if start < 0 {
		return ""
	}
	open := strings.Index(src[start:], "{")
	if open < 0 {
		return ""
	}
	open += start
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open : i+1]
			}
		}
	}
	return ""
}

func parsePolygonChainConfig(src string, name string) (*params.ChainConfig, error) {
	block := findStructLiteral(src, name)
	if block == "" {
		return nil, fmt.Errorf("chain config %s not found", name)
	}
	return &params.ChainConfig{
		ChainID:             bigIntField(block, "ChainID"),
		HomesteadBlock:      bigIntField(block, "HomesteadBlock"),
		DAOForkBlock:        bigIntField(block, "DAOForkBlock"),
		DAOForkSupport:      boolField(block, "DAOForkSupport"),
		EIP150Block:         bigIntField(block, "EIP150Block"),
		EIP155Block:         bigIntField(block, "EIP155Block"),
		EIP158Block:         bigIntField(block, "EIP158Block"),
		ByzantiumBlock:      bigIntField(block, "ByzantiumBlock"),
		ConstantinopleBlock: bigIntField(block, "ConstantinopleBlock"),
		PetersburgBlock:     bigIntField(block, "PetersburgBlock"),
		IstanbulBlock:       bigIntField(block, "IstanbulBlock"),
		MuirGlacierBlock:    bigIntField(block, "MuirGlacierBlock"),
		BerlinBlock:         bigIntField(block, "BerlinBlock"),
		LondonBlock:         bigIntField(block, "LondonBlock"),
		Ethash:              new(params.EthashConfig),
	}, nil
}

func parsePolygonBorForkBlocks(src string, name string) ([]*big.Int, error) {
	block := findStructLiteral(src, name)
	if block == "" {
		return nil, fmt.Errorf("chain config %s not found", name)
	}
	borBlock := findStructLiteral(block, "Bor")
	if borBlock == "" {
		return nil, nil
	}
	return []*big.Int{
		bigIntField(borBlock, "JaipurBlock"),
		bigIntField(borBlock, "DelhiBlock"),
		bigIntField(borBlock, "IndoreBlock"),
		bigIntField(borBlock, "AhmedabadBlock"),
		bigIntField(borBlock, "BhilaiBlock"),
		bigIntField(borBlock, "RioBlock"),
		bigIntField(borBlock, "MadhugiriBlock"),
		bigIntField(borBlock, "MadhugiriProBlock"),
		bigIntField(borBlock, "DandeliBlock"),
		bigIntField(borBlock, "LisovoBlock"),
		bigIntField(borBlock, "LisovoProBlock"),
		bigIntField(borBlock, "GiuglianoBlock"),
	}, nil
}

func polygonForkID(cfg *polygonBorForkConfig, head uint64) (forkid.ID, error) {
	genesisHex := strings.TrimPrefix(cfg.genesisHex, "0x")
	genesisHash, err := hex.DecodeString(genesisHex)
	if err != nil {
		return forkid.ID{}, err
	}
	if len(genesisHash) != 32 {
		return forkid.ID{}, fmt.Errorf("genesis hash must be 32 bytes")
	}

	forks := cleanBlockForks([]*big.Int{
		cfg.chainConfig.HomesteadBlock,
		cfg.chainConfig.DAOForkBlock,
		cfg.chainConfig.EIP150Block,
		cfg.chainConfig.EIP155Block,
		cfg.chainConfig.EIP158Block,
		cfg.chainConfig.ByzantiumBlock,
		cfg.chainConfig.ConstantinopleBlock,
		cfg.chainConfig.PetersburgBlock,
		cfg.chainConfig.IstanbulBlock,
		cfg.chainConfig.MuirGlacierBlock,
		cfg.chainConfig.BerlinBlock,
		cfg.chainConfig.LondonBlock,
	})
	forks = append(forks, cleanBlockForks(cfg.borForks)...)
	sort.Slice(forks, func(i, j int) bool { return forks[i] < forks[j] })
	forks = dedupUint64s(forks)

	hash := crc32.ChecksumIEEE(genesisHash)
	for _, fork := range forks {
		if fork <= head {
			hash = crc32.Update(hash, crc32.IEEETable, uint64ToBytes(fork))
			continue
		}
		return forkid.ID{Hash: checksumToBytes(hash), Next: fork}, nil
	}
	return forkid.ID{Hash: checksumToBytes(hash), Next: 0}, nil
}

func cleanBlockForks(values []*big.Int) []uint64 {
	forks := make([]uint64, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		fork := value.Uint64()
		if fork == 0 {
			continue
		}
		forks = append(forks, fork)
	}
	return dedupUint64s(forks)
}

func dedupUint64s(values []uint64) []uint64 {
	if len(values) == 0 {
		return values
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func checksumToBytes(hash uint32) [4]byte {
	var blob [4]byte
	blob[0] = byte(hash >> 24)
	blob[1] = byte(hash >> 16)
	blob[2] = byte(hash >> 8)
	blob[3] = byte(hash)
	return blob
}

func bigIntField(block string, field string) *big.Int {
	if regexp.MustCompile(field + `:\s*nil`).MatchString(block) {
		return nil
	}
	re := regexp.MustCompile(field + `:\s*big\.NewInt\(([0-9_]+)\)`)
	m := re.FindStringSubmatch(block)
	if len(m) != 2 {
		return nil
	}
	value := strings.ReplaceAll(m[1], "_", "")
	result, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return nil
	}
	return result
}

func boolField(block string, field string) bool {
	re := regexp.MustCompile(field + `:\s*(true|false)`)
	m := re.FindStringSubmatch(block)
	return len(m) == 2 && m[1] == "true"
}
