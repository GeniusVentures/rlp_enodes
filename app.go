package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/ecdsa"
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

	"reflect"

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
	sigBytes, err := crypto.Sign(msgHash[:], privateKey)
	if err != nil {
		return "", "", fmt.Errorf("sign hash: %w", err)
	}

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
	if len(sigBytes) != crypto.SignatureLength {
		return false, fmt.Errorf("invalid signature length: expected %d bytes, got %d", crypto.SignatureLength, len(sigBytes))
	}

	publicKey, err := crypto.SigToPub(msgHash[:], sigBytes)
	if err != nil {
		return false, fmt.Errorf("recover signer public key: %w", err)
	}

	recoveredAddress := crypto.PubkeyToAddress(*publicKey).Hex()
	return strings.EqualFold(recoveredAddress, signerAddress), nil
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

func loadChainBootnodes(chain ChainConfig, topN int) ([]OutputNode, error) {
	records, err := loadChainBootnodeRecords(chain, topN)
	if err != nil {
		return nil, err
	}
	return outputNodesFromRecords(records), nil
}

func loadChainBootnodeRecords(chain ChainConfig, topN int) ([]string, error) {
	if chain.BootnodesType != "" {
		return loadExplicitBootnodes(chain, topN)
	}

	switch chain.FilterType {
	case "bootnodes_yaml":
		return loadBootnodesYAML(chain.SourceURL)
	case "bootnodes_go":
		records, err := loadBootnodesGo(chain.SourceURL, chain.SourceKey)
		if err != nil {
			return nil, err
		}
		for i := range records {
			records[i] = normalizeGoBootnode(records[i])
		}
		return records, nil
	case "bootnodes_enrtree":
		return loadBootnodesENRTree(chain.SourceURL, topN)
	}

	sourceURL, sourceKey, ok := chainBootnodesGoSource(chain)
	if !ok {
		return []string{}, nil
	}
	records, err := loadBootnodesGo(sourceURL, sourceKey)
	if err != nil {
		return nil, err
	}
	for i := range records {
		records[i] = normalizeGoBootnode(records[i])
	}
	return records, nil
}

func loadExplicitBootnodes(chain ChainConfig, topN int) ([]string, error) {
	switch chain.BootnodesType {
	case "yaml":
		return loadBootnodesYAML(chain.BootnodesURL)
	case "go":
		records, err := loadBootnodesGo(chain.BootnodesURL, chain.BootnodesKey)
		if err != nil {
			return nil, err
		}
		for i := range records {
			records[i] = normalizeGoBootnode(records[i])
		}
		return records, nil
	case "enrtree":
		return loadBootnodesENRTree(chain.BootnodesURL, topN)
	case "zip_toml_static_nodes":
		return loadZipTOMLStaticNodes(chain.BootnodesURL, chain.BootnodesKey)
	default:
		return nil, fmt.Errorf("unsupported bootnodesType %q", chain.BootnodesType)
	}
}

func loadZipTOMLStaticNodes(url string, path string) ([]string, error) {
	if url == "" {
		return nil, fmt.Errorf("missing bootnodesUrl")
	}
	if path == "" {
		return nil, fmt.Errorf("missing bootnodesKey")
	}
	raw, err := loadTextURL(url)
	if err != nil {
		return nil, err
	}
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, err
	}
	for _, file := range reader.File {
		if file.Name != path {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		data, err := io.ReadAll(rc)
		if err != nil {
			return nil, err
		}
		return parseTOMLStringArray(string(data), "StaticNodes")
	}
	return nil, fmt.Errorf("%s not found in zip", path)
}

func parseTOMLStringArray(src string, key string) ([]string, error) {
	var (
		values  []string
		inArray bool
	)
	prefix := key + " = ["
	scanner := bufio.NewScanner(strings.NewReader(src))
	for scanner.Scan() {
		line := strings.TrimSpace(stripYAMLComment(scanner.Text()))
		if line == "" {
			continue
		}
		if !inArray {
			if line == prefix {
				inArray = true
			}
			continue
		}
		if strings.HasPrefix(line, "]") {
			return values, nil
		}
		start := strings.IndexByte(line, '"')
		end := strings.LastIndexByte(line, '"')
		if start == -1 || end <= start {
			continue
		}
		value, err := strconv.Unquote(line[start : end+1])
		if err != nil || value == "" {
			continue
		}
		values = append(values, value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !inArray {
		return nil, fmt.Errorf("%s not found", key)
	}
	return values, nil
}

func chainBootnodesGoSource(chain ChainConfig) (string, string, bool) {
	ref := chain.ForkSourceRef
	if ref == "" {
		ref = "master"
	}
	baseURL := strings.TrimRight(chain.ForkSourceURL, "/")
	if baseURL == "" {
		return "", "", false
	}

	switch chain.ForkProvider {
	case "ethereum_geth":
		sourceKey := gethBootnodesKey(chain.Network)
		return baseURL + "/" + ref + "/params/bootnodes.go", sourceKey, sourceKey != ""
	case "bsc":
		if chain.ChainID != 56 {
			return "", "", false
		}
		return baseURL + "/" + ref + "/params/bootnodes.go", "MainnetBootnodes", true
	default:
		return "", "", false
	}
}

func gethBootnodesKey(network string) string {
	switch network {
	case "mainnet":
		return "MainnetBootnodes"
	case "sepolia":
		return "SepoliaBootnodes"
	case "holesky":
		return "HoleskyBootnodes"
	case "hoodi":
		return "HoodiBootnodes"
	default:
		return ""
	}
}

func outputNodesFromRecords(records []string) []OutputNode {
	output := make([]OutputNode, 0, len(records))
	for _, record := range records {
		node, ok := outputNodeFromRecord(record)
		if !ok {
			continue
		}
		output = append(output, node)
	}
	return output
}

func outputNodeFromRecord(record string) (OutputNode, bool) {
	n, err := enode.Parse(enode.ValidSchemes, record)
	if err != nil {
		return OutputNode{}, false
	}

	out := OutputNode{}
	if strings.HasPrefix(record, "enr:") {
		out.ENR = record
	}
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
	return out, true
}

func cloneOutputNodes(nodes []OutputNode) []OutputNode {
	if nodes == nil {
		return []OutputNode{}
	}
	out := make([]OutputNode, len(nodes))
	copy(out, nodes)
	return out
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

func processChain(chain ChainConfig, allNodes map[string]NodeRecord, outputDir string, topN int, forkIDs ForkIDIndex) (ChainOutput, error) {
	if chain.FilterType == "bootnodes_yaml" || chain.FilterType == "bootnodes_go" {
		return processBootnodeSourceOnlyChain(chain, outputDir, topN, forkIDs)
	}
	if chain.FilterType == "bootnodes_enrtree" {
		return processBootnodesENRTreeChain(chain, outputDir, topN, forkIDs)
	}

	filter, err := buildFilter(chain, forkIDs)
	if err != nil {
		return ChainOutput{}, fmt.Errorf("build filter: %w", err)
	}

	// Step 1: collect matching candidates.
	var candidates []candidateNode
	var upcomingCandidates []candidateNode
	upcomingTuple, hasUpcoming := upcomingForkTupleForChain(chain, forkIDs)
	upcomingFilter, hasUpcomingFilter, err := buildUpcomingForkCandidateFilter(chain, forkIDs)
	if err != nil {
		return ChainOutput{}, fmt.Errorf("build upcoming fork filter: %w", err)
	}
	for nodeID, record := range allNodes {
		n, err := enode.Parse(enode.ValidSchemes, record.Record)
		if err != nil {
			continue
		}
		fh, fn := extractForkID(n)
		candidate := candidateNode{
			nodeID:   nodeID,
			record:   record,
			node:     n,
			forkHash: fh,
			forkNext: fn,
		}
		if filter(n) {
			if chain.FilterType == "geth_network" && fh == "" {
				continue
			}
			candidates = append(candidates, candidate)
		}
		if hasUpcoming && hasUpcomingFilter && upcomingFilter(n) && fh == upcomingTuple.forkID && fn == upcomingTuple.forkNext {
			upcomingCandidates = append(upcomingCandidates, candidate)
		}
	}

	var dominant forkTuple
	var output []OutputNode
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
		output = make([]OutputNode, 0, len(filtered))
		for _, c := range filtered {
			output = append(output, toOutputNode(c))
		}
	}

	writeFork := dominant
	if forkIDTuple, ok := currentForkTupleForChain(chain, forkIDs); ok {
		writeFork = forkIDTuple
	} else if writeFork.forkID == "" {
		writeFork = chainForkTuple(output)
	}
	bootnodes, err := loadChainBootnodes(chain, topN)
	if err != nil {
		log.Printf("WARNING [%s] load bootnodes: %v", chain.Name, err)
		bootnodes = []OutputNode{}
	}
	upcoming := buildUpcomingForkOutput(chain, forkIDs, upcomingCandidates, topN)
	chainOutput := newChainOutput(chain, output, bootnodes, writeFork.forkID, writeFork.forkNext, upcoming)
	if err := writeChainOutput(chain, chainOutput, outputDir); err != nil {
		return ChainOutput{}, fmt.Errorf("write chain output: %w", err)
	}
	return chainOutput, nil
}

func processBootnodeSourceOnlyChain(chain ChainConfig, outputDir string, topN int, forkIDs ForkIDIndex) (ChainOutput, error) {
	bootnodes, err := loadChainBootnodes(chain, topN)
	if err != nil {
		return ChainOutput{}, fmt.Errorf("load bootnodes: %w", err)
	}

	fork := chainForkTuple(bootnodes)
	if forkIDTuple, ok := currentForkTupleForChain(chain, forkIDs); ok {
		fork = forkIDTuple
	}

	chainOutput := newChainOutput(chain, []OutputNode{}, bootnodes, fork.forkID, fork.forkNext, nil)
	if err := writeChainOutput(chain, chainOutput, outputDir); err != nil {
		return ChainOutput{}, fmt.Errorf("write chain output: %w", err)
	}
	return chainOutput, nil
}

func processBootnodesYAMLChain(chain ChainConfig, outputDir string, topN int, forkIDs ForkIDIndex) (ChainOutput, error) {
	bootnodes, err := loadBootnodesYAML(chain.SourceURL)
	if err != nil {
		return ChainOutput{}, fmt.Errorf("load bootnodes yaml: %w", err)
	}
	return processBootnodeRecords(chain, bootnodes, outputDir, topN, forkIDs)
}

func processBootnodesGOChain(chain ChainConfig, outputDir string, topN int, forkIDs ForkIDIndex) (ChainOutput, error) {
	bootnodes, err := loadBootnodesGo(chain.SourceURL, chain.SourceKey)
	if err != nil {
		return ChainOutput{}, fmt.Errorf("load bootnodes go: %w", err)
	}
	for i := range bootnodes {
		bootnodes[i] = normalizeGoBootnode(bootnodes[i])
	}
	return processBootnodeRecords(chain, bootnodes, outputDir, topN, forkIDs)
}

func processBootnodesENRTreeChain(chain ChainConfig, outputDir string, topN int, forkIDs ForkIDIndex) (ChainOutput, error) {
	bootnodes, err := loadBootnodesENRTree(chain.SourceURL, topN)
	if err != nil {
		return ChainOutput{}, fmt.Errorf("load bootnodes enrtree: %w", err)
	}
	return processBootnodeRecords(chain, bootnodes, outputDir, topN, forkIDs)
}

func processBootnodeRecords(chain ChainConfig, bootnodes []string, outputDir string, topN int, forkIDs ForkIDIndex) (ChainOutput, error) {
	output := make([]OutputNode, 0, len(bootnodes))
	upcomingNodes := make([]OutputNode, 0)
	wantFork, filterByFork := currentForkTupleForChain(chain, forkIDs)
	upcomingTuple, hasUpcoming := upcomingForkTupleForChain(chain, forkIDs)
	for _, record := range bootnodes {
		n, err := enode.Parse(enode.ValidSchemes, record)
		if err != nil {
			continue
		}

		out := OutputNode{}
		if strings.HasPrefix(record, "enr:") {
			out.ENR = record
		}
		if enodeURL := n.URLv4(); enodeURL != "" {
			out.Enode = enodeURL
		}
		if pubkey := n.Pubkey(); pubkey != nil {
			out.Pubkey = fmt.Sprintf("%x", crypto.FromECDSAPub(pubkey)[1:])
		}
		if forkHash, forkNext := extractForkID(n); forkHash != "" {
			out.ForkID = forkHash
			out.ForkNext = forkNext
			if hasUpcoming && forkHash == upcomingTuple.forkID && forkNext == upcomingTuple.forkNext {
				upcomingNodes = append(upcomingNodes, out)
				continue
			}
			if filterByFork && (forkHash != wantFork.forkID || forkNext != wantFork.forkNext) {
				continue
			}
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
	if forkIDTuple, ok := currentForkTupleForChain(chain, forkIDs); ok {
		fork = forkIDTuple
	}

	upcoming := buildUpcomingForkOutputFromNodes(chain, forkIDs, upcomingNodes, topN)
	outputNodes := output
	outputBootnodes := []OutputNode{}
	if chain.BootnodesType != "" {
		var err error
		outputBootnodes, err = loadChainBootnodes(chain, topN)
		if err != nil {
			return ChainOutput{}, fmt.Errorf("load explicit bootnodes: %w", err)
		}
	}
	chainOutput := newChainOutput(chain, outputNodes, outputBootnodes, fork.forkID, fork.forkNext, upcoming)
	if err := writeChainOutput(chain, chainOutput, outputDir); err != nil {
		return ChainOutput{}, fmt.Errorf("write chain output: %w", err)
	}
	return chainOutput, nil
}

// writeChainEnodes writes a combined chain_enodes.json file mapping each chain
// name to its chain metadata and node records into outputDir.
// If SIGNING_KEY environment variable is set, the file gets top-level
// signature/signerAddress fields.
func writeChainEnodes(outputDir string, chainEnodes map[string]ChainOutput) error {
	privateKey, err := loadSigningKey()
	if err != nil {
		return fmt.Errorf("load signing key: %w", err)
	}

	unsignedChainEnodes := make(map[string]ChainOutput, len(chainEnodes))
	for name, output := range chainEnodes {
		output.Signature = ""
		output.SignerAddress = ""
		unsignedChainEnodes[name] = output
	}

	signature, signerAddress, err := signChainData(unsignedChainEnodes, privateKey)
	if err != nil {
		return fmt.Errorf("sign chain data: %w", err)
	}

	finalDocument := make(map[string]interface{}, len(unsignedChainEnodes)+2)
	for name, output := range unsignedChainEnodes {
		finalDocument[name] = output
	}
	if signature != "" {
		finalDocument["signature"] = signature
		finalDocument["signerAddress"] = signerAddress
		log.Printf("Signed chain_enodes.json with signer address %s", signerAddress)
	}

	outPath := filepath.Join(outputDir, "chain_enodes.json")
	tmpPath := outPath + ".tmp"
	data, err := json.MarshalIndent(finalDocument, "", "  ")
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

func writeForkIDs(outputDir string, forkIDs map[string]ForkIDOutput) error {
	outPath := filepath.Join(outputDir, "fork_ids.json")
	tmpPath := outPath + ".tmp"
	data, err := json.MarshalIndent(forkIDs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal fork ids: %w", err)
	}
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return fmt.Errorf("write tmp fork ids: %w", err)
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		return fmt.Errorf("rename fork ids: %w", err)
	}
	log.Printf("Wrote fork_ids.json → %s", outPath)
	return nil
}

func loadForkIDs(outputDir string) (ForkIDIndex, error) {
	path := filepath.Join(outputDir, "fork_ids.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var forkIDs ForkIDIndex
	if err := json.Unmarshal(data, &forkIDs); err != nil {
		return nil, err
	}
	return forkIDs, nil
}

func collectForkIDs(cfg *AppConfig, allNodes map[string]NodeRecord) ForkIDIndex {
	forkIDs := make(ForkIDIndex)
	generatedAt := time.Now().UTC()
	for _, chain := range cfg.Chains {
		forkID := ""
		forkNext := ""
		source := ""
		var forks []ForkTupleOutput

		if chain.ForkProvider != "" {
			if tuple, tuples, providerSource, err := collectProviderForkIDs(chain); err == nil {
				forkID = tuple.forkID
				forkNext = tuple.forkNext
				source = providerSource
				forks = forkTupleOutputs(tuples)
			} else {
				log.Printf("[%s] fork provider %q failed: %v", chain.Name, chain.ForkProvider, err)
			}
		}

		if forkID == "" && chain.ForkConfigPath != "" {
			if id, next, err := loadForkConfig(chain); err == nil {
				forkID = id
				forkNext = next
				source = chain.ForkConfigPath
			}
		} else if forkID == "" && chain.ForkConfigURL != "" {
			if id, next, err := loadRemoteForkConfig(chain.ForkConfigURL); err == nil {
				forkID = id
				forkNext = next
				source = chain.ForkConfigURL
			}
		} else if forkID == "" && chain.FilterType == "geth_network" {
			if tuples, err := gethForkTuples(chain); err == nil {
				forks = make([]ForkTupleOutput, 0, len(tuples))
				for _, tuple := range tuples {
					forks = append(forks, ForkTupleOutput{ForkID: tuple.forkID, ForkNext: tuple.forkNext})
				}
				if currentTuple, currentErr := currentGethForkTuple(chain); currentErr == nil {
					forkID = currentTuple.forkID
					forkNext = currentTuple.forkNext
				}
				source = "go-ethereum params"
			}
		}

		if forkID == "" && len(chain.ForkHashes) > 0 {
			forkID = strings.TrimPrefix(chain.ForkHashes[len(chain.ForkHashes)-1], "0x")
			forkNext = "0"
			source = "chains_config.json forkHashes"
			forks = make([]ForkTupleOutput, 0, len(chain.ForkHashes))
			for _, forkHash := range chain.ForkHashes {
				forks = append(forks, ForkTupleOutput{ForkID: strings.TrimPrefix(forkHash, "0x"), ForkNext: "0"})
			}
		}

		if forkID == "" && allNodes != nil && (chain.FilterType == "enr_field" || chain.FilterType == "fork_hash_list") {
			if tuple, tuples, ok := discoverForkTuplesForChain(chain, allNodes); ok {
				forkID = tuple.forkID
				forkNext = tuple.forkNext
				source = "all.json discovery"
				forks = forkTupleOutputs(tuples)
			}
		}

		if forkID == "" && chain.FilterType == "bootnodes_enrtree" {
			if tuple, tuples, err := discoverForkTuplesFromBootnodes(chain); err == nil && tuple.forkID != "" {
				forkID = tuple.forkID
				forkNext = tuple.forkNext
				source = chain.SourceURL
				forks = forkTupleOutputs(tuples)
			}
		}

		if forkID == "" && forkNext == "" && len(forks) == 0 {
			continue
		}
		current := ForkTupleOutput{ForkID: forkID, ForkNext: forkNext}
		forkIDs[chain.Name] = ForkIDOutput{
			ChainID:     chain.ChainID,
			GenesisHex:  chain.GenesisHex,
			ForkID:      forkID,
			ForkNext:    forkNext,
			Current:     current,
			Upcoming:    upcomingForkOutputFromForks(forkTuple{forkID: forkID, forkNext: forkNext}, forks),
			Source:      source,
			GeneratedAt: generatedAt,
			Forks:       forks,
		}
	}
	return forkIDs
}

func upcomingForkOutputFromForks(current forkTuple, forks []ForkTupleOutput) *ForkUpcomingOutput {
	if current.forkNext == "" || current.forkNext == "0" {
		return nil
	}
	output := &ForkUpcomingOutput{At: current.forkNext}
	for i, item := range forks {
		tuple := forkTuple{
			forkID:   strings.TrimPrefix(item.ForkID, "0x"),
			forkNext: strings.TrimPrefix(item.ForkNext, "0x"),
		}
		if tuple == current && i+1 < len(forks) {
			output.ForkID = strings.TrimPrefix(forks[i+1].ForkID, "0x")
			output.ForkNext = strings.TrimPrefix(forks[i+1].ForkNext, "0x")
			break
		}
	}
	return output
}

func currentForkTupleForChain(chain ChainConfig, forkIDs ForkIDIndex) (forkTuple, bool) {
	if forkIDs == nil {
		return forkTuple{}, false
	}
	output, ok := forkIDs[chain.Name]
	if !ok {
		return forkTuple{}, false
	}
	if output.Current.ForkID != "" || output.Current.ForkNext != "" {
		return forkTuple{forkID: strings.TrimPrefix(output.Current.ForkID, "0x"), forkNext: strings.TrimPrefix(output.Current.ForkNext, "0x")}, true
	}
	if output.ForkID == "" || output.ForkNext == "" {
		return forkTuple{}, false
	}
	return forkTuple{forkID: strings.TrimPrefix(output.ForkID, "0x"), forkNext: strings.TrimPrefix(output.ForkNext, "0x")}, true
}

func forkTuplesForChain(chain ChainConfig, forkIDs ForkIDIndex) []forkTuple {
	output, ok := forkIDs[chain.Name]
	if !ok {
		return nil
	}
	tuples := make([]forkTuple, 0, len(output.Forks)+1)
	for _, tuple := range output.Forks {
		if tuple.ForkID == "" || tuple.ForkNext == "" {
			continue
		}
		tuples = append(tuples, forkTuple{
			forkID:   strings.TrimPrefix(tuple.ForkID, "0x"),
			forkNext: strings.TrimPrefix(tuple.ForkNext, "0x"),
		})
	}
	if output.ForkID != "" && output.ForkNext != "" {
		current := forkTuple{forkID: strings.TrimPrefix(output.ForkID, "0x"), forkNext: strings.TrimPrefix(output.ForkNext, "0x")}
		found := false
		for _, tuple := range tuples {
			if tuple == current {
				found = true
				break
			}
		}
		if !found {
			tuples = append(tuples, current)
		}
	}
	return tuples
}

func upcomingForkTupleForChain(chain ChainConfig, forkIDs ForkIDIndex) (forkTuple, bool) {
	output, ok := forkIDs[chain.Name]
	if !ok || output.Upcoming == nil || output.Upcoming.ForkID == "" || output.Upcoming.ForkNext == "" {
		return forkTuple{}, false
	}
	return forkTuple{
		forkID:   strings.TrimPrefix(output.Upcoming.ForkID, "0x"),
		forkNext: strings.TrimPrefix(output.Upcoming.ForkNext, "0x"),
	}, true
}

func hasUpcomingForkForChain(chain ChainConfig, forkIDs ForkIDIndex) bool {
	output, ok := forkIDs[chain.Name]
	return ok && output.Upcoming != nil && output.Upcoming.At != ""
}

func upcomingForkAtForChain(chain ChainConfig, forkIDs ForkIDIndex) string {
	output, ok := forkIDs[chain.Name]
	if !ok || output.Upcoming == nil {
		return ""
	}
	return output.Upcoming.At
}

func buildUpcomingForkCandidateFilter(chain ChainConfig, forkIDs ForkIDIndex) (nodeFilter, bool, error) {
	upcoming, ok := upcomingForkTupleForChain(chain, forkIDs)
	if !ok {
		return nil, false, nil
	}
	tupleFilter := buildForkTupleListFilter([]forkTuple{upcoming})

	if chain.FilterType == "geth_network" {
		return tupleFilter, true, nil
	}

	identity, err := buildDiscoveryIdentityFilter(chain)
	if err == nil {
		return combineFilters([]nodeFilter{identity, tupleFilter}), true, nil
	}
	if len(chain.ForkHashes) > 0 || chain.EnrField != "" {
		return nil, false, err
	}
	return tupleFilter, true, nil
}

func buildUpcomingForkOutput(chain ChainConfig, forkIDs ForkIDIndex, candidates []candidateNode, topN int) *UpcomingForkOutput {
	nodes := make([]OutputNode, 0, len(candidates))
	sort.Slice(candidates, func(i, j int) bool {
		si, sj := candidates[i].record.Score, candidates[j].record.Score
		if si != sj {
			return si > sj
		}
		return candidates[i].record.LastResponse.After(candidates[j].record.LastResponse)
	})
	for _, candidate := range candidates {
		nodes = append(nodes, toOutputNode(candidate))
	}
	return buildUpcomingForkOutputFromNodes(chain, forkIDs, nodes, topN)
}

func buildUpcomingForkOutputFromNodes(chain ChainConfig, forkIDs ForkIDIndex, nodes []OutputNode, topN int) *UpcomingForkOutput {
	if !hasUpcomingForkForChain(chain, forkIDs) {
		return nil
	}
	upcoming, hasUpcomingTuple := upcomingForkTupleForChain(chain, forkIDs)
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Score != nodes[j].Score {
			return nodes[i].Score > nodes[j].Score
		}
		return nodes[i].LastResponse.After(nodes[j].LastResponse)
	})
	if topN > 0 && len(nodes) > topN {
		nodes = nodes[:topN]
	}
	output := &UpcomingForkOutput{
		At:    upcomingForkAtForChain(chain, forkIDs),
		Nodes: nodes,
	}
	if hasUpcomingTuple {
		output.ForkID = upcoming.forkID
		output.ForkNext = upcoming.forkNext
	}
	return output
}

func forkTupleOutputs(tuples []forkTuple) []ForkTupleOutput {
	output := make([]ForkTupleOutput, 0, len(tuples))
	seen := make(map[forkTuple]bool)
	for _, tuple := range tuples {
		if tuple.forkID == "" || tuple.forkNext == "" || seen[tuple] {
			continue
		}
		seen[tuple] = true
		output = append(output, ForkTupleOutput{ForkID: tuple.forkID, ForkNext: tuple.forkNext})
	}
	return output
}

func collectProviderForkIDs(chain ChainConfig) (forkTuple, []forkTuple, string, error) {
	switch chain.ForkProvider {
	case "ethereum_geth":
		return collectEthereumGethForkIDs(chain)
	case "bsc":
		return collectBSCForkIDs(chain)
	case "polygon_bor":
		return collectPolygonBorForkIDs(chain)
	case "op_stack_superchain":
		return collectOPStackSuperchainForkIDs(chain)
	default:
		return forkTuple{}, nil, "", fmt.Errorf("unknown fork provider %q", chain.ForkProvider)
	}
}

func collectEthereumGethForkIDs(chain ChainConfig) (forkTuple, []forkTuple, string, error) {
	ref := chain.ForkSourceRef
	if ref == "" {
		return forkTuple{}, nil, "", fmt.Errorf("missing forkSourceRef")
	}
	baseURL := strings.TrimRight(chain.ForkSourceURL, "/")
	if baseURL == "" {
		baseURL = "https://raw.githubusercontent.com/ethereum/go-ethereum"
	}
	sourceURL := fmt.Sprintf("%s/%s/params/config.go", baseURL, ref)
	raw, err := loadTextURL(sourceURL)
	if err != nil {
		return forkTuple{}, nil, "", err
	}

	configName := chain.ForkConfigName
	genesisName := chain.ForkGenesisName
	if configName == "" || genesisName == "" {
		switch chain.Network {
		case "mainnet":
			configName = "MainnetChainConfig"
			genesisName = "MainnetGenesisHash"
		case "sepolia":
			configName = "SepoliaChainConfig"
			genesisName = "SepoliaGenesisHash"
		case "holesky":
			configName = "HoleskyChainConfig"
			genesisName = "HoleskyGenesisHash"
		case "hoodi":
			configName = "HoodiChainConfig"
			genesisName = "HoodiGenesisHash"
		default:
			return forkTuple{}, nil, "", fmt.Errorf("missing ethereum geth network/config names")
		}
	}

	head, err := loadCurrentBlockNumber(chain.RPCURL)
	if err != nil {
		return forkTuple{}, nil, "", err
	}
	tuple, tuples, err := forkTuplesFromClientConfig(string(raw), configName, genesisName, head, time.Now())
	return tuple, tuples, sourceURL, err
}

func collectBSCForkIDs(chain ChainConfig) (forkTuple, []forkTuple, string, error) {
	ref := chain.ForkSourceRef
	if ref == "" {
		return forkTuple{}, nil, "", fmt.Errorf("missing forkSourceRef")
	}
	baseURL := strings.TrimRight(chain.ForkSourceURL, "/")
	if baseURL == "" {
		baseURL = "https://raw.githubusercontent.com/bnb-chain/bsc"
	}
	sourceURL := fmt.Sprintf("%s/%s/params/config.go", baseURL, ref)
	raw, err := loadTextURL(sourceURL)
	if err != nil {
		return forkTuple{}, nil, "", err
	}

	configName := chain.ForkConfigName
	genesisName := chain.ForkGenesisName
	if configName == "" || genesisName == "" {
		return forkTuple{}, nil, "", fmt.Errorf("missing forkConfigName or forkGenesisName")
	}

	head, err := loadCurrentBlockNumber(chain.RPCURL)
	if err != nil {
		return forkTuple{}, nil, "", err
	}
	tuple, tuples, err := forkTuplesFromClientConfig(string(raw), configName, genesisName, head, time.Now())
	return tuple, tuples, sourceURL, err
}

func collectPolygonBorForkIDs(chain ChainConfig) (forkTuple, []forkTuple, string, error) {
	ref := chain.ForkSourceRef
	if ref == "" {
		return forkTuple{}, nil, "", fmt.Errorf("missing forkSourceRef")
	}
	baseURL := strings.TrimRight(chain.ForkSourceURL, "/")
	if baseURL == "" {
		baseURL = "https://raw.githubusercontent.com/0xPolygon/bor"
	}
	sourceURL := fmt.Sprintf("%s/%s/params/config.go", baseURL, ref)
	raw, err := loadTextURL(sourceURL)
	if err != nil {
		return forkTuple{}, nil, "", err
	}

	configName := chain.ForkConfigName
	genesisName := chain.ForkGenesisName
	if configName == "" || genesisName == "" {
		switch chain.Network {
		case "mainnet":
			configName = "BorMainnetChainConfig"
			genesisName = "BorMainnetGenesisHash"
		case "amoy":
			configName = "AmoyChainConfig"
			genesisName = "AmoyGenesisHash"
		default:
			return forkTuple{}, nil, "", fmt.Errorf("missing polygon network/config names")
		}
	}

	head, err := loadCurrentBlockNumber(chain.RPCURL)
	if err != nil {
		return forkTuple{}, nil, "", err
	}
	tuple, tuples, err := forkTuplesFromClientConfig(string(raw), configName, genesisName, head, time.Now())
	return tuple, tuples, sourceURL, err
}

func collectOPStackSuperchainForkIDs(chain ChainConfig) (forkTuple, []forkTuple, string, error) {
	ref := chain.ForkSourceRef
	if ref == "" {
		return forkTuple{}, nil, "", fmt.Errorf("missing forkSourceRef")
	}
	baseURL := strings.TrimRight(chain.ForkSourceURL, "/")
	if baseURL == "" {
		baseURL = "https://raw.githubusercontent.com/ethereum-optimism/superchain-registry"
	}
	superchain := chain.Network
	if superchain == "" {
		return forkTuple{}, nil, "", fmt.Errorf("missing superchain network")
	}
	chainName := chain.ForkConfigName
	if chainName == "" {
		return forkTuple{}, nil, "", fmt.Errorf("missing superchain chain name")
	}
	sourceURL := fmt.Sprintf("%s/%s/superchain/configs/%s/%s.toml", baseURL, ref, superchain, chainName)
	raw, err := loadTextURL(sourceURL)
	if err != nil {
		return forkTuple{}, nil, "", err
	}

	tuple, tuples, err := forkTuplesFromSuperchainConfig(chain.GenesisHex, string(raw), time.Now())
	return tuple, tuples, sourceURL, err
}

func forkTuplesFromClientConfig(src string, configName string, genesisName string, head uint64, now time.Time) (forkTuple, []forkTuple, error) {
	genesisHex, err := parseClientGenesisHash(src, genesisName)
	if err != nil {
		return forkTuple{}, nil, err
	}
	block := findStructLiteral(src, configName)
	if block == "" {
		return forkTuple{}, nil, fmt.Errorf("chain config %s not found", configName)
	}

	blockForks, timeForks := parseForkPointsFromStruct(block)
	blockForks = dedupUint64s(blockForks)
	timeForks = dedupUint64s(timeForks)
	return computeForkTuples(genesisHex, blockForks, timeForks, head, now)
}

func forkTuplesFromSuperchainConfig(genesisHex string, src string, now time.Time) (forkTuple, []forkTuple, error) {
	if genesisHex == "" {
		var err error
		genesisHex, err = tomlStringField(src, "l2", "hash")
		if err != nil {
			return forkTuple{}, nil, err
		}
	}
	hardforks := tomlSection(src, "hardforks")
	if hardforks == "" {
		return forkTuple{}, nil, fmt.Errorf("hardforks section not found")
	}

	re := regexp.MustCompile(`(?m)^\s*[a-zA-Z0-9_]+_time\s*=\s*([0-9]+)(?:\s*#.*)?\s*$`)
	matches := re.FindAllStringSubmatch(hardforks, -1)
	timeForks := make([]uint64, 0, len(matches))
	for _, match := range matches {
		value, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil || value == 0 || value == math.MaxUint64 {
			continue
		}
		timeForks = append(timeForks, value)
	}
	timeForks = dedupUint64s(timeForks)
	return computeForkTuples(genesisHex, nil, timeForks, 0, now)
}

func computeForkTuples(genesisHex string, blockForks []uint64, timeForks []uint64, head uint64, now time.Time) (forkTuple, []forkTuple, error) {
	genesisHash, err := decodeGenesisHash(genesisHex)
	if err != nil {
		return forkTuple{}, nil, err
	}
	nowUnix := uint64(now.Unix())
	hash := crc32.ChecksumIEEE(genesisHash)
	tuples := make([]forkTuple, 0, len(blockForks)+len(timeForks)+1)
	var current forkTuple
	for _, fork := range blockForks {
		next := forkTuple{forkID: fmt.Sprintf("%08x", hash), forkNext: fmt.Sprintf("%x", fork)}
		tuples = append(tuples, next)
		if fork <= head {
			hash = crc32.Update(hash, crc32.IEEETable, uint64ToBytes(fork))
			continue
		}
		current = next
		return current, tuples, nil
	}
	for _, fork := range timeForks {
		next := forkTuple{forkID: fmt.Sprintf("%08x", hash), forkNext: fmt.Sprintf("%x", fork)}
		tuples = append(tuples, next)
		if fork <= nowUnix {
			hash = crc32.Update(hash, crc32.IEEETable, uint64ToBytes(fork))
			continue
		}
		current = next
		return current, tuples, nil
	}

	current = forkTuple{forkID: fmt.Sprintf("%08x", hash), forkNext: "0"}
	tuples = append(tuples, current)
	return current, tuples, nil
}

func parseClientGenesisHash(src string, name string) (string, error) {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(name + `\s*=\s*common\.HexToHash\("([^"]+)"\)`),
		regexp.MustCompile(name + `\s*=\s*common\.HexToHash\(\s*"([^"]+)"\s*\)`),
	}
	for _, re := range patterns {
		if m := re.FindStringSubmatch(src); len(m) == 2 {
			return m[1], nil
		}
	}
	return "", fmt.Errorf("genesis hash %s not found", name)
}

func parseForkPointsFromStruct(block string) ([]uint64, []uint64) {
	block = topLevelStructFields(block)
	re := regexp.MustCompile(`([A-Za-z0-9_]+(?:Block|Time)):\s*(?:big\.NewInt\(([0-9_]+)\)|newUint64\(([0-9_]+)\)|uint64Ptr\(([0-9_]+)\)|uint64\(([0-9_]+)\)|([0-9_]+))`)
	matches := re.FindAllStringSubmatch(block, -1)
	blockForks := make([]uint64, 0, len(matches))
	timeForks := make([]uint64, 0, len(matches))
	for _, match := range matches {
		var raw string
		for i := 2; i < len(match); i++ {
			if match[i] != "" {
				raw = match[i]
				break
			}
		}
		if raw == "" {
			continue
		}
		value, err := strconv.ParseUint(strings.ReplaceAll(raw, "_", ""), 10, 64)
		if err != nil || value == 0 || value == math.MaxUint64 {
			continue
		}
		if strings.HasSuffix(match[1], "Time") {
			timeForks = append(timeForks, value)
			continue
		}
		blockForks = append(blockForks, value)
	}
	return blockForks, timeForks
}

func topLevelStructFields(block string) string {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(block); i++ {
		ch := block[i]
		switch ch {
		case '{':
			depth++
			continue
		case '}':
			depth--
			continue
		}
		if depth == 1 {
			b.WriteByte(ch)
		}
	}
	return b.String()
}

func tomlStringField(src string, section string, key string) (string, error) {
	body := tomlSection(src, section)
	if body == "" {
		return "", fmt.Errorf("toml section %s not found", section)
	}
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s*=\s*"([^"]+)"\s*$`)
	m := re.FindStringSubmatch(body)
	if len(m) != 2 {
		return "", fmt.Errorf("toml field %s.%s not found", section, key)
	}
	return m[1], nil
}

func tomlSection(src string, section string) string {
	re := regexp.MustCompile(`(?m)^\s*\[` + regexp.QuoteMeta(section) + `\]\s*$`)
	loc := re.FindStringIndex(src)
	if loc == nil {
		return ""
	}
	rest := src[loc[1]:]
	next := regexp.MustCompile(`(?m)^\s*\[[^\]]+\]\s*$`).FindStringIndex(rest)
	if next == nil {
		return rest
	}
	return rest[:next[0]]
}

func discoverForkTuplesForChain(chain ChainConfig, allNodes map[string]NodeRecord) (forkTuple, []forkTuple, bool) {
	filter, err := buildDiscoveryIdentityFilter(chain)
	if err != nil {
		return forkTuple{}, nil, false
	}
	candidates := make([]candidateNode, 0)
	for nodeID, record := range allNodes {
		n, err := enode.Parse(enode.ValidSchemes, record.Record)
		if err != nil || !filter(n) {
			continue
		}
		fh, fn := extractForkID(n)
		if fh == "" || fn == "" {
			continue
		}
		candidates = append(candidates, candidateNode{
			nodeID:   nodeID,
			record:   record,
			node:     n,
			forkHash: fh,
			forkNext: fn,
		})
	}
	if len(candidates) == 0 {
		return forkTuple{}, nil, false
	}
	return dominantForkTuple(candidates), rankedForkTuples(candidates), true
}

func discoverForkTuplesFromBootnodes(chain ChainConfig) (forkTuple, []forkTuple, error) {
	var records []string
	var err error
	switch chain.FilterType {
	case "bootnodes_enrtree":
		topN := chain.TopN
		if topN <= 0 {
			topN = 100
		}
		records, err = loadBootnodesENRTree(chain.SourceURL, topN)
	case "bootnodes_go":
		records, err = loadBootnodesGo(chain.SourceURL, chain.SourceKey)
		for i := range records {
			records[i] = normalizeGoBootnode(records[i])
		}
	case "bootnodes_yaml":
		records, err = loadBootnodesYAML(chain.SourceURL)
	default:
		return forkTuple{}, nil, fmt.Errorf("unsupported bootnode filter type %q", chain.FilterType)
	}
	if err != nil {
		return forkTuple{}, nil, err
	}

	candidates := make([]candidateNode, 0, len(records))
	for _, record := range records {
		n, err := enode.Parse(enode.ValidSchemes, record)
		if err != nil {
			continue
		}
		fh, fn := extractForkID(n)
		if fh == "" || fn == "" {
			continue
		}
		candidates = append(candidates, candidateNode{
			record:   NodeRecord{Record: record, Score: 1},
			node:     n,
			forkHash: fh,
			forkNext: fn,
		})
	}
	if len(candidates) == 0 {
		return forkTuple{}, nil, nil
	}
	return dominantForkTuple(candidates), rankedForkTuples(candidates), nil
}

func currentGethForkTuple(chain ChainConfig) (forkTuple, error) {
	config, err := gethChainConfig(chain.Network)
	if err != nil {
		return forkTuple{}, err
	}
	genesisHash, err := decodeGenesisHash(chain.GenesisHex)
	if err != nil {
		return forkTuple{}, err
	}

	hash := crc32.ChecksumIEEE(genesisHash)
	forks := gatherOrderedForks(config)
	for _, fork := range forks {
		if isForkPassedNow(fork) {
			hash = crc32.Update(hash, crc32.IEEETable, uint64ToBytes(fork))
			continue
		}
		return forkTuple{forkID: fmt.Sprintf("%08x", hash), forkNext: fmt.Sprintf("%x", fork)}, nil
	}
	return forkTuple{forkID: fmt.Sprintf("%08x", hash), forkNext: "0"}, nil
}

func gethForkTuples(chain ChainConfig) ([]forkTuple, error) {
	config, err := gethChainConfig(chain.Network)
	if err != nil {
		return nil, err
	}
	genesisHash, err := decodeGenesisHash(chain.GenesisHex)
	if err != nil {
		return nil, err
	}

	hash := crc32.ChecksumIEEE(genesisHash)
	forkPoints := gatherOrderedForks(config)
	tuples := make([]forkTuple, 0, len(forkPoints)+1)
	for _, fork := range forkPoints {
		tuples = append(tuples, forkTuple{forkID: fmt.Sprintf("%08x", hash), forkNext: fmt.Sprintf("%x", fork)})
		hash = crc32.Update(hash, crc32.IEEETable, uint64ToBytes(fork))
	}
	tuples = append(tuples, forkTuple{forkID: fmt.Sprintf("%08x", hash), forkNext: "0"})
	return tuples, nil
}

func decodeGenesisHash(genesisHex string) ([]byte, error) {
	decoded, err := hex.DecodeString(strings.TrimPrefix(genesisHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("decode genesis hash: %w", err)
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("invalid genesis hash length: %d", len(decoded))
	}
	return decoded, nil
}

func gatherOrderedForks(config *params.ChainConfig) []uint64 {
	if config == nil {
		return nil
	}

	kind := reflect.TypeOf(params.ChainConfig{})
	conf := reflect.ValueOf(config).Elem()
	blockKind := reflect.TypeOf(new(big.Int))
	timeKind := reflect.TypeOf(new(uint64))

	forksByBlock := make([]uint64, 0)
	forksByTime := make([]uint64, 0)
	for i := 0; i < kind.NumField(); i++ {
		field := kind.Field(i)
		isBlock := strings.HasSuffix(field.Name, "Block")
		isTime := strings.HasSuffix(field.Name, "Time")
		if !isBlock && !isTime {
			continue
		}

		switch field.Type {
		case blockKind:
			rule := conf.Field(i).Interface().(*big.Int)
			if rule == nil {
				continue
			}
			value := rule.Uint64()
			if value == 0 {
				continue
			}
			forksByBlock = append(forksByBlock, value)
		case timeKind:
			rule := conf.Field(i).Interface().(*uint64)
			if rule == nil {
				continue
			}
			value := *rule
			if value == 0 {
				continue
			}
			forksByTime = append(forksByTime, value)
		}
	}

	forksByBlock = dedupUint64s(forksByBlock)
	forksByTime = dedupUint64s(forksByTime)
	return append(forksByBlock, forksByTime...)
}

// ---------------------------------------------------------------------------
// Discovery filters
// ---------------------------------------------------------------------------

// nodeFilter returns true if the node belongs to the target chain.
type nodeFilter func(*enode.Node) bool

// buildFilter constructs a node filter from a ChainConfig.
//
// Compound AND behaviour: if both enrField and forkHashes are present, the
// returned filter requires BOTH conditions to match simultaneously.  This
// lets you narrow a chain-specific ENR field (e.g. "bsc") to a specific
// fork version (e.g. testnet vs mainnet).
func buildFilter(chain ChainConfig, forkIDs ForkIDIndex) (nodeFilter, error) {
	var filters []nodeFilter

	switch chain.FilterType {
	case "geth_network":
		return buildGethFilter(chain, forkIDs)
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
		tuples := forkTuplesForChain(chain, forkIDs)
		if len(tuples) == 0 && len(chain.ForkHashes) == 0 {
			return nil, fmt.Errorf("fork_hash_list filter requires forkHashes; run -discover to find them")
		}
		if len(tuples) > 0 {
			filters = append(filters, buildForkTupleListFilter(tuples))
		} else {
			filters = append(filters, buildForkHashListFilter(chain.ForkHashes))
		}
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
	if tuple, ok := currentForkTupleForChain(chain, forkIDs); ok && chain.FilterType != "geth_network" {
		filters = append(filters, buildForkTupleListFilter([]forkTuple{tuple}))
	} else if chain.FilterType != "fork_hash_list" && len(chain.ForkHashes) > 0 {
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

// buildGethFilter keeps Ethereum-family nodes on the requested network by using
// go-ethereum's authoritative chain config and forkid computation derived from
// the configured genesis/header data, avoiding hardcoded live fork hashes.
func buildGethFilter(chain ChainConfig, forkIDs ForkIDIndex) (nodeFilter, error) {
	want, ok := currentForkTupleForChain(chain, forkIDs)
	if !ok {
		return nil, fmt.Errorf("missing current fork tuple for %s in fork_ids.json", chain.Name)
	}
	return func(n *enode.Node) bool {
		fh, fn := extractForkID(n)
		if fh == "" || fn == "" {
			return false
		}
		return fh == want.forkID && fn == want.forkNext
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

func buildDiscoveryIdentityFilter(chain ChainConfig) (nodeFilter, error) {
	var filters []nodeFilter
	if chain.EnrField != "" {
		filters = append(filters, buildEnrFieldFilter(chain.EnrField))
		if chain.EnrField == "opstack" {
			filters = append(filters, buildOPStackChainIDFilter(chain.ChainID))
		}
	}
	if len(chain.ForkHashes) > 0 {
		filters = append(filters, buildForkHashListFilter(chain.ForkHashes))
	}
	if len(filters) == 0 {
		return nil, fmt.Errorf("chain %s has no discovery identity filter", chain.Name)
	}
	return combineFilters(filters), nil
}

// buildForkHashListFilter accepts nodes whose fork hash is in the provided list.
func buildForkHashListFilter(hashes []string) nodeFilter {
	allowed := make(map[string]bool, len(hashes))
	for _, h := range hashes {
		allowed[strings.TrimPrefix(h, "0x")] = true
	}
	return func(n *enode.Node) bool {
		fh, _ := extractForkID(n)
		return fh != "" && allowed[fh]
	}
}

func buildForkTupleListFilter(tuples []forkTuple) nodeFilter {
	allowed := make(map[forkTuple]bool, len(tuples))
	for _, tuple := range tuples {
		allowed[forkTuple{
			forkID:   strings.TrimPrefix(tuple.forkID, "0x"),
			forkNext: strings.TrimPrefix(tuple.forkNext, "0x"),
		}] = true
	}
	return func(n *enode.Node) bool {
		fh, fn := extractForkID(n)
		return fh != "" && fn != "" && allowed[forkTuple{forkID: fh, forkNext: fn}]
	}
}

func combineFilters(filters []nodeFilter) nodeFilter {
	if len(filters) == 1 {
		return filters[0]
	}
	return func(n *enode.Node) bool {
		for _, f := range filters {
			if !f(n) {
				return false
			}
		}
		return true
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
	selectBest := func(items []candidateNode) forkTuple {
		counts := make(map[forkTuple]int)
		best := forkTuple{}
		bestCount := 0
		for _, c := range items {
			if c.forkHash == "" || c.forkNext == "" {
				continue
			}
			key := forkTuple{forkID: c.forkHash, forkNext: c.forkNext}
			counts[key]++
			if counts[key] > bestCount {
				best = key
				bestCount = counts[key]
			}
		}
		return best
	}

	currentCandidates := make([]candidateNode, 0, len(candidates))
	for _, c := range candidates {
		if c.forkNext == "0" {
			currentCandidates = append(currentCandidates, c)
		}
	}
	if len(currentCandidates) > 0 {
		if best := selectBest(currentCandidates); best.forkID != "" {
			return best
		}
	}
	return selectBest(candidates)
}

func rankedForkTuples(candidates []candidateNode) []forkTuple {
	counts := make(map[forkTuple]int)
	for _, c := range candidates {
		if c.forkHash == "" || c.forkNext == "" {
			continue
		}
		counts[forkTuple{forkID: c.forkHash, forkNext: c.forkNext}]++
	}

	tuples := make([]forkTuple, 0, len(counts))
	for tuple := range counts {
		tuples = append(tuples, tuple)
	}
	sort.Slice(tuples, func(i, j int) bool {
		if counts[tuples[i]] != counts[tuples[j]] {
			return counts[tuples[i]] > counts[tuples[j]]
		}
		if tuples[i].forkID != tuples[j].forkID {
			return tuples[i].forkID < tuples[j].forkID
		}
		return tuples[i].forkNext < tuples[j].forkNext
	})
	return tuples
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

func newChainOutput(chain ChainConfig, nodes []OutputNode, bootnodes []OutputNode, forkID string, forkNext string, upcoming *UpcomingForkOutput) ChainOutput {
	return ChainOutput{
		NetworkID:    chain.ChainID,
		GenesisHex:   chain.GenesisHex,
		ForkID:       forkID,
		ForkNext:     forkNext,
		UpcomingFork: upcoming,
		Nodes:        nodes,
		Bootnodes:    bootnodes,
	}
}

// writeChainOutput writes a ChainOutput to outputDir/{chainName}.json.
func writeChainOutput(chain ChainConfig, output ChainOutput, outputDir string) error {
	outPath := filepath.Join(outputDir, chain.Name+".json")
	tmpPath := outPath + ".tmp"
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	log.Printf("[%s] Wrote %d nodes → %s", chain.Name, len(output.Nodes), outPath)
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

	currentForkVersion, nextForkVersion, err := forkVersionsFromBeaconConfig(string(raw), time.Now())
	if err != nil {
		return "", "", err
	}
	return currentForkVersion, nextForkVersion, nil
}

func forkVersionsFromBeaconConfig(src string, now time.Time) (string, string, error) {
	versions := make(map[string]string)
	epochs := make(map[string]uint64)
	var genesisTime uint64
	presetBase := ""
	slotsPerEpoch := uint64(32)
	secondsPerSlot := uint64(12)
	slotsPerEpochSet := false
	secondsPerSlotSet := false

	scanner := bufio.NewScanner(strings.NewReader(src))
	for scanner.Scan() {
		line := stripYAMLComment(strings.TrimSpace(scanner.Text()))
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if value == "" {
			continue
		}

		switch key {
		case "PRESET_BASE":
			presetBase = value
		case "MIN_GENESIS_TIME":
			genesisTime = parseUintOrZero(value)
		case "SLOTS_PER_EPOCH":
			slotsPerEpoch = parseUintOrDefault(value, slotsPerEpoch)
			slotsPerEpochSet = true
		case "SECONDS_PER_SLOT":
			secondsPerSlot = parseUintOrDefault(value, secondsPerSlot)
			secondsPerSlotSet = true
		}

		if strings.HasSuffix(key, "_FORK_VERSION") {
			name := strings.TrimSuffix(key, "_FORK_VERSION")
			versions[name] = strings.TrimPrefix(value, "0x")
			continue
		}
		if strings.HasSuffix(key, "_FORK_EPOCH") {
			name := strings.TrimSuffix(key, "_FORK_EPOCH")
			if epoch := parseUintOrZero(value); epoch != math.MaxUint64 {
				epochs[name] = epoch
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", err
	}
	if genesisTime == 0 {
		return "", "", fmt.Errorf("missing MIN_GENESIS_TIME")
	}
	if presetBase == "gnosis" {
		if !slotsPerEpochSet {
			slotsPerEpoch = 16
		}
		if !secondsPerSlotSet {
			secondsPerSlot = 5
		}
	}

	type beaconFork struct {
		name    string
		version string
		epoch   uint64
	}
	forks := make([]beaconFork, 0, len(versions))
	if version := versions["GENESIS"]; version != "" {
		forks = append(forks, beaconFork{name: "GENESIS", version: version, epoch: 0})
	}
	for name, version := range versions {
		if name == "GENESIS" {
			continue
		}
		epoch, ok := epochs[name]
		if !ok {
			continue
		}
		forks = append(forks, beaconFork{name: name, version: version, epoch: epoch})
	}
	sort.Slice(forks, func(i, j int) bool {
		if forks[i].epoch != forks[j].epoch {
			return forks[i].epoch < forks[j].epoch
		}
		return forks[i].name < forks[j].name
	})

	if len(forks) == 0 {
		return "", "", fmt.Errorf("no fork versions found")
	}

	nowUnix := uint64(now.Unix())
	current := forks[0]
	next := ""
	for _, fork := range forks {
		activation := genesisTime + fork.epoch*slotsPerEpoch*secondsPerSlot
		if activation <= nowUnix {
			current = fork
			continue
		}
		next = fork.version
		break
	}
	if next == "" {
		next = "0"
	}
	return current.version, next, nil
}

func stripYAMLComment(line string) string {
	if before, _, ok := strings.Cut(line, "#"); ok {
		line = before
	}
	return strings.TrimSpace(line)
}

func parseUintOrZero(value string) uint64 {
	return parseUintOrDefault(value, 0)
}

func parseUintOrDefault(value string, fallback uint64) uint64 {
	parsed, err := strconv.ParseUint(strings.ReplaceAll(value, "_", ""), 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func loadCurrentBlockNumber(rpcURL string) (uint64, error) {
	if rpcURL == "" {
		return 0, fmt.Errorf("missing rpcUrl")
	}

	req, err := http.NewRequest(http.MethodPost, rpcURL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("http status %d", resp.StatusCode)
	}

	var payload struct {
		Result string `json:"result"`
		Error  struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return 0, err
	}
	if payload.Error.Message != "" {
		return 0, fmt.Errorf("rpc error %d: %s", payload.Error.Code, payload.Error.Message)
	}
	if payload.Result == "" {
		return 0, fmt.Errorf("missing eth_blockNumber result")
	}
	return strconv.ParseUint(strings.TrimPrefix(payload.Result, "0x"), 16, 64)
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

func isForkPassedNow(fork uint64) bool {
	return isForkPassedAt(fork, uint64(time.Now().Unix()))
}

func isForkPassedAt(fork uint64, timestamp uint64) bool {
	const timestampThreshold = 1438269973
	if fork > timestampThreshold {
		return fork <= timestamp
	}
	return true
}

func gethChainConfig(network string) (*params.ChainConfig, error) {
	switch network {
	case "mainnet":
		return params.MainnetChainConfig, nil
	case "sepolia":
		return params.SepoliaChainConfig, nil
	case "holesky":
		return params.HoleskyChainConfig, nil
	case "hoodi":
		return params.HoodiChainConfig, nil
	default:
		return nil, fmt.Errorf("unknown geth network %q", network)
	}
}
