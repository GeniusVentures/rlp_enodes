package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
)

type BaseAllNode struct {
	OutputNode
	Source         string `json:"source,omitempty"`
	ForkKey        string `json:"forkKey,omitempty"`
	ForkID         string `json:"forkId,omitempty"`
	ForkNext       string `json:"forkNext,omitempty"`
	OPStackChainID uint64 `json:"opstackChainId,omitempty"`
	ATTSubnet      string `json:"attnets,omitempty"`
}

type BaseAllOutput struct {
	Network   string        `json:"network"`
	Generated time.Time     `json:"generated"`
	Nodes     []BaseAllNode `json:"nodes"`
}

type BaseFilteredResult struct {
	ForkID   string
	ForkNext string
	Nodes    []OutputNode
}

func writeBaseAllFile(network string, outputDir string) error {
	bootnodes, chain, err := loadBaseBootnodes(network)
	if err != nil {
		return err
	}

	nodes, err := crawlBaseBootnodes(bootnodes, chain.TopN)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}

	outPath := filepath.Join(outputDir, fmt.Sprintf("base-%s-all.json", network))
	payload, changed, err := mergeBaseAllOutput(outPath, network, nodes)
	if err != nil {
		return err
	}
	if changed {
		tmpPath := outPath + ".tmp"
		blob, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(tmpPath, blob, 0o644); err != nil {
			return err
		}
		if err := os.Rename(tmpPath, outPath); err != nil {
			return err
		}
		log.Printf("[base-%s] Wrote %d merged nodes → %s", network, len(payload.Nodes), outPath)
	} else {
		log.Printf("[base-%s] No changes for %s", network, outPath)
	}

	chainOutputPath := filepath.Join(outputDir, fmt.Sprintf("base-%s.json", network))
	filtered := filterBaseAllNodes(payload.Nodes, network)
	if err := writeBaseFilteredOutput(network, filtered, chainOutputPath); err != nil {
		return err
	}
	log.Printf("[base-%s] Wrote %d filtered nodes → %s", network, len(filtered.Nodes), chainOutputPath)
	return nil
}

func mergeBaseAllOutput(outPath string, network string, freshNodes []BaseAllNode) (BaseAllOutput, bool, error) {
	merged := make(map[string]BaseAllNode)
	if existing, err := loadBaseAllOutput(outPath); err == nil {
		for _, node := range existing.Nodes {
			merged[baseAllNodeKey(node)] = node
		}
	}
	before := len(merged)
	for _, node := range freshNodes {
		key := baseAllNodeKey(node)
		existing, ok := merged[key]
		if !ok || preferBaseAllNode(node, existing) {
			merged[key] = node
		}
	}

	nodes := make([]BaseAllNode, 0, len(merged))
	for _, node := range merged {
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Source != nodes[j].Source {
			return nodes[i].Source < nodes[j].Source
		}
		if nodes[i].IP != nodes[j].IP {
			return nodes[i].IP < nodes[j].IP
		}
		if nodes[i].Port != nodes[j].Port {
			return nodes[i].Port < nodes[j].Port
		}
		return nodes[i].Pubkey < nodes[j].Pubkey
	})

	changed := len(merged) != before
	return BaseAllOutput{
		Network:   network,
		Generated: time.Now().UTC(),
		Nodes:     nodes,
	}, changed, nil
}

func loadBaseAllOutput(outPath string) (BaseAllOutput, error) {
	data, err := os.ReadFile(outPath)
	if err != nil {
		return BaseAllOutput{}, err
	}
	var payload BaseAllOutput
	if err := json.Unmarshal(data, &payload); err != nil {
		return BaseAllOutput{}, err
	}
	return payload, nil
}

func baseAllNodeKey(node BaseAllNode) string {
	if node.Pubkey != "" {
		return node.Pubkey
	}
	return node.ENR
}

func preferBaseAllNode(candidate BaseAllNode, existing BaseAllNode) bool {
	if existing.Source == "bootnode" && candidate.Source != "bootnode" {
		return true
	}
	if existing.ForkID == "" && candidate.ForkID != "" {
		return true
	}
	if existing.OPStackChainID == 0 && candidate.OPStackChainID != 0 {
		return true
	}
	if existing.ATTSubnet == "" && candidate.ATTSubnet != "" {
		return true
	}
	return false
}

func filterBaseAllNodes(nodes []BaseAllNode, network string) BaseFilteredResult {
	output := make([]OutputNode, 0, len(nodes))
	seen := make(map[string]bool)

	dominantForkID := selectDominantBaseForkID(nodes)
	if dominantForkID == "" {
		log.Printf("[base-%s] No non-empty fork IDs found; returning no filtered nodes", network)
		return BaseFilteredResult{ForkNext: "0", Nodes: output}
	}

	dominantForkNext := "0"
	for _, node := range nodes {
		if node.Port == 0 {
			continue
		}
		if strings.ToLower(node.ForkID) != dominantForkID {
			continue
		}
		if dominantForkNext == "0" && node.ForkNext != "" {
			dominantForkNext = node.ForkNext
		}

		key := node.Pubkey
		if key == "" {
			key = node.ENR
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		output = append(output, node.OutputNode)
	}

	sort.Slice(output, func(i, j int) bool {
		if output[i].Port != output[j].Port {
			return output[i].Port < output[j].Port
		}
		if output[i].IP != output[j].IP {
			return output[i].IP < output[j].IP
		}
		return output[i].Pubkey < output[j].Pubkey
	})
	return BaseFilteredResult{ForkID: dominantForkID, ForkNext: dominantForkNext, Nodes: output}
}

func selectDominantBaseForkID(nodes []BaseAllNode) string {
	counts := make(map[string]int)
	for _, node := range nodes {
		if node.Port == 0 || node.ForkID == "" {
			continue
		}
		counts[strings.ToLower(node.ForkID)]++
	}

	best := ""
	bestCount := 0
	for forkID, count := range counts {
		if count > bestCount {
			best = forkID
			bestCount = count
		}
	}
	return best
}

func writeBaseFilteredOutput(network string, result BaseFilteredResult, outPath string) error {
	chainID := 0
	genesisHex := ""
	switch network {
	case "mainnet":
		chainID = 8453
		genesisHex = "f712aa9241cc24369b143cf6dce85f0902a9731e70d66818a3a5845b296c73dd"
	case "sepolia":
		chainID = 84532
		genesisHex = "0dcc9e089e30b90ddfc55be9a37dd15bc551aeee999d2e2b51414c54eaf934e4"
	}

	payload := ChainOutput{
		NetworkID:  chainID,
		GenesisHex: genesisHex,
		ForkID:     result.ForkID,
		ForkNext:   result.ForkNext,
		Nodes:      result.Nodes,
	}
	blob, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := outPath + ".tmp"
	if err := os.WriteFile(tmpPath, blob, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, outPath)
}

func loadBaseBootnodes(network string) ([]*enode.Node, ChainConfig, error) {
	cfg, err := loadConfig("chains_config.json")
	if err != nil {
		return nil, ChainConfig{}, err
	}

	var chainName string
	switch network {
	case "mainnet":
		chainName = "base-mainnet"
	case "sepolia":
		chainName = "base-sepolia"
	default:
		return nil, ChainConfig{}, fmt.Errorf("unknown base network %q", network)
	}

	var chain ChainConfig
	for _, candidate := range cfg.Chains {
		if candidate.Name == chainName {
			chain = candidate
			break
		}
	}
	if chain.Name == "" {
		return nil, ChainConfig{}, fmt.Errorf("missing chain config for %s", chainName)
	}

	bootnodeRecords, err := loadBootnodesGo("https://raw.githubusercontent.com/base/op-geth/78436b6ae2a45a9c8449a9b0c93b062a37bd20da/params/bootnodes.go", map[string]string{
		"mainnet": "OPMainnetBootnodes",
		"sepolia": "OPSepoliaBootnodes",
	}[network])
	if err != nil {
		return nil, ChainConfig{}, err
	}

	bootnodes := make([]*enode.Node, 0, len(bootnodeRecords))
	for _, record := range bootnodeRecords {
		normalized := normalizeGoBootnode(record)
		node, err := enode.Parse(enode.ValidSchemes, normalized)
		if err != nil {
			continue
		}
		bootnodes = append(bootnodes, node)
	}
	if len(bootnodes) == 0 {
		return nil, ChainConfig{}, fmt.Errorf("no Base bootnodes parsed for %s", network)
	}
	return bootnodes, chain, nil
}

func crawlBaseBootnodes(bootnodes []*enode.Node, topN int) ([]BaseAllNode, error) {
	priv, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	db, err := enode.OpenDB("")
	if err != nil {
		return nil, err
	}
	localNode := enode.NewLocalNode(db, priv)
	localNode.SetFallbackIP(net.ParseIP("0.0.0.0"))
	localNode.SetFallbackUDP(0)

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.Close()
	}()

	discv5, err := discover.ListenV5(conn, localNode, discover.Config{
		PrivateKey:      priv,
		Bootnodes:       bootnodes,
		ValidSchemes:    enode.ValidSchemes,
		RefreshInterval: 15 * time.Second,
		PingInterval:    15 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	defer discv5.Close()

	for _, node := range bootnodes {
		discv5.AddKnownNode(node)
	}

	time.Sleep(30 * time.Second)
	candidates := make(map[string]*enode.Node)
	sources := make(map[string]string)
	for _, node := range bootnodes {
		key := node.ID().String()
		candidates[key] = node
		sources[key] = "bootnode"
	}
	for _, node := range discv5.AllNodes() {
		key := node.ID().String()
		candidates[key] = node
		if sources[key] == "" {
			sources[key] = "discv5"
		}
	}

	output := make([]BaseAllNode, 0, len(candidates))
	for key, node := range candidates {
		out := BaseAllNode{
			OutputNode: OutputNode{ENR: node.String()},
			Source:     sources[key],
		}
		if enodeURL := node.URLv4(); enodeURL != "" {
			out.Enode = enodeURL
		}
		if pubkey := node.Pubkey(); pubkey != nil {
			out.Pubkey = fmt.Sprintf("%x", crypto.FromECDSAPub(pubkey)[1:])
		}
		if ip := node.IP(); ip != nil {
			out.IP = ip.String()
		}
		if port := node.TCP(); port > 0 {
			out.Port = port
		} else if port := node.UDP(); port > 0 {
			out.Port = port
		}
		if out.Port == 0 {
			continue
		}

		if forkID, forkNext := extractForkID(node); forkID != "" {
			out.ForkID = forkID
			out.ForkNext = forkNext
			if ethForkID, _ := extractForkIDFromENRKey(node, "eth"); ethForkID != "" {
				out.ForkKey = "eth"
			} else if opelForkID, _ := extractForkIDFromENRKey(node, "opel"); opelForkID != "" {
				out.ForkKey = "opel"
			}
		}

		var opstackChainID uint64
		if node.Load(enr.WithEntry("opstack", &opstackChainID)) == nil {
			out.OPStackChainID = opstackChainID
		}
		var attnets []byte
		if node.Load(enr.WithEntry("attnets", &attnets)) == nil {
			out.ATTSubnet = fmt.Sprintf("%x", attnets)
		}

		output = append(output, out)
	}

	sort.Slice(output, func(i, j int) bool {
		if output[i].Source != output[j].Source {
			return output[i].Source < output[j].Source
		}
		if output[i].IP != output[j].IP {
			return output[i].IP < output[j].IP
		}
		if output[i].Port != output[j].Port {
			return output[i].Port < output[j].Port
		}
		return output[i].Pubkey < output[j].Pubkey
	})
	if topN > 0 && len(output) > topN {
		output = output[:topN]
	}
	return output, nil
}
