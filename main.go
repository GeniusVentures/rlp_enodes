package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"path/filepath"
)

func main() {
	configPath := flag.String("config", "chains_config.json", "path to chains_config.json")
	inputFile := flag.String("input", "", "local all.json file to use instead of downloading")
	discover := flag.Bool("discover", false, "run fork-hash discovery and exit; use -v to print the summary")
	verbose := flag.Bool("v", false, "enable verbose output")
	forkIDsOnly := flag.Bool("fork-ids-only", false, "generate output/fork_ids.json and exit")
	baseAll := flag.Bool("base-all", false, "crawl Base bootnodes and write output/base-all.json")
	baseNetwork := flag.String("base-network", "mainnet", "Base network for -base-all: mainnet or sepolia")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	outDir := cfg.OutputDir
	if outDir == "" {
		outDir = "output"
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", outDir, err)
	}

	if *baseAll {
		if err := writeBaseAllFile(*baseNetwork, outDir); err != nil {
			log.Fatalf("write base-all.json: %v", err)
		}
		chainEnodes, err := loadChainOutputsFromDisk(cfg, outDir)
		if err != nil {
			log.Fatalf("load chain outputs: %v", err)
		}
		if err := writeChainEnodes(outDir, chainEnodes); err != nil {
			log.Fatalf("write chain_enodes.json: %v", err)
		}
		return
	}

	raw, err := loadAllJSON(*inputFile, cfg.AllJSONURL)
	if err != nil {
		log.Fatalf("load all.json: %v", err)
	}

	var allNodes map[string]NodeRecord
	if err := json.Unmarshal(raw, &allNodes); err != nil {
		log.Fatalf("parse all.json: %v", err)
	}
	log.Printf("Loaded %d nodes from all.json (SHA256=%s...)", len(allNodes), shortSHA(raw))

	if *discover {
		if *verbose {
			printDiscovery(allNodes)
		} else {
			log.Printf("Discovery summary suppressed; rerun with -discover -v to print it")
		}
		return
	}

	forkIDs := collectForkIDs(cfg, allNodes)
	if err := writeForkIDs(outDir, forkIDs); err != nil {
		log.Fatalf("write fork_ids.json: %v", err)
	}
	forkIDs, err = loadForkIDs(outDir)
	if err != nil {
		log.Fatalf("load fork_ids.json: %v", err)
	}
	if *forkIDsOnly {
		return
	}

	defaultTopN := cfg.DefaultTopN
	if defaultTopN <= 0 {
		defaultTopN = 100
	}

	chainEnodes := make(map[string]ChainOutput)
	for _, chain := range cfg.Chains {
		if chain.Name == "base-mainnet" || chain.Name == "base-sepolia" {
			output, err := loadChainOutputFromDisk(outDir, chain.Name)
			if err != nil {
				if os.IsNotExist(err) {
					log.Printf("[%s] output file not found on disk; skipping for this run", chain.Name)
					continue
				}
				log.Printf("ERROR loading chain %s from disk: %v", chain.Name, err)
				continue
			}
			chainEnodes[chain.Name] = output
			log.Printf("[%s] Loaded %d nodes from existing output file", chain.Name, len(output.Nodes))
			continue
		}
		topN := chain.TopN
		if topN <= 0 {
			topN = defaultTopN
		}
		output, err := processChain(chain, allNodes, outDir, topN, forkIDs)
		if err != nil {
			log.Printf("ERROR processing chain %s: %v", chain.Name, err)
			continue
		}
		if output.Nodes == nil {
			output.Nodes = []OutputNode{}
		}
		chainEnodes[chain.Name] = output
	}

	if err := writeChainEnodes(outDir, chainEnodes); err != nil {
		log.Fatalf("write chain_enodes.json: %v", err)
	}
}

func loadChainOutputsFromDisk(cfg *AppConfig, outDir string) (map[string]ChainOutput, error) {
	chainEnodes := make(map[string]ChainOutput)
	for _, chain := range cfg.Chains {
		path := filepath.Join(outDir, chain.Name+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		var output ChainOutput
		if err := json.Unmarshal(data, &output); err != nil {
			return nil, err
		}
		chainEnodes[chain.Name] = output
	}
	return chainEnodes, nil
}

func loadChainOutputFromDisk(outDir string, chainName string) (ChainOutput, error) {
	path := filepath.Join(outDir, chainName+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return ChainOutput{}, err
	}
	var output ChainOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return ChainOutput{}, err
	}
	return output, nil
}
