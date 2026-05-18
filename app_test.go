package main

import (
	"testing"
	"time"
)

func TestForkTuplesFromClientConfigIgnoresNestedBorForks(t *testing.T) {
	src := `
var TestGenesisHash = common.HexToHash("0000000000000000000000000000000000000000000000000000000000000001")
var TestChainConfig = &ChainConfig{
	ChainID:        big.NewInt(137),
	HomesteadBlock: big.NewInt(10),
	Bor: &bor.BorConfig{
		JaipurBlock: big.NewInt(30),
	},
}
`

	current, tuples, err := forkTuplesFromClientConfig(src, "TestChainConfig", "TestGenesisHash", 20, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("fork tuples from client config: %v", err)
	}
	if current.forkNext != "0" {
		t.Fatalf("current forkNext = %s, want 0; nested Bor fork was included", current.forkNext)
	}
	if len(tuples) != 2 {
		t.Fatalf("tuple count = %d, want 2; nested Bor fork was included", len(tuples))
	}
}

func TestCurrentGethForkTuple(t *testing.T) {
	cfg, err := loadConfig("chains_config.json")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	chains := make(map[string]ChainConfig)
	for _, chain := range cfg.Chains {
		chains[chain.Name] = chain
	}

	tests := []struct {
		name     string
		forkID   string
		forkNext string
	}{
		{name: "ethereum-mainnet", forkID: "07c9462e", forkNext: "0"},
		{name: "ethereum-sepolia", forkID: "268956b6", forkNext: "0"},
		{name: "ethereum-holesky", forkID: "9bc6cb31", forkNext: "0"},
		{name: "ethereum-hoodi", forkID: "23aa1351", forkNext: "0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain, ok := chains[tt.name]
			if !ok {
				t.Fatalf("missing chain config")
			}

			got, err := currentGethForkTuple(chain)
			if err != nil {
				t.Fatalf("current geth fork tuple: %v", err)
			}
			if got.forkID != tt.forkID || got.forkNext != tt.forkNext {
				t.Fatalf("current tuple = (%s, %s), want (%s, %s)", got.forkID, got.forkNext, tt.forkID, tt.forkNext)
			}
		})
	}
}
