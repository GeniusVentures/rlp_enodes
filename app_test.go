package main

import "testing"

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
