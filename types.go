package main

import (
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/params"
)

// AppConfig is the root of chains_config.json.
type AppConfig struct {
	AllJSONURL  string        `json:"allJsonURL"`
	OutputDir   string        `json:"outputDir"`
	DefaultTopN int           `json:"defaultTopN"`
	Chains      []ChainConfig `json:"chains"`
}

// ChainConfig describes one chain to filter for.
//
// filterType values:
//   - "geth_network"   – go-ethereum forkid filter; requires "network".
//   - "enr_field"      – presence of a specific ENR key; requires "enrField".
//   - "fork_hash_list" – eth fork hash exact match; requires "forkHashes".
//   - "bootnodes_yaml" – external YAML list of ENR bootnodes; requires "sourceUrl".
//   - "bootnodes_go"   – external Go file containing a named []string bootnode list;
//     requires "sourceUrl" and "sourceKey".
//   - "bootnodes_enrtree" – EIP-1459 ENR tree source; requires "sourceUrl".
//     See https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1459.md
//
// Compound AND: set both enrField AND forkHashes together with either
// "enr_field" or "fork_hash_list" as filterType to require both conditions.
type ChainConfig struct {
	Name            string   `json:"name"`
	ChainID         int      `json:"chainId"`
	GenesisHex      string   `json:"genesisHex,omitempty"`
	Description     string   `json:"description,omitempty"`
	FilterType      string   `json:"filterType"`
	SourceURL       string   `json:"sourceUrl,omitempty"`
	SourceKey       string   `json:"sourceKey,omitempty"`
	RPCURL          string   `json:"rpcUrl,omitempty"`
	Network         string   `json:"network,omitempty"`    // geth_network / polygon_bor
	EnrField        string   `json:"enrField,omitempty"`   // enr_field (or compound)
	ForkHashes      []string `json:"forkHashes,omitempty"` // fork_hash_list (or compound)
	TopN            int      `json:"topN,omitempty"`
	ForkProvider    string   `json:"forkProvider,omitempty"`
	ForkSourceURL   string   `json:"forkSourceUrl,omitempty"`
	ForkSourceRef   string   `json:"forkSourceRef,omitempty"`
	ForkConfigName  string   `json:"forkConfigName,omitempty"`
	ForkGenesisName string   `json:"forkGenesisName,omitempty"`
	ForkConfigURL   string   `json:"forkConfigUrl,omitempty"`
	ForkConfigPath  string   `json:"forkConfigPath,omitempty"`
	BootnodesType   string   `json:"bootnodesType,omitempty"`
	BootnodesURL    string   `json:"bootnodesUrl,omitempty"`
	BootnodesKey    string   `json:"bootnodesKey,omitempty"`
}

// NodeRecord mirrors one entry in all.json.
type NodeRecord struct {
	Seq           uint64    `json:"seq"`
	Record        string    `json:"record"`
	Score         int       `json:"score"`
	FirstResponse time.Time `json:"firstResponse,omitempty"`
	LastResponse  time.Time `json:"lastResponse,omitempty"`
	LastCheck     time.Time `json:"lastCheck,omitempty"`
}

// OutputNode is one entry in an output {chain}.json file.
type OutputNode struct {
	ENR          string    `json:"enr"`
	Enode        string    `json:"enode,omitempty"`
	Pubkey       string    `json:"pubkey"`
	Score        int       `json:"score"`
	LastResponse time.Time `json:"lastResponse,omitempty"`
	ForkID       string    `json:"-"`
	ForkNext     string    `json:"-"`
	IP           string    `json:"ip,omitempty"`
	Port         int       `json:"port,omitempty"`
}

// ChainOutput is the output structure for a chain's JSON file.
type ChainOutput struct {
	NetworkID     int                 `json:"networkId"`
	GenesisHex    string              `json:"genesisHex"`
	ForkID        string              `json:"forkId"`
	ForkNext      string              `json:"forkNext"`
	UpcomingFork  *UpcomingForkOutput `json:"upcomingFork,omitempty"`
	Nodes         []OutputNode        `json:"nodes"`
	Bootnodes     []OutputNode        `json:"bootnodes"`
	Signature     string              `json:"signature,omitempty"`
	SignerAddress string              `json:"signerAddress,omitempty"`
}

type UpcomingForkOutput struct {
	ForkID   string       `json:"forkId,omitempty"`
	ForkNext string       `json:"forkNext,omitempty"`
	At       string       `json:"at"`
	Nodes    []OutputNode `json:"nodes"`
}

type candidateNode struct {
	nodeID   string
	record   NodeRecord
	node     *enode.Node
	forkHash string // hex-encoded 4-byte fork hash, or "" if no eth entry
	forkNext string
}

type forkTuple struct {
	forkID   string
	forkNext string
}

type LocalForkConfig struct {
	Name           string            `json:"name"`
	ChainID        uint64            `json:"chainId"`
	RPCURL         string            `json:"rpcUrl,omitempty"`
	GenesisHashHex string            `json:"genesisHashHex,omitempty"`
	GenesisTime    uint64            `json:"genesisTime,omitempty"`
	ForkID         string            `json:"forkId,omitempty"`
	ForkNext       string            `json:"forkNext,omitempty"`
	ForkTimes      map[string]uint64 `json:"forkTimes,omitempty"`
}

type polygonBorForkConfig struct {
	chainConfig *params.ChainConfig
	genesisHex  string
	borForks    []*big.Int
}

type ForkTupleOutput struct {
	ForkID   string `json:"forkId"`
	ForkNext string `json:"forkNext"`
}

type ForkUpcomingOutput struct {
	At       string `json:"at"`
	ForkID   string `json:"forkId,omitempty"`
	ForkNext string `json:"forkNext,omitempty"`
}

type ForkIDOutput struct {
	ChainID     int                 `json:"chainId"`
	GenesisHex  string              `json:"genesisHex"`
	ForkID      string              `json:"-"`
	ForkNext    string              `json:"-"`
	Current     ForkTupleOutput     `json:"current"`
	Upcoming    *ForkUpcomingOutput `json:"upcoming,omitempty"`
	Source      string              `json:"source"`
	GeneratedAt time.Time           `json:"generatedAt"`
	Forks       []ForkTupleOutput   `json:"forks,omitempty"`
}

type ForkIDIndex map[string]ForkIDOutput
