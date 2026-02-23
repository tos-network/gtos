// Package tosconfig contains the configuration of the TOS protocol.
package tosconfig

import (
	"fmt"
	"math/big"
	"time"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus"
	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/miner"
	"github.com/tos-network/gtos/node"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/tos/downloader"
	"github.com/tos-network/gtos/tos/gasprice"
	"github.com/tos-network/gtos/tosdb"
)

// FullNodeGPO contains default gasprice oracle settings for full node.
var FullNodeGPO = gasprice.Config{
	Blocks:           20,
	Percentile:       60,
	MaxHeaderHistory: 1024,
	MaxBlockHistory:  1024,
	MaxPrice:         gasprice.DefaultMaxPrice,
	IgnorePrice:      gasprice.DefaultIgnorePrice,
}

// LightClientGPO contains default gasprice oracle settings for light client.
var LightClientGPO = gasprice.Config{
	Blocks:           2,
	Percentile:       60,
	MaxHeaderHistory: 300,
	MaxBlockHistory:  5,
	MaxPrice:         gasprice.DefaultMaxPrice,
	IgnorePrice:      gasprice.DefaultIgnorePrice,
}

// Defaults contains default settings for use on the TOS main net.
var Defaults = Config{
	SyncMode:                1,
	NetworkId:               1,
	TxLookupLimit:           2350000,
	LightPeers:              100,
	UltraLightFraction:      75,
	DatabaseCache:           512,
	TrieCleanCache:          154,
	TrieCleanCacheJournal:   "triecache",
	TrieCleanCacheRejournal: 60 * time.Minute,
	TrieDirtyCache:          256,
	TrieTimeout:             60 * time.Minute,
	SnapshotCache:           102,
	FilterLogCacheSize:      32,
	Miner: miner.Config{
		GasCeil:  30000000,
		GasPrice: big.NewInt(params.GWei),
		Recommit: 3 * time.Second,
	},
	TxPool:        core.DefaultTxPoolConfig,
	RPCGasCap:     50000000,
	RPCEVMTimeout: 5 * time.Second,
	GPO:           FullNodeGPO,
	RPCTxFeeCap:   1, // 1 tos
}

//go:generate go run github.com/fjl/gencodec -type Config -formats toml -out gen_config.go

// Config contains configuration options for the TOS and LES protocols.
type Config struct {
	// The genesis block, which is inserted if the database is empty.
	// If nil, the TOS main net block is used.
	Genesis *core.Genesis `toml:",omitempty"`

	// Protocol options
	NetworkId uint64 // Network ID to use for selecting peers to connect to
	SyncMode  downloader.SyncMode

	// This can be set to list of enrtree:// URLs which will be queried for
	// for nodes to connect to.
	TosDiscoveryURLs  []string
	SnapDiscoveryURLs []string

	NoPruning  bool // Whether to disable pruning and flush everything to disk
	NoPrefetch bool // Whether to disable prefetching and only load state on demand

	TxLookupLimit uint64 `toml:",omitempty"` // The maximum number of blocks from head whose tx indices are reserved.

	// RequiredBlocks is a set of block number -> hash mappings which must be in the
	// canonical chain of all remote peers. Setting the option makes gtos verify the
	// presence of these blocks for every new peer connection.
	RequiredBlocks map[uint64]common.Hash `toml:"-"`

	// Light client options
	LightServ          int  `toml:",omitempty"` // Maximum percentage of time allowed for serving LES requests
	LightIngress       int  `toml:",omitempty"` // Incoming bandwidth limit for light servers
	LightEgress        int  `toml:",omitempty"` // Outgoing bandwidth limit for light servers
	LightPeers         int  `toml:",omitempty"` // Maximum number of LES client peers
	LightNoPrune       bool `toml:",omitempty"` // Whether to disable light chain pruning
	LightNoSyncServe   bool `toml:",omitempty"` // Whether to serve light clients before syncing
	SyncFromCheckpoint bool `toml:",omitempty"` // Whether to sync the header chain from the configured checkpoint

	// Ultra Light client options
	UltraLightServers      []string `toml:",omitempty"` // List of trusted ultra light servers
	UltraLightFraction     int      `toml:",omitempty"` // Percentage of trusted servers to accept an announcement
	UltraLightOnlyAnnounce bool     `toml:",omitempty"` // Whether to only announce headers, or also serve them

	// Database options
	SkipBcVersionCheck bool `toml:"-"`
	DatabaseHandles    int  `toml:"-"`
	DatabaseCache      int
	DatabaseFreezer    string

	TrieCleanCache          int
	TrieCleanCacheJournal   string        `toml:",omitempty"` // Disk journal directory for trie cache to survive node restarts
	TrieCleanCacheRejournal time.Duration `toml:",omitempty"` // Time interval to regenerate the journal for clean cache
	TrieDirtyCache          int
	TrieTimeout             time.Duration
	SnapshotCache           int
	Preimages               bool

	// This is the number of blocks for which logs will be cached in the filter system.
	FilterLogCacheSize int

	// Mining options
	Miner miner.Config

	// Transaction pool options
	TxPool core.TxPoolConfig

	// Gas Price Oracle options
	GPO gasprice.Config

	// Enables tracking of SHA3 preimages in the VM
	EnablePreimageRecording bool

	// Miscellaneous options
	DocRoot string `toml:"-"`

	// RPCGasCap is the global gas cap for tos-call variants.
	RPCGasCap uint64

	// RPCEVMTimeout is the global timeout for tos-call.
	RPCEVMTimeout time.Duration

	// RPCTxFeeCap is the global transaction fee(price * gaslimit) cap for
	// send-transaction variants. The unit is tos.
	RPCTxFeeCap float64

	// Checkpoint is a hardcoded checkpoint which can be nil.
	Checkpoint *params.TrustedCheckpoint `toml:",omitempty"`

	// OverrideTerminalTotalDifficulty (TODO: remove after the fork)
	OverrideTerminalTotalDifficulty *big.Int `toml:",omitempty"`

	// OverrideTerminalTotalDifficultyPassed (TODO: remove after the fork)
	OverrideTerminalTotalDifficultyPassed *bool `toml:",omitempty"`

	// Engine, if non-nil, is used as the consensus engine instead of creating
	// one via CreateConsensusEngine. Intended for tests that need dpos.NewFaker().
	Engine consensus.Engine `toml:"-"`
}

// CreateConsensusEngine creates a consensus engine for the given chain configuration.
// If chainConfig.DPoS is nil (e.g. custom genesis files or legacy network configs that
// predate the DPoS section), it falls back to the protocol defaults.
func CreateConsensusEngine(_ *node.Node, chainConfig *params.ChainConfig, db tosdb.Database) consensus.Engine {
	cfg := chainConfig.DPoS
	if cfg == nil {
		cfg = &params.DPoSConfig{
			Period:        params.DPoSBlockPeriod,
			Epoch:         params.DPoSEpochLength,
			MaxValidators: params.DPoSMaxValidators,
		}
	}
	e, err := dpos.New(cfg, db)
	if err != nil {
		panic(fmt.Sprintf("invalid dpos config: %v", err))
	}
	return e
}
