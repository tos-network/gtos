package params

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/tos-network/gtos/common"
	"golang.org/x/crypto/sha3"
)

// Genesis hashes to enforce below configs on.
var (
	MainnetGenesisHash = common.HexToHash("0x55b0800c7a891f1755ebe8d48bff7408aba63f2f307c0d4e82e6be20c28d2683")
)

// TrustedCheckpoints associates each known checkpoint with the genesis hash of
// the chain it belongs to.
var TrustedCheckpoints = map[common.Hash]*TrustedCheckpoint{
	MainnetGenesisHash: MainnetTrustedCheckpoint,
}

// CheckpointOracles associates each known checkpoint oracles with the genesis hash of
// the chain it belongs to.
var CheckpointOracles = map[common.Hash]*CheckpointOracleConfig{
	MainnetGenesisHash: MainnetCheckpointOracle,
}

var (
	MainnetTerminalTotalDifficulty, _ = new(big.Int).SetString("58_750_000_000_000_000_000_000", 0)

	// MainnetChainConfig is the chain parameters to run a node on the main network.
	MainnetChainConfig = &ChainConfig{
		ChainID:                       big.NewInt(1),
		AIGenesisBlock:                big.NewInt(0),
		TerminalTotalDifficulty:       MainnetTerminalTotalDifficulty, // 58_750_000_000_000_000_000_000
		TerminalTotalDifficultyPassed: true,
	}

	// MainnetTrustedCheckpoint contains the light client trusted checkpoint for the main network.
	MainnetTrustedCheckpoint = &TrustedCheckpoint{
		SectionIndex: 451,
		SectionHead:  common.HexToHash("0xe47f84b9967eb2ad2afff74d59901b63134660011822fdababaf8fdd18a75aa6"),
		CHTRoot:      common.HexToHash("0xc31e0462ca3d39a46111bb6b63ac4e1cac84089472b7474a319d582f72b3f0c0"),
		BloomRoot:    common.HexToHash("0x7c9f25ce3577a3ab330d52a7343f801899cf9d4980c69f81de31ccc1a055c809"),
	}

	// MainnetCheckpointOracle contains a set of configs for the main network oracle.
	MainnetCheckpointOracle = &CheckpointOracleConfig{
		Address: common.HexToAddress("0x9a9070028361F7AAbeB3f2F2Dc07F82C4a98A02a"),
		Signers: []common.Address{
			common.HexToAddress("0x1b2C260efc720BE89101890E4Db589b44E950527"), // Peter
			common.HexToAddress("0x78d1aD571A1A09D60D9BBf25894b44e4C8859595"), // Martin
			common.HexToAddress("0x286834935f4A8Cfb4FF4C77D5770C2775aE2b0E7"), // Zsolt
			common.HexToAddress("0xb86e2B0Ab5A4B1373e40c51A7C712c70Ba2f9f8E"), // Gary
			common.HexToAddress("0x0DF8fa387C602AE62559cC4aFa4972A7045d6707"), // Guillaume
		},
		Threshold: 2,
	}

	// AllDPoSProtocolChanges contains every protocol change proposal introduced
	// and accepted by the TOS core developers into the DPoS consensus.
	AllDPoSProtocolChanges = &ChainConfig{
		ChainID:        big.NewInt(1337),
		AIGenesisBlock: big.NewInt(0),
		DPoS:           &DPoSConfig{Period: 3, Epoch: 200, MaxValidators: 21},
	}

	TestChainConfig = &ChainConfig{
		ChainID:        big.NewInt(1),
		AIGenesisBlock: big.NewInt(0),
		DPoS:           &DPoSConfig{Period: 3, Epoch: 200, MaxValidators: 21},
	}
	TestRules = TestChainConfig.Rules(new(big.Int), false)
)

// NetworkNames are user friendly names to use in the chain spec banner.
var NetworkNames = map[string]string{
	MainnetChainConfig.ChainID.String(): "mainnet",
}

// TrustedCheckpoint represents a set of post-processed trie roots (CHT and
// BloomTrie) associated with the appropriate section index and head hash. It is
// used to start light syncing from this checkpoint and avoid downloading the
// entire header chain while still being able to securely access old headers/logs.
type TrustedCheckpoint struct {
	SectionIndex uint64      `json:"sectionIndex"`
	SectionHead  common.Hash `json:"sectionHead"`
	CHTRoot      common.Hash `json:"chtRoot"`
	BloomRoot    common.Hash `json:"bloomRoot"`
}

// HashEqual returns an indicator comparing the itself hash with given one.
func (c *TrustedCheckpoint) HashEqual(hash common.Hash) bool {
	if c.Empty() {
		return hash == common.Hash{}
	}
	return c.Hash() == hash
}

// Hash returns the hash of checkpoint's four key fields(index, sectionHead, chtRoot and bloomTrieRoot).
func (c *TrustedCheckpoint) Hash() common.Hash {
	var sectionIndex [8]byte
	binary.BigEndian.PutUint64(sectionIndex[:], c.SectionIndex)

	w := sha3.NewLegacyKeccak256()
	w.Write(sectionIndex[:])
	w.Write(c.SectionHead[:])
	w.Write(c.CHTRoot[:])
	w.Write(c.BloomRoot[:])

	var h common.Hash
	w.Sum(h[:0])
	return h
}

// Empty returns an indicator whether the checkpoint is regarded as empty.
func (c *TrustedCheckpoint) Empty() bool {
	return c.SectionHead == (common.Hash{}) || c.CHTRoot == (common.Hash{}) || c.BloomRoot == (common.Hash{})
}

// CheckpointOracleConfig represents a set of checkpoint contract(which acts as an oracle)
// config which used for light client checkpoint syncing.
type CheckpointOracleConfig struct {
	Address   common.Address   `json:"address"`
	Signers   []common.Address `json:"signers"`
	Threshold uint64           `json:"threshold"`
}

// ChainConfig is the core config which determines the blockchain settings.
//
// ChainConfig is stored in the database on a per block basis. This means
// that any network, identified by its genesis block, can have its own
// set of configuration options.
type ChainConfig struct {
	ChainID *big.Int `json:"chainId"` // chainId identifies the current chain and is used for replay protection

	AIGenesisBlock     *big.Int `json:"aiGenesisBlock,omitempty"`     // TIP-5133 (bomb delay) switch block (nil = no fork, 0 = already activated)
	MergeNetsplitBlock *big.Int `json:"mergeNetsplitBlock,omitempty"` // Virtual fork after The Merge to use as a network splitter
	ShanghaiBlock      *big.Int `json:"shanghaiBlock,omitempty"`      // Shanghai switch block (nil = no fork, 0 = already on shanghai)
	CancunBlock        *big.Int `json:"cancunBlock,omitempty"`        // Cancun switch block (nil = no fork, 0 = already on cancun)

	// TerminalTotalDifficulty is the amount of total difficulty reached by
	// the network that triggers the consensus upgrade.
	TerminalTotalDifficulty *big.Int `json:"terminalTotalDifficulty,omitempty"`

	// TerminalTotalDifficultyPassed is a flag specifying that the network already
	// passed the terminal total difficulty. Its purpose is to disable legacy sync
	// even without having seen the TTD locally (safer long term).
	TerminalTotalDifficultyPassed bool `json:"terminalTotalDifficultyPassed,omitempty"`

	// Various consensus engines
	DPoS *DPoSConfig `json:"dpos,omitempty"`
}

// DPoSConfig is the consensus engine config for delegated proof-of-stake based sealing.
type DPoSConfig struct {
	Period        uint64 `json:"period"`        // target block interval (seconds)
	Epoch         uint64 `json:"epoch"`         // blocks between validator-set snapshots
	MaxValidators uint64 `json:"maxValidators"` // maximum active validators
}

// String implements the stringer interface, returning the consensus engine details.
func (c *DPoSConfig) String() string {
	return fmt.Sprintf("{period: %d, epoch: %d, maxValidators: %d}",
		c.Period, c.Epoch, c.MaxValidators)
}

// String implements the fmt.Stringer interface.
func (c *ChainConfig) String() string {
	var banner string

	// Create some basinc network config output
	network := NetworkNames[c.ChainID.String()]
	if network == "" {
		network = "unknown"
	}
	banner += fmt.Sprintf("Chain ID:  %v (%s)\n", c.ChainID, network)
	if c.DPoS != nil {
		banner += "Consensus: DPoS (delegated proof-of-stake)\n"
	} else {
		banner += "Consensus: unknown\n"
	}
	banner += "\n"

	banner += "Pre-Merge rules:\n"
	if c.AIGenesisBlock != nil {
		banner += fmt.Sprintf(" - AI Genesis baseline:       %-8v (all prior rules included)\n", c.AIGenesisBlock)
	}
	if c.ShanghaiBlock != nil {
		banner += fmt.Sprintf(" - Shanghai:                     %-8v (https://github.com/tos/execution-specs/blob/master/network-upgrades/mainnet-upgrades/shanghai.md)\n", c.ShanghaiBlock)
	}
	if c.CancunBlock != nil {
		banner += fmt.Sprintf(" - Cancun:                      %-8v\n", c.CancunBlock)
	}
	banner += "\n"

	// Add a special section for the merge as it's non-obvious
	if c.TerminalTotalDifficulty == nil {
		banner += "The Merge is not yet available for this network!\n"
		banner += " - Hard-fork specification: https://github.com/tos/execution-specs/blob/master/network-upgrades/mainnet-upgrades/paris.md"
	} else {
		banner += "Merge configured:\n"
		banner += " - Hard-fork specification:    https://github.com/tos/execution-specs/blob/master/network-upgrades/mainnet-upgrades/paris.md\n"
		banner += fmt.Sprintf(" - Network known to be merged: %v\n", c.TerminalTotalDifficultyPassed)
		banner += fmt.Sprintf(" - Total terminal difficulty:  %v\n", c.TerminalTotalDifficulty)
		banner += fmt.Sprintf(" - Merge netsplit block:       %-8v", c.MergeNetsplitBlock)
	}
	return banner
}

// IsAIGenesis returns whether num is either equal to the AI Genesis (TIP-5133) fork block or greater.
func (c *ChainConfig) IsAIGenesis(num *big.Int) bool {
	return isForked(c.AIGenesisBlock, num)
}

// IsTerminalPoWBlock returns whether the given block is the last block of PoW stage.
func (c *ChainConfig) IsTerminalPoWBlock(parentTotalDiff *big.Int, totalDiff *big.Int) bool {
	if c.TerminalTotalDifficulty == nil {
		return false
	}
	return parentTotalDiff.Cmp(c.TerminalTotalDifficulty) < 0 && totalDiff.Cmp(c.TerminalTotalDifficulty) >= 0
}

// IsShanghai returns whether num is either equal to the Shanghai fork block or greater.
func (c *ChainConfig) IsShanghai(num *big.Int) bool {
	return isForked(c.ShanghaiBlock, num)
}

// IsCancun returns whether num is either equal to the Cancun fork block or greater.
func (c *ChainConfig) IsCancun(num *big.Int) bool {
	return isForked(c.CancunBlock, num)
}

// CheckCompatible checks whether scheduled fork transitions have been imported
// with a mismatching chain configuration.
func (c *ChainConfig) CheckCompatible(newcfg *ChainConfig, height uint64) *ConfigCompatError {
	bhead := new(big.Int).SetUint64(height)

	// Iterate checkCompatible to find the lowest conflict.
	var lasterr *ConfigCompatError
	for {
		err := c.checkCompatible(newcfg, bhead)
		if err == nil || (lasterr != nil && err.RewindTo == lasterr.RewindTo) {
			break
		}
		lasterr = err
		bhead.SetUint64(err.RewindTo)
	}
	return lasterr
}

// CheckConfigForkOrder checks that we don't "skip" any forks, gtos isn't pluggable enough
// to guarantee that forks can be implemented in a different order than on official networks
func (c *ChainConfig) CheckConfigForkOrder() error {
	type fork struct {
		name     string
		block    *big.Int
		optional bool // if true, the fork may be nil and next fork is still allowed
	}
	var lastFork fork
	for _, cur := range []fork{
		{name: "aiGenesisBlock", block: c.AIGenesisBlock, optional: true},
		{name: "mergeNetsplitBlock", block: c.MergeNetsplitBlock, optional: true},
		{name: "shanghaiBlock", block: c.ShanghaiBlock, optional: true},
		{name: "cancunBlock", block: c.CancunBlock, optional: true},
	} {
		if lastFork.name != "" {
			// Next one must be higher number
			if lastFork.block == nil && cur.block != nil {
				return fmt.Errorf("unsupported fork ordering: %v not enabled, but %v enabled at %v",
					lastFork.name, cur.name, cur.block)
			}
			if lastFork.block != nil && cur.block != nil {
				if lastFork.block.Cmp(cur.block) > 0 {
					return fmt.Errorf("unsupported fork ordering: %v enabled at %v, but %v enabled at %v",
						lastFork.name, lastFork.block, cur.name, cur.block)
				}
			}
		}
		// If it was optional and not set, then ignore it
		if !cur.optional || cur.block != nil {
			lastFork = cur
		}
	}
	return nil
}

func (c *ChainConfig) checkCompatible(newcfg *ChainConfig, head *big.Int) *ConfigCompatError {
	if !configNumEqual(c.ChainID, newcfg.ChainID) {
		return &ConfigCompatError{
			What:         "chain ID",
			StoredConfig: c.ChainID,
			NewConfig:    newcfg.ChainID,
			RewindTo:     0,
		}
	}
	if isForkIncompatible(c.AIGenesisBlock, newcfg.AIGenesisBlock, head) {
		return newCompatError("AI Genesis fork block", c.AIGenesisBlock, newcfg.AIGenesisBlock)
	}
	if isForkIncompatible(c.MergeNetsplitBlock, newcfg.MergeNetsplitBlock, head) {
		return newCompatError("Merge netsplit fork block", c.MergeNetsplitBlock, newcfg.MergeNetsplitBlock)
	}
	if isForkIncompatible(c.ShanghaiBlock, newcfg.ShanghaiBlock, head) {
		return newCompatError("Shanghai fork block", c.ShanghaiBlock, newcfg.ShanghaiBlock)
	}
	if isForkIncompatible(c.CancunBlock, newcfg.CancunBlock, head) {
		return newCompatError("Cancun fork block", c.CancunBlock, newcfg.CancunBlock)
	}
	return nil
}

// isForkIncompatible returns true if a fork scheduled at s1 cannot be rescheduled to
// block s2 because head is already past the fork.
func isForkIncompatible(s1, s2, head *big.Int) bool {
	return (isForked(s1, head) || isForked(s2, head)) && !configNumEqual(s1, s2)
}

// isForked returns whether a fork scheduled at block s is active at the given head block.
func isForked(s, head *big.Int) bool {
	if s == nil || head == nil {
		return false
	}
	return s.Cmp(head) <= 0
}

func configNumEqual(x, y *big.Int) bool {
	if x == nil {
		return y == nil
	}
	if y == nil {
		return x == nil
	}
	return x.Cmp(y) == 0
}

// ConfigCompatError is raised if the locally-stored blockchain is initialised with a
// ChainConfig that would alter the past.
type ConfigCompatError struct {
	What string
	// block numbers of the stored and new configurations
	StoredConfig, NewConfig *big.Int
	// the block number to which the local chain must be rewound to correct the error
	RewindTo uint64
}

func newCompatError(what string, storedblock, newblock *big.Int) *ConfigCompatError {
	var rew *big.Int
	switch {
	case storedblock == nil:
		rew = newblock
	case newblock == nil || storedblock.Cmp(newblock) < 0:
		rew = storedblock
	default:
		rew = newblock
	}
	err := &ConfigCompatError{what, storedblock, newblock, 0}
	if rew != nil && rew.Sign() > 0 {
		err.RewindTo = rew.Uint64() - 1
	}
	return err
}

func (err *ConfigCompatError) Error() string {
	return fmt.Sprintf("mismatching %s in database (have %d, want %d, rewindto %d)", err.What, err.StoredConfig, err.NewConfig, err.RewindTo)
}

// Rules wraps ChainConfig and is merely syntactic sugar or can be used for functions
// that do not have or require information about the block.
//
// Rules is a one time interface meaning that it shouldn't be used in between transition
// phases.
type Rules struct {
	ChainID                       *big.Int
	IsAiBaseline                  bool
	IsMerge, IsShanghai, IsCancun bool
}

// Rules ensures c's ChainID is not nil.
func (c *ChainConfig) Rules(num *big.Int, isMerge bool) Rules {
	chainID := c.ChainID
	if chainID == nil {
		chainID = new(big.Int)
	}
	return Rules{
		ChainID:      new(big.Int).Set(chainID),
		IsAiBaseline: c.IsAIGenesis(num),
		IsMerge:      isMerge,
		IsShanghai:   c.IsShanghai(num),
		IsCancun:     c.IsCancun(num),
	}
}
