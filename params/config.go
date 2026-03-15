// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/tos-network/gtos/common"
	"golang.org/x/crypto/sha3"
)

// Genesis hashes to enforce below configs on.
var (
	MainnetGenesisHash = common.HexToHash("0x48dec5dc45b1944fc6263d44a6669e4b0fa29e4791a200c7b9f8fabef38e9ca7")
	TestnetGenesisHash = common.HexToHash("0xe96ea9c1dc1c3c1796ee06a65b042265316ec1aa0baefbb8733a26384eeea93c")
)

// TrustedCheckpoints associates each known checkpoint with the genesis hash of
// the chain it belongs to.
var TrustedCheckpoints = map[common.Hash]*TrustedCheckpoint{
	// No built-in trusted checkpoint is defined for the rewritten built-in genesis.
}

var (
	MainnetTerminalTotalDifficulty, _ = new(big.Int).SetString("58_750_000_000_000_000_000_000", 0)

	// MainnetChainConfig is the chain parameters to run a node on the main network.
	MainnetChainConfig = &ChainConfig{
		ChainID:                       big.NewInt(1),
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

	// TestnetChainConfig is the chain parameters to run a node on the test network.
	TestnetChainConfig = &ChainConfig{
		ChainID: big.NewInt(1666),
		DPoS: &DPoSConfig{
			PeriodMs:       DPoSBlockPeriodMs,
			Epoch:          DPoSEpochLength,
			MaxValidators:  DPoSMaxValidators,
			TurnLength:     DPoSTurnLength,
			SealSignerType: DefaultDPoSSealSignerType,
		},
	}

	// AllDPoSProtocolChanges contains every protocol change proposal introduced
	// and accepted by the TOS core developers into the DPoS consensus.
	AllDPoSProtocolChanges = &ChainConfig{
		ChainID: big.NewInt(1337),
		DPoS: &DPoSConfig{
			PeriodMs:       DPoSBlockPeriodMs,
			Epoch:          DPoSEpochLength,
			MaxValidators:  DPoSMaxValidators,
			TurnLength:     DPoSTurnLength,
			SealSignerType: DefaultDPoSSealSignerType,
		},
	}

	TestChainConfig = &ChainConfig{
		ChainID: big.NewInt(1),
		DPoS: &DPoSConfig{
			PeriodMs:       DPoSBlockPeriodMs,
			Epoch:          DPoSEpochLength,
			MaxValidators:  DPoSMaxValidators,
			TurnLength:     DPoSTurnLength,
			SealSignerType: DefaultDPoSSealSignerType,
		},
	}
	TestRules = TestChainConfig.Rules(new(big.Int), false)
)

const (
	DPoSSealSignerTypeEd25519 = "ed25519"
	DefaultDPoSSealSignerType = DPoSSealSignerTypeEd25519
)

func NormalizeDPoSSealSignerType(signerType string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(signerType)) {
	case "", DPoSSealSignerTypeEd25519:
		return DPoSSealSignerTypeEd25519, nil
	default:
		return "", fmt.Errorf("unsupported dpos seal signer type %q: only ed25519 is allowed", strings.TrimSpace(signerType))
	}
}

// NetworkNames are user friendly names to use in the chain spec banner.
var NetworkNames = map[string]string{
	MainnetChainConfig.ChainID.String(): "mainnet",
	TestnetChainConfig.ChainID.String(): "testnet",
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

// ChainConfig is the core config which determines the blockchain settings.
//
// ChainConfig is stored in the database on a per block basis. This means
// that any network, identified by its genesis block, can have its own
// set of configuration options.
type ChainConfig struct {
	ChainID *big.Int `json:"chainId"` // chainId identifies the current chain and is used for replay protection

	// TerminalTotalDifficulty is the amount of total difficulty reached by
	// the network that triggers the consensus upgrade.
	TerminalTotalDifficulty *big.Int `json:"terminalTotalDifficulty,omitempty"`

	// TerminalTotalDifficultyPassed is a flag specifying that the network already
	// passed the terminal total difficulty. Its purpose is to disable legacy sync
	// even without having seen the TTD locally (safer long term).
	TerminalTotalDifficultyPassed bool `json:"terminalTotalDifficultyPassed,omitempty"`

	// ProtocolForks lists the block numbers at which hard-fork protocol upgrades
	// activate, in ascending order. These are fed into the devp2p fork-ID checksum
	// (forkid.gatherForks) so that post-fork nodes reject pre-fork peers and vice
	// versa. Leave nil for the current single-version network (no scheduled forks).
	// When planning a hard fork, append its activation block number here AND deploy
	// the new binary before that block is reached.
	ProtocolForks []uint64 `json:"protocolForks,omitempty"`

	// Various consensus engines
	DPoS *DPoSConfig `json:"dpos,omitempty"`
}

// DPoSConfig is the consensus engine config for delegated proof-of-stake based sealing.
type DPoSConfig struct {
	PeriodMs                uint64   `json:"periodMs"`                          // target block interval (milliseconds)
	Epoch                   uint64   `json:"epoch"`                             // blocks between validator-set snapshots
	MaxValidators           uint64   `json:"maxValidators"`                     // maximum active validators
	RecentSignerWindow      uint64   `json:"recentSignerWindow,omitempty"`      // recent-sign window in slots; 0 => auto (grouped-turn default)
	TurnLength              uint64   `json:"turnLength,omitempty"`              // consecutive slots owned by the in-turn proposer; mandatory
	SealSignerType          string   `json:"sealSignerType,omitempty"`          // consensus block-seal signer type: ed25519 only
	MaintenanceMaxBlocks    uint64   `json:"maintenanceMaxBlocks,omitempty"`    // max blocks a validator may remain in maintenance before protocol expiry; 0 => default
	CheckpointInterval      uint64   `json:"checkpointInterval,omitempty"`      // blocks between checkpoint finality votes (0 => inactive)
	CheckpointFinalityBlock *big.Int `json:"checkpointFinalityBlock,omitempty"` // activation block for checkpoint finality (nil => inactive)
}

// TargetBlockPeriodMs returns the configured target block interval in milliseconds.
func (c *DPoSConfig) TargetBlockPeriodMs() uint64 {
	if c == nil {
		return 0
	}
	return c.PeriodMs
}

// RecentSignerWindowSize returns the effective recent-sign window in slots.
// If RecentSignerWindow is zero, it defaults to grouped-turn history:
// (validators/2 + 1) * turnLength - 1.
func (c *DPoSConfig) RecentSignerWindowSize(validators int) uint64 {
	if validators <= 0 {
		return 1
	}
	if c != nil && c.RecentSignerWindow > 0 {
		return c.RecentSignerWindow
	}
	turnLength := uint64(1)
	if c != nil && c.TurnLength > 0 {
		turnLength = c.TurnLength
	}
	return (uint64(validators/2)+1)*turnLength - 1
}

// MaintenanceMaxBlocksEffective returns the effective protocol-hard maintenance
// expiry window in blocks.
func (c *DPoSConfig) MaintenanceMaxBlocksEffective() uint64 {
	if c != nil && c.MaintenanceMaxBlocks > 0 {
		return c.MaintenanceMaxBlocks
	}
	return DPoSMaintenanceMaxBlocks
}

// UnmarshalJSON rejects the removed legacy dpos.period field.
func (c *DPoSConfig) UnmarshalJSON(input []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(input, &fields); err != nil {
		return err
	}
	if _, ok := fields["period"]; ok {
		return fmt.Errorf("dpos.period is removed; use dpos.periodMs")
	}
	type dposConfigAlias DPoSConfig
	var dec dposConfigAlias
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	*c = DPoSConfig(dec)
	return nil
}

// String implements the stringer interface, returning the consensus engine details.
func (c *DPoSConfig) String() string {
	return fmt.Sprintf("{periodMs: %d, epoch: %d, maxValidators: %d, recentSignerWindow: %d, turnLength: %d, sealSignerType: %s, maintenanceMaxBlocks: %d}",
		c.TargetBlockPeriodMs(), c.Epoch, c.MaxValidators, c.RecentSignerWindow, c.TurnLength, c.SealSignerType, c.MaintenanceMaxBlocksEffective())
}

// IsCheckpointFinality reports whether checkpoint finality is active at the given block number.
func (c *DPoSConfig) IsCheckpointFinality(num *big.Int) bool {
	return c != nil && c.CheckpointFinalityBlock != nil &&
		num != nil && num.Cmp(c.CheckpointFinalityBlock) >= 0
}

// FirstEligibleCheckpoint returns the smallest checkpoint height h such that
// h >= CheckpointFinalityBlock and h % CheckpointInterval == 0.
// Returns 0 if checkpoint finality is not configured.
func (c *DPoSConfig) FirstEligibleCheckpoint() uint64 {
	if c == nil || c.CheckpointFinalityBlock == nil || c.CheckpointInterval == 0 {
		return 0
	}
	base := c.CheckpointFinalityBlock.Uint64()
	k := c.CheckpointInterval
	rem := base % k
	if rem == 0 {
		return base
	}
	return base + (k - rem)
}

// ValidateCheckpointConfig returns an error if the checkpoint finality configuration
// is invalid. Called during engine construction.
func (c *DPoSConfig) ValidateCheckpointConfig() error {
	if c == nil || c.CheckpointFinalityBlock == nil {
		return nil
	}
	if c.MaxValidators > 64 {
		return fmt.Errorf("checkpoint finality v1 requires MaxValidators <= 64, got %d", c.MaxValidators)
	}
	if c.CheckpointInterval == 0 {
		c.CheckpointInterval = 200
	}
	return nil
}

// ValidateTurnLengthConfig returns an error if grouped-turn DPoS parameters are invalid.
func (c *DPoSConfig) ValidateTurnLengthConfig() error {
	if c == nil {
		return nil
	}
	if c.TurnLength == 0 {
		return fmt.Errorf("dpos: turnLength missing or zero")
	}
	if c.Epoch == 0 {
		return fmt.Errorf("dpos: epoch must be > 0")
	}
	if c.TurnLength > c.Epoch {
		return fmt.Errorf("dpos: turnLength %d exceeds epoch %d", c.TurnLength, c.Epoch)
	}
	if c.Epoch%c.TurnLength != 0 {
		return fmt.Errorf("dpos: epoch %d must be divisible by turnLength %d", c.Epoch, c.TurnLength)
	}
	return nil
}

// ValidateMaintenanceConfig returns an error if maintenance-governance
// parameters are invalid. Zero means "use protocol default".
func (c *DPoSConfig) ValidateMaintenanceConfig() error {
	if c == nil {
		return nil
	}
	if c.MaintenanceMaxBlocks == 0 {
		c.MaintenanceMaxBlocks = DPoSMaintenanceMaxBlocks
	}
	if c.MaintenanceMaxBlocks == 0 {
		return fmt.Errorf("dpos: maintenanceMaxBlocks missing or zero")
	}
	return nil
}

func normalizedCheckpointCompatibility(cfg *DPoSConfig) (uint64, *big.Int) {
	if cfg == nil || cfg.CheckpointFinalityBlock == nil {
		return 0, nil
	}
	interval := cfg.CheckpointInterval
	if interval == 0 {
		interval = 200
	}
	return interval, new(big.Int).Set(cfg.CheckpointFinalityBlock)
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

	// Add a special section for the merge as it's non-obvious
	if c.TerminalTotalDifficulty == nil {
		banner += "The Merge is not yet available for this network!\n"
		banner += " - Hard-fork specification: https://github.com/tos/execution-specs/blob/master/network-upgrades/mainnet-upgrades/paris.md"
	} else {
		banner += "Merge configured:\n"
		banner += " - Hard-fork specification:    https://github.com/tos/execution-specs/blob/master/network-upgrades/mainnet-upgrades/paris.md\n"
		banner += fmt.Sprintf(" - Network known to be merged: %v\n", c.TerminalTotalDifficultyPassed)
		banner += fmt.Sprintf(" - Total terminal difficulty:  %v", c.TerminalTotalDifficulty)
	}
	return banner
}

// IsTerminalPoWBlock returns whether the given block is the last block of PoW stage.
func (c *ChainConfig) IsTerminalPoWBlock(parentTotalDiff *big.Int, totalDiff *big.Int) bool {
	if c.TerminalTotalDifficulty == nil {
		return false
	}
	return parentTotalDiff.Cmp(c.TerminalTotalDifficulty) < 0 && totalDiff.Cmp(c.TerminalTotalDifficulty) >= 0
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

// CheckConfigForkOrder validates chain-config ordering constraints.
func (c *ChainConfig) CheckConfigForkOrder() error {
	for i, fork := range c.ProtocolForks {
		if fork == 0 {
			return fmt.Errorf("protocolForks[%d] must be > 0", i)
		}
		if i > 0 && fork <= c.ProtocolForks[i-1] {
			return fmt.Errorf("protocolForks must be strictly increasing: index %d has %d after %d", i, fork, c.ProtocolForks[i-1])
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
	// DPoS consensus params are immutable: mismatches must block startup (Fatal=true)
	// even when RewindTo==0, because rewinding cannot fix a consensus engine mismatch.
	if (c.DPoS == nil) != (newcfg.DPoS == nil) {
		return &ConfigCompatError{What: "DPoS config presence", RewindTo: 0, Fatal: true}
	}
	if c.DPoS != nil && newcfg.DPoS != nil {
		if c.DPoS.Epoch != newcfg.DPoS.Epoch {
			return &ConfigCompatError{
				What:         "DPoS epoch",
				StoredConfig: new(big.Int).SetUint64(c.DPoS.Epoch),
				NewConfig:    new(big.Int).SetUint64(newcfg.DPoS.Epoch),
				RewindTo:     0,
				Fatal:        true,
			}
		}
		if c.DPoS.TargetBlockPeriodMs() != newcfg.DPoS.TargetBlockPeriodMs() {
			return &ConfigCompatError{
				What:         "DPoS periodMs",
				StoredConfig: new(big.Int).SetUint64(c.DPoS.TargetBlockPeriodMs()),
				NewConfig:    new(big.Int).SetUint64(newcfg.DPoS.TargetBlockPeriodMs()),
				RewindTo:     0,
				Fatal:        true,
			}
		}
		if c.DPoS.MaxValidators != newcfg.DPoS.MaxValidators {
			return &ConfigCompatError{
				What:         "DPoS maxValidators",
				StoredConfig: new(big.Int).SetUint64(c.DPoS.MaxValidators),
				NewConfig:    new(big.Int).SetUint64(newcfg.DPoS.MaxValidators),
				RewindTo:     0,
				Fatal:        true,
			}
		}
		if c.DPoS.MaintenanceMaxBlocksEffective() != newcfg.DPoS.MaintenanceMaxBlocksEffective() {
			return &ConfigCompatError{
				What:         "DPoS maintenanceMaxBlocks",
				StoredConfig: new(big.Int).SetUint64(c.DPoS.MaintenanceMaxBlocksEffective()),
				NewConfig:    new(big.Int).SetUint64(newcfg.DPoS.MaintenanceMaxBlocksEffective()),
				RewindTo:     0,
				Fatal:        true,
			}
		}
		if c.DPoS.TurnLength != newcfg.DPoS.TurnLength {
			return &ConfigCompatError{
				What:         "DPoS turnLength",
				StoredConfig: new(big.Int).SetUint64(c.DPoS.TurnLength),
				NewConfig:    new(big.Int).SetUint64(newcfg.DPoS.TurnLength),
				RewindTo:     0,
				Fatal:        true,
			}
		}
		storedSealType, storedErr := NormalizeDPoSSealSignerType(c.DPoS.SealSignerType)
		newSealType, newErr := NormalizeDPoSSealSignerType(newcfg.DPoS.SealSignerType)
		if storedErr != nil || newErr != nil || storedSealType != newSealType {
			return &ConfigCompatError{What: "DPoS sealSignerType", RewindTo: 0, Fatal: true}
		}
		storedInterval, storedActivation := normalizedCheckpointCompatibility(c.DPoS)
		newInterval, newActivation := normalizedCheckpointCompatibility(newcfg.DPoS)
		if storedInterval != newInterval {
			return &ConfigCompatError{
				What:         "DPoS checkpointInterval",
				StoredConfig: new(big.Int).SetUint64(storedInterval),
				NewConfig:    new(big.Int).SetUint64(newInterval),
				RewindTo:     0,
				Fatal:        true,
			}
		}
		if !configNumEqual(storedActivation, newActivation) {
			return &ConfigCompatError{
				What:         "DPoS checkpointFinalityBlock",
				StoredConfig: storedActivation,
				NewConfig:    newActivation,
				RewindTo:     0,
				Fatal:        true,
			}
		}
	}
	storedForks := appliedProtocolForks(c.ProtocolForks, head.Uint64())
	newForks := appliedProtocolForks(newcfg.ProtocolForks, head.Uint64())
	if storedFork, newFork := firstProtocolForkMismatch(storedForks, newForks); storedFork != nil || newFork != nil {
		return newCompatError("protocolForks", storedFork, newFork)
	}
	return nil
}

func appliedProtocolForks(forks []uint64, head uint64) []uint64 {
	var applied []uint64
	for _, fork := range forks {
		if fork > head {
			break
		}
		applied = append(applied, fork)
	}
	return applied
}

func firstProtocolForkMismatch(stored, updated []uint64) (*big.Int, *big.Int) {
	maxLen := len(stored)
	if len(updated) > maxLen {
		maxLen = len(updated)
	}
	for i := 0; i < maxLen; i++ {
		var storedFork, newFork *big.Int
		if i < len(stored) {
			storedFork = new(big.Int).SetUint64(stored[i])
		}
		if i < len(updated) {
			newFork = new(big.Int).SetUint64(updated[i])
		}
		switch {
		case storedFork == nil && newFork == nil:
			continue
		case storedFork == nil || newFork == nil:
			return storedFork, newFork
		case storedFork.Cmp(newFork) != 0:
			return storedFork, newFork
		}
	}
	return nil, nil
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
	// Fatal marks immutable consensus params (e.g. DPoS Epoch/PeriodMs) whose
	// mismatch must block node startup even when RewindTo == 0.
	Fatal bool
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
	err := &ConfigCompatError{what, storedblock, newblock, 0, false}
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
	ChainID *big.Int
	IsMerge bool
}

// Rules ensures c's ChainID is not nil.
func (c *ChainConfig) Rules(_ *big.Int, isMerge bool) Rules {
	chainID := c.ChainID
	if chainID == nil {
		chainID = new(big.Int)
	}
	return Rules{
		ChainID: new(big.Int).Set(chainID),
		IsMerge: isMerge,
	}
}
