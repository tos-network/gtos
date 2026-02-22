package dpos

import (
	"sort"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/consensus"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/rpc"
)

// API exposes DPoS-specific RPC methods under the "dpos" namespace.
type API struct {
	chain consensus.ChainHeaderReader
	dpos  *DPoS
}

// ValidatorInfo is a validator status view at a snapshot/block.
type ValidatorInfo struct {
	Address            common.Address   `json:"address"`
	Active             bool             `json:"active"`
	Index              *hexutil.Uint    `json:"index,omitempty"`
	SnapshotBlock      hexutil.Uint64   `json:"snapshotBlock"`
	SnapshotHash       common.Hash      `json:"snapshotHash"`
	RecentSignedBlocks []hexutil.Uint64 `json:"recentSignedBlocks,omitempty"`
}

// EpochInfo describes epoch context for a specific block.
type EpochInfo struct {
	BlockNumber        hexutil.Uint64 `json:"blockNumber"`
	EpochLength        hexutil.Uint64 `json:"epochLength"`
	EpochIndex         hexutil.Uint64 `json:"epochIndex"`
	EpochStart         hexutil.Uint64 `json:"epochStart"`
	NextEpochStart     hexutil.Uint64 `json:"nextEpochStart"`
	BlocksUntilEpoch   hexutil.Uint64 `json:"blocksUntilEpoch"`
	TargetBlockPeriodS hexutil.Uint64 `json:"targetBlockPeriodS"`
	MaxValidators      hexutil.Uint64 `json:"maxValidators"`
	ValidatorCount     hexutil.Uint64 `json:"validatorCount"`
	SnapshotHash       common.Hash    `json:"snapshotHash"`
}

func (api *API) resolveHeader(number *rpc.BlockNumber) *types.Header {
	header := api.chain.CurrentHeader()
	if number != nil && number.Int64() >= 0 {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	return header
}

// GetSnapshot returns the validator snapshot at the requested block.
// If number is nil, the latest block is used.
func (api *API) GetSnapshot(number *rpc.BlockNumber) (*Snapshot, error) {
	header := api.resolveHeader(number)
	if header == nil {
		return nil, consensus.ErrUnknownAncestor
	}
	return api.dpos.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
}

// GetValidators returns the active validator addresses at the requested block.
// If number is nil, the latest block is used.
func (api *API) GetValidators(number *rpc.BlockNumber) ([]interface{}, error) {
	snap, err := api.GetSnapshot(number)
	if err != nil {
		return nil, err
	}
	validators := snap.validatorList()
	result := make([]interface{}, len(validators))
	for i, v := range validators {
		result[i] = v
	}
	return result, nil
}

// GetValidator returns validator status for an address at the requested block.
// If number is nil, latest block is used.
func (api *API) GetValidator(address common.Address, number *rpc.BlockNumber) (*ValidatorInfo, error) {
	header := api.resolveHeader(number)
	if header == nil {
		return nil, consensus.ErrUnknownAncestor
	}
	snap, err := api.dpos.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	validators := snap.validatorList()
	var (
		active bool
		index  *hexutil.Uint
	)
	for i, v := range validators {
		if v == address {
			active = true
			idx := hexutil.Uint(i)
			index = &idx
			break
		}
	}
	var recent []hexutil.Uint64
	for blockNum, signer := range snap.Recents {
		if signer == address {
			recent = append(recent, hexutil.Uint64(blockNum))
		}
	}
	sort.Slice(recent, func(i, j int) bool { return recent[i] < recent[j] })

	return &ValidatorInfo{
		Address:            address,
		Active:             active,
		Index:              index,
		SnapshotBlock:      hexutil.Uint64(snap.Number),
		SnapshotHash:       snap.Hash,
		RecentSignedBlocks: recent,
	}, nil
}

// GetEpochInfo returns epoch context at the requested block.
// If number is nil, latest block is used.
func (api *API) GetEpochInfo(number *rpc.BlockNumber) (*EpochInfo, error) {
	header := api.resolveHeader(number)
	if header == nil {
		return nil, consensus.ErrUnknownAncestor
	}
	snap, err := api.dpos.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}

	cfg := api.chain.Config().DPoS
	epoch := cfg.Epoch
	if epoch == 0 {
		epoch = 1
	}
	blockNum := header.Number.Uint64()
	epochIndex := blockNum / epoch
	epochStart := epochIndex * epoch
	nextEpochStart := epochStart + epoch

	return &EpochInfo{
		BlockNumber:        hexutil.Uint64(blockNum),
		EpochLength:        hexutil.Uint64(epoch),
		EpochIndex:         hexutil.Uint64(epochIndex),
		EpochStart:         hexutil.Uint64(epochStart),
		NextEpochStart:     hexutil.Uint64(nextEpochStart),
		BlocksUntilEpoch:   hexutil.Uint64(nextEpochStart - blockNum),
		TargetBlockPeriodS: hexutil.Uint64(cfg.Period),
		MaxValidators:      hexutil.Uint64(cfg.MaxValidators),
		ValidatorCount:     hexutil.Uint64(len(snap.Validators)),
		SnapshotHash:       snap.Hash,
	}, nil
}
