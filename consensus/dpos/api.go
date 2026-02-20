package dpos

import (
	"github.com/tos-network/gtos/consensus"
	"github.com/tos-network/gtos/rpc"
)

// API exposes DPoS-specific RPC methods under the "dpos" namespace.
type API struct {
	chain consensus.ChainHeaderReader
	dpos  *DPoS
}

// GetSnapshot returns the validator snapshot at the requested block.
// If number is nil, the latest block is used.
func (api *API) GetSnapshot(number *rpc.BlockNumber) (*Snapshot, error) {
	var header = api.chain.CurrentHeader()
	if number != nil && *number != rpc.LatestBlockNumber {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
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
