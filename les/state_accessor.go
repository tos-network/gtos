// Copyright 2021 The go-ethereum Authors
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

package les

import (
	"context"
	"errors"
	"fmt"

	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/light"
)

// stateAtBlock retrieves the state database associated with a certain block.
func (leth *LightEthereum) stateAtBlock(ctx context.Context, block *types.Block, reexec uint64) (*state.StateDB, error) {
	return light.NewState(ctx, block.Header(), leth.odr), nil
}

// stateAtTransaction returns the message and state at the start of a given transaction.
func (leth *LightEthereum) stateAtTransaction(ctx context.Context, block *types.Block, txIndex int, reexec uint64) (core.Message, *state.StateDB, error) {
	// Short circuit if it's genesis block.
	if block.NumberU64() == 0 {
		return nil, nil, errors.New("no transaction in genesis")
	}
	// Create the parent state database
	parent, err := leth.blockchain.GetBlock(ctx, block.ParentHash(), block.NumberU64()-1)
	if err != nil {
		return nil, nil, err
	}
	statedb, err := leth.stateAtBlock(ctx, parent, reexec)
	if err != nil {
		return nil, nil, err
	}
	if txIndex == 0 && len(block.Transactions()) == 0 {
		return nil, statedb, nil
	}
	// Recompute transactions up to the target index.
	signer := types.MakeSigner(leth.blockchain.Config(), block.Number())
	blockCtx := core.NewEVMBlockContext(block.Header(), leth.blockchain, nil)
	for idx, tx := range block.Transactions() {
		msg, _ := tx.AsMessage(signer, block.BaseFee())
		statedb.Prepare(tx.Hash(), idx)
		if idx == txIndex {
			return msg, statedb, nil
		}
		// Not yet the searched for transaction, execute on top of the current state
		if _, err := core.ApplyMessage(blockCtx, leth.blockchain.Config(), msg, new(core.GasPool).AddGas(tx.Gas()), statedb); err != nil {
			return nil, nil, fmt.Errorf("transaction %#x failed: %v", tx.Hash(), err)
		}
		// Ensure any modifications are committed to the state
		statedb.Finalise(leth.blockchain.Config().IsEIP158(block.Number()))
	}
	return nil, nil, fmt.Errorf("transaction index %d out of range for block %#x", txIndex, block.Hash())
}
