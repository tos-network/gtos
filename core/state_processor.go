// Copyright 2015 The go-ethereum Authors
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

package core

import (
	"fmt"
	"math/big"

	"github.com/tos-network/gtos/common"
	cmath "github.com/tos-network/gtos/common/math"
	"github.com/tos-network/gtos/consensus"
	"github.com/tos-network/gtos/core/parallel"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/params"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the GTOS rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts types.Receipts
		allLogs  []*types.Log
		usedGas  = new(uint64)
		header   = block.Header()
		gp       = new(GasPool).AddGas(block.GasLimit())
	)
	blockCtx := NewTVMBlockContext(header, p.bc, nil)
	signer := types.MakeSigner(p.config, header.Number)

	// Build per-transaction messages upfront (needs statedb for sender resolution).
	txs := block.Transactions()
	msgs := make([]types.Message, len(txs))
	for i, tx := range txs {
		msg, err := txAsMessageWithAccountSigner(tx, signer, header.BaseFee, statedb)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		msgs[i] = msg
	}

	// applyMsgFn wraps ApplyMessage for the parallel executor.
	// Each call uses an independent per-tx gas pool seeded with msg.Gas(),
	// keeping per-tx gas accounting self-contained. Block-level gas is
	// accounted for serially by ExecuteParallel.
	applyMsgFn := func(bCtx vm.BlockContext, cfg *params.ChainConfig, msg types.Message, sdb vm.StateDB) (*parallel.TxResult, error) {
		perTxGP := new(GasPool).AddGas(msg.Gas())
		result, err := ApplyMessage(bCtx, cfg, msg, perTxGP, sdb)
		if err != nil {
			return nil, err
		}
		return &parallel.TxResult{UsedGas: result.UsedGas, VMErr: result.Err}, nil
	}

	var parallelErr error
	receipts, allLogs, *usedGas, parallelErr = parallel.ExecuteParallel(
		p.config, blockCtx, statedb, block, gp, msgs, applyMsgFn,
	)
	if parallelErr != nil {
		return nil, nil, 0, parallelErr
	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles())

	return receipts, allLogs, *usedGas, nil
}

func applyTransaction(msg types.Message, config *params.ChainConfig, blockCtx vm.BlockContext, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64) (*types.Receipt, error) {
	// Apply the transaction to the current state.
	result, err := ApplyMessage(blockCtx, config, msg, gp, statedb)
	if err != nil {
		return nil, err
	}

	// Update the state with pending changes.
	statedb.Finalise(true)
	var root []byte
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockHash)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, err
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64) (*types.Receipt, error) {
	msg, err := txAsMessageWithAccountSigner(tx, types.MakeSigner(config, header.Number), header.BaseFee, statedb)
	if err != nil {
		return nil, err
	}
	blockCtx := NewTVMBlockContext(header, bc, author)
	return applyTransaction(msg, config, blockCtx, gp, statedb, header.Number, header.Hash(), tx, usedGas)
}

func txAsMessageWithAccountSigner(tx *types.Transaction, signer types.Signer, baseFee *big.Int, statedb *state.StateDB) (types.Message, error) {
	txPrice := new(big.Int).Set(tx.TxPrice())
	gasFeeCap := new(big.Int).Set(tx.GasFeeCap())
	gasTipCap := new(big.Int).Set(tx.GasTipCap())
	if baseFee != nil {
		txPrice = cmath.BigMin(new(big.Int).Add(gasTipCap, baseFee), gasFeeCap)
	}
	from, err := ResolveSender(tx, signer, statedb)
	if err != nil {
		return types.Message{}, err
	}
	return types.NewMessage(
		from,
		tx.To(),
		tx.Nonce(),
		tx.Value(),
		tx.Gas(),
		txPrice,
		gasFeeCap,
		gasTipCap,
		tx.Data(),
		tx.AccessList(),
		false,
	), nil
}
