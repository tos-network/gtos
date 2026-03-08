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
	"context"
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
	"github.com/tos-network/gtos/task"
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
	blockCtx := NewVMBlockContext(header, p.bc, nil)
	signer := types.MakeSigner(p.config, header.Number)

	// Build per-transaction messages upfront using the pre-block statedb snapshot.
	// Sender resolution uses the signer state at block START (before any tx executes),
	// which is the consensus-defined semantic: if ACCOUNT_SET_SIGNER changes an
	// account's signer mid-block, subsequent txs in the same block still resolve
	// to the old signer.  chain_makers.AddTxWithChain was aligned to this same
	// pre-block-state semantics (see BlockGen.initStatedb).
	txs := block.Transactions()
	msgs := make([]types.Message, len(txs))
	for i, tx := range txs {
		msg, err := TxAsMessageWithAccountSigner(tx, signer, header.BaseFee, statedb)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		msgs[i] = msg
	}

	scheduledGas, err := RunScheduledTasks(statedb, blockCtx, p.config, header.Number.Uint64(), gp)
	if err != nil {
		return nil, nil, 0, err
	}

	receipts, allLogs, txGas, err := ExecuteTransactions(
		p.config, blockCtx, statedb, txs, block.Hash(), header.Number, gp, msgs,
	)
	if err != nil {
		return nil, nil, 0, err
	}
	// NOTE: Scheduled task gas is added to block.GasUsed (via *usedGas) and
	// shifted into each receipt's CumulativeGasUsed, but no dedicated receipt
	// is emitted for the scheduled work itself. Block explorers that sum
	// per-receipt gas will therefore undercount by scheduledGas. This is an
	// accepted gap — scheduled tasks are consensus-internal and have no
	// originating transaction to attach a receipt to.
	if scheduledGas != 0 {
		for _, receipt := range receipts {
			receipt.CumulativeGasUsed += scheduledGas
		}
	}
	*usedGas = scheduledGas + txGas

	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles())

	// For engines that implement FinalizedStateVerifier (e.g. DPoS), verify
	// engine-specific post-tx invariants — such as epoch validator list integrity.
	// Uses the consensus package interface rather than a local ad-hoc interface,
	// aligned with go-ethereum's optional-capability engine extension pattern.
	if fsv, ok := p.engine.(consensus.FinalizedStateVerifier); ok {
		if err := fsv.VerifyFinalizedState(header, statedb); err != nil {
			return nil, nil, 0, err
		}
	}

	return receipts, allLogs, *usedGas, nil
}

// ExecuteTransactions runs txs against statedb using the parallel executor with
// the standard per-tx gas pool accounting.  It is the single entry point for
// all tx execution in GTOS (validation, mining, and test chain generation).
func ExecuteTransactions(
	config *params.ChainConfig,
	blockCtx vm.BlockContext,
	statedb *state.StateDB,
	txs types.Transactions,
	blockHash common.Hash,
	blockNumber *big.Int,
	gp *GasPool,
	msgs []types.Message,
) (types.Receipts, []*types.Log, uint64, error) {
	applyMsgFn := func(bCtx vm.BlockContext, cfg *params.ChainConfig, msg types.Message, sdb vm.StateDB) (*parallel.TxResult, error) {
		perTxGP := new(GasPool).AddGas(msg.Gas())
		result, err := ApplyMessage(context.Background(), bCtx, cfg, msg, perTxGP, sdb)
		if err != nil {
			return nil, err
		}
		return &parallel.TxResult{UsedGas: result.UsedGas, VMErr: result.Err}, nil
	}
	return parallel.ExecuteParallel(config, blockCtx, statedb, txs, blockHash, blockNumber, gp, msgs, applyMsgFn)
}

// RunScheduledTasks executes all tasks due at blockNum against statedb.
// Called by both Process() (block validation) and the miner (block building)
// before user transactions are applied, so the resulting state root is identical
// in both paths.
func RunScheduledTasks(statedb *state.StateDB, blockCtx vm.BlockContext, chainCfg *params.ChainConfig, blockNum uint64, gp *GasPool) (uint64, error) {
	_, gasUsed, err := task.ProcessDueTasks(statedb, blockCtx, chainCfg, blockNum,
		func(db vm.StateDB, bCtx vm.BlockContext, cfg *params.ChainConfig,
			caller, target common.Address, calldata []byte, gasLimit uint64,
		) task.ExecResult {
			if gp != nil && gasLimit > gp.Gas() {
				return task.ExecResult{Err: ErrGasLimitReached, Fatal: true}
			}
			ctx := vm.CallCtx{From: caller, To: target, Data: calldata}
			code := db.GetCode(target)
			gasUsed, _, _, err := vm.Execute(db, bCtx, cfg, ctx, code, gasLimit)
			if gp != nil {
				if gasUsed > gasLimit {
					gasUsed = gasLimit
				}
				if err := gp.SubGas(gasUsed); err != nil {
					return task.ExecResult{GasUsed: gasUsed, Err: ErrGasLimitReached, Fatal: true}
				}
			}
			return task.ExecResult{GasUsed: gasUsed, Err: err}
		})
	return gasUsed, err
}

// TxAsMessageWithAccountSigner converts a transaction to a Message using the
// account-based signer (resolves sender from state for SignerTx types).
func TxAsMessageWithAccountSigner(tx *types.Transaction, signer types.Signer, baseFee *big.Int, statedb *state.StateDB) (types.Message, error) {
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
