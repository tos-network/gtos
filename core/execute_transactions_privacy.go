package core

import (
	"context"
	"fmt"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

type executionPrivacyCandidate struct {
	index    int
	tx       *types.Transaction
	from     common.Address
	prepared preparedPrivacyTx
}

func hasPrivacyTransactions(txs types.Transactions) bool {
	for _, tx := range txs {
		if isPrivacyTxType(tx.Type()) {
			return true
		}
	}
	return false
}

func isPrivacyTxType(txType uint8) bool {
	return txType == types.PrivTransferTxType || txType == types.ShieldTxType || txType == types.UnshieldTxType
}

func executeTransactionsSerial(
	config *params.ChainConfig,
	blockCtx vm.BlockContext,
	statedb *state.StateDB,
	txs types.Transactions,
	blockHash common.Hash,
	blockNumber *big.Int,
	gp *GasPool,
	msgs []types.Message,
) (types.Receipts, []*types.Log, uint64, error) {
	receiptsByTx := make(types.Receipts, len(txs))
	var (
		allLogs           []*types.Log
		totalGas          uint64
		cumulativeGasUsed uint64
		pending           []executionPrivacyCandidate
		pendingState      *state.StateDB
	)

	flushPrivacyBatch := func() error {
		if len(pending) == 0 {
			return nil
		}
		batchPrepared := make([]preparedPrivacyTx, 0, len(pending))
		for _, candidate := range pending {
			batchPrepared = append(batchPrepared, candidate.prepared)
		}

		fallbackFrom := len(pending)
		if err := verifyPreparedPrivacyBatch(batchPrepared); err == nil {
			for idx, candidate := range pending {
				if err := applyPreparedPrivacyExecution(candidate.prepared, statedb, blockCtx.Coinbase); err != nil {
					fallbackFrom = idx
					break
				}
				receiptsByTx[candidate.index] = privacyExecutionSuccess(
					candidate.tx,
					candidate.index,
					blockHash,
					blockNumber,
					cumulativeGasUsed,
					candidate.from,
				)
			}
		} else {
			fallbackFrom = 0
		}

		for _, candidate := range pending[fallbackFrom:] {
			statedb.Prepare(candidate.tx.Hash(), candidate.index)
			prepared, err := preparePrivacyTxState(config.ChainID, statedb, candidate.tx)
			if err == nil {
				err = prepared.VerifyProofs()
			}
			if err == nil {
				err = applyPreparedPrivacyExecution(prepared, statedb, blockCtx.Coinbase)
			}
			if err == nil {
				receiptsByTx[candidate.index] = privacyExecutionSuccess(
					candidate.tx,
					candidate.index,
					blockHash,
					blockNumber,
					cumulativeGasUsed,
					candidate.from,
				)
				continue
			}
			receiptsByTx[candidate.index] = privacyExecutionFailure(
				candidate.tx,
				candidate.index,
				blockHash,
				blockNumber,
				cumulativeGasUsed,
				candidate.from,
			)
		}

		pending = nil
		pendingState = nil
		return nil
	}

	for i, tx := range txs {
		if isPrivacyTxType(tx.Type()) {
			if pendingState == nil {
				pendingState = statedb.Copy()
			}
			prepared, err := preparePrivacyTxState(config.ChainID, pendingState, tx)
			if err != nil {
				if err := flushPrivacyBatch(); err != nil {
					return nil, nil, 0, err
				}
				receiptsByTx[i] = executeSinglePrivacyTx(
					config.ChainID,
					statedb,
					tx,
					msgs[i].From(),
					blockCtx.Coinbase,
					i,
					blockHash,
					blockNumber,
					cumulativeGasUsed,
				)
				continue
			}
			snap := pendingState.Snapshot()
			feeWei, err := prepared.ApplyState(pendingState)
			if err != nil {
				pendingState.RevertToSnapshot(snap)
				if err := flushPrivacyBatch(); err != nil {
					return nil, nil, 0, err
				}
				receiptsByTx[i] = executeSinglePrivacyTx(
					config.ChainID,
					statedb,
					tx,
					msgs[i].From(),
					blockCtx.Coinbase,
					i,
					blockHash,
					blockNumber,
					cumulativeGasUsed,
				)
				continue
			}
			if feeWei > 0 {
				pendingState.AddBalance(blockCtx.Coinbase, new(big.Int).SetUint64(feeWei))
			}
			pendingState.Finalise(true)
			pending = append(pending, executionPrivacyCandidate{
				index:    i,
				tx:       tx,
				from:     msgs[i].From(),
				prepared: prepared,
			})
			continue
		}

		if err := flushPrivacyBatch(); err != nil {
			return nil, nil, 0, err
		}

		statedb.Prepare(tx.Hash(), i)
		result, err := publicExecutionResult(config, blockCtx, statedb, msgs[i], gp)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		txLogs, nextAllLogs := txExecutionLogs(statedb, tx.Hash(), blockHash, blockNumber.Uint64(), allLogs)
		allLogs = nextAllLogs
		totalGas += result.UsedGas
		cumulativeGasUsed += result.UsedGas
		if result.Failed() {
			receiptsByTx[i] = publicExecutionFailure(
				tx,
				i,
				blockHash,
				blockNumber,
				result.UsedGas,
				cumulativeGasUsed,
				txLogs,
				msgs[i].From(),
			)
			continue
		}
		receiptsByTx[i] = publicExecutionSuccess(
			tx,
			i,
			blockHash,
			blockNumber,
			result.UsedGas,
			cumulativeGasUsed,
			txLogs,
			msgs[i].From(),
		)
	}

	if err := flushPrivacyBatch(); err != nil {
		return nil, nil, 0, err
	}
	return receiptsByTx, allLogs, totalGas, nil
}

func applyPreparedPrivacyExecution(prepared preparedPrivacyTx, statedb *state.StateDB, coinbase common.Address) error {
	snap := statedb.Snapshot()
	feeWei, err := prepared.ApplyState(statedb)
	if err != nil {
		statedb.RevertToSnapshot(snap)
		return err
	}
	if feeWei > 0 {
		statedb.AddBalance(coinbase, new(big.Int).SetUint64(feeWei))
	}
	statedb.Finalise(true)
	return nil
}

func executeSinglePrivacyTx(
	chainID *big.Int,
	statedb *state.StateDB,
	tx *types.Transaction,
	from common.Address,
	coinbase common.Address,
	txIndex int,
	blockHash common.Hash,
	blockNumber *big.Int,
	cumulativeGasUsed uint64,
) *types.Receipt {
	statedb.Prepare(tx.Hash(), txIndex)
	prepared, err := preparePrivacyTxState(chainID, statedb, tx)
	if err == nil {
		err = prepared.VerifyProofs()
	}
	if err == nil {
		err = applyPreparedPrivacyExecution(prepared, statedb, coinbase)
	}
	if err != nil {
		return privacyExecutionFailure(tx, txIndex, blockHash, blockNumber, cumulativeGasUsed, from)
	}
	return privacyExecutionSuccess(tx, txIndex, blockHash, blockNumber, cumulativeGasUsed, from)
}

func publicExecutionResult(
	config *params.ChainConfig,
	blockCtx vm.BlockContext,
	statedb *state.StateDB,
	msg types.Message,
	gp *GasPool,
) (*ExecutionResult, error) {
	perTxGP := new(GasPool).AddGas(msg.Gas())
	result, err := ApplyMessage(context.Background(), blockCtx, config, msg, perTxGP, statedb)
	if err != nil {
		return nil, err
	}
	if msg.Gas() > gp.Gas() {
		return nil, ErrGasLimitReached
	}
	if err := gp.SubGas(result.UsedGas); err != nil {
		return nil, ErrGasLimitReached
	}
	statedb.Finalise(true)
	return result, nil
}

func txExecutionLogs(statedb *state.StateDB, txHash, blockHash common.Hash, blockNumber uint64, allLogs []*types.Log) ([]*types.Log, []*types.Log) {
	var txLogs []*types.Log
	for _, l := range statedb.GetLogs(txHash, blockHash) {
		lCopy := *l
		lCopy.BlockHash = blockHash
		lCopy.BlockNumber = blockNumber
		lCopy.Index = uint(len(allLogs))
		txLogs = append(txLogs, &lCopy)
		allLogs = append(allLogs, &lCopy)
	}
	return txLogs, allLogs
}

func txReceipt(tx *types.Transaction, txIndex int, blockHash common.Hash, blockNumber *big.Int, gasUsed, cumulativeGasUsed uint64, status uint64, txLogs []*types.Log, from common.Address) *types.Receipt {
	receipt := &types.Receipt{
		Type:              tx.Type(),
		Status:            status,
		CumulativeGasUsed: cumulativeGasUsed,
		TxHash:            tx.Hash(),
		GasUsed:           gasUsed,
		BlockHash:         blockHash,
		BlockNumber:       blockNumber,
		TransactionIndex:  uint(txIndex),
		Logs:              txLogs,
	}
	if tx.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(from, tx.Nonce())
	}
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	return receipt
}

func privacyExecutionFailure(tx *types.Transaction, txIndex int, blockHash common.Hash, blockNumber *big.Int, cumulativeGasUsed uint64, from common.Address) *types.Receipt {
	return txReceipt(tx, txIndex, blockHash, blockNumber, 0, cumulativeGasUsed, types.ReceiptStatusFailed, nil, from)
}

func publicExecutionFailure(tx *types.Transaction, txIndex int, blockHash common.Hash, blockNumber *big.Int, gasUsed, cumulativeGasUsed uint64, txLogs []*types.Log, from common.Address) *types.Receipt {
	return txReceipt(tx, txIndex, blockHash, blockNumber, gasUsed, cumulativeGasUsed, types.ReceiptStatusFailed, txLogs, from)
}

func publicExecutionSuccess(tx *types.Transaction, txIndex int, blockHash common.Hash, blockNumber *big.Int, gasUsed, cumulativeGasUsed uint64, txLogs []*types.Log, from common.Address) *types.Receipt {
	return txReceipt(tx, txIndex, blockHash, blockNumber, gasUsed, cumulativeGasUsed, types.ReceiptStatusSuccessful, txLogs, from)
}

func privacyExecutionSuccess(tx *types.Transaction, txIndex int, blockHash common.Hash, blockNumber *big.Int, cumulativeGasUsed uint64, from common.Address) *types.Receipt {
	return txReceipt(tx, txIndex, blockHash, blockNumber, 0, cumulativeGasUsed, types.ReceiptStatusSuccessful, nil, from)
}
