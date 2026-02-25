package core

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/params"
)

func TestExecuteTransactionsBatchVsPerTxParity(t *testing.T) {
	makeState := func() *state.StateDB {
		db, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		if err != nil {
			t.Fatalf("state.New: %v", err)
		}
		return db
	}
	makeTx := func(nonce uint64, to common.Address) *types.Transaction {
		return types.NewTx(&types.SignerTx{
			ChainID: big.NewInt(1),
			Nonce:   nonce,
			To:      &to,
			Gas:     params.TxGas,
			Value:   big.NewInt(0),
			V:       new(big.Int),
			R:       new(big.Int),
			S:       new(big.Int),
		})
	}

	config := &params.ChainConfig{ChainID: big.NewInt(1)}
	coinbase := common.HexToAddress("0xCAFE")
	senderA := common.HexToAddress("0xAA01")
	senderB := common.HexToAddress("0xAA02")
	recv1 := common.HexToAddress("0xBB01")
	recv2 := common.HexToAddress("0xBB02")
	recv3 := common.HexToAddress("0xBB03")

	baseState := makeState()
	huge := new(big.Int)
	huge.SetString("1000000000000000000", 10)
	baseState.AddBalance(senderA, huge)
	baseState.AddBalance(senderB, huge)
	baseState.Finalise(false)

	msgs := []types.Message{
		types.NewMessage(senderA, &recv1, 0, big.NewInt(100), params.TxGas, params.GTOSPrice(), params.GTOSPrice(), params.GTOSPrice(), nil, nil, true),
		types.NewMessage(senderA, &recv2, 1, big.NewInt(200), params.TxGas, params.GTOSPrice(), params.GTOSPrice(), params.GTOSPrice(), nil, nil, true),
		types.NewMessage(senderB, &recv3, 0, big.NewInt(300), params.TxGas, params.GTOSPrice(), params.GTOSPrice(), params.GTOSPrice(), nil, nil, true),
	}
	txs := types.Transactions{
		makeTx(0, recv1),
		makeTx(1, recv2),
		makeTx(2, recv3),
	}
	blockHash := common.HexToHash("0x1234")
	blockNumber := big.NewInt(1)
	blockCtx := vm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		Coinbase:    coinbase,
		BlockNumber: blockNumber,
		GasLimit:    10_000_000,
		BaseFee:     big.NewInt(1),
	}

	// Batch path: one ExecuteTransactions call for the whole block.
	dbBatch := baseState.Copy()
	gpBatch := new(GasPool).AddGas(10_000_000)
	batchReceipts, _, batchUsedGas, err := ExecuteTransactions(
		config, blockCtx, dbBatch, txs, blockHash, blockNumber, gpBatch, msgs,
	)
	if err != nil {
		t.Fatalf("batch execute: %v", err)
	}
	batchRoot, err := dbBatch.Commit(false)
	if err != nil {
		t.Fatalf("batch commit: %v", err)
	}

	// Per-tx path: simulate chain_maker style loop (single tx each call).
	dbSingle := baseState.Copy()
	gpSingle := new(GasPool).AddGas(10_000_000)
	var (
		singleReceipts types.Receipts
		singleUsedGas  uint64
	)
	for i := 0; i < len(txs); i++ {
		rs, _, used, execErr := ExecuteTransactions(
			config, blockCtx, dbSingle,
			types.Transactions{txs[i]}, blockHash, blockNumber, gpSingle, []types.Message{msgs[i]},
		)
		if execErr != nil {
			t.Fatalf("single execute tx %d: %v", i, execErr)
		}
		rs[0].CumulativeGasUsed += singleUsedGas
		singleReceipts = append(singleReceipts, rs[0])
		singleUsedGas += used
	}
	singleRoot, err := dbSingle.Commit(false)
	if err != nil {
		t.Fatalf("single commit: %v", err)
	}

	if batchRoot != singleRoot {
		t.Fatalf("state root mismatch: batch=%s single=%s", batchRoot.Hex(), singleRoot.Hex())
	}
	if batchUsedGas != singleUsedGas {
		t.Fatalf("used gas mismatch: batch=%d single=%d", batchUsedGas, singleUsedGas)
	}
	if len(batchReceipts) != len(singleReceipts) {
		t.Fatalf("receipt len mismatch: batch=%d single=%d", len(batchReceipts), len(singleReceipts))
	}
	for i := range batchReceipts {
		br, sr := batchReceipts[i], singleReceipts[i]
		if br.TxHash != sr.TxHash {
			t.Fatalf("receipt[%d] tx hash mismatch: batch=%s single=%s", i, br.TxHash, sr.TxHash)
		}
		if br.CumulativeGasUsed != sr.CumulativeGasUsed {
			t.Fatalf("receipt[%d] cumulative gas mismatch: batch=%d single=%d", i, br.CumulativeGasUsed, sr.CumulativeGasUsed)
		}
		if br.GasUsed != sr.GasUsed {
			t.Fatalf("receipt[%d] gas used mismatch: batch=%d single=%d", i, br.GasUsed, sr.GasUsed)
		}
		if br.Status != sr.Status {
			t.Fatalf("receipt[%d] status mismatch: batch=%d single=%d", i, br.Status, sr.Status)
		}
	}
}
