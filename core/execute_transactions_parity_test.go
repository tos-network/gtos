package core

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/priv"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
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
		types.NewMessage(senderA, &recv1, 0, big.NewInt(100), params.TxGas, params.TxPrice(), params.TxPrice(), params.TxPrice(), nil, nil, true),
		types.NewMessage(senderA, &recv2, 1, big.NewInt(200), params.TxGas, params.TxPrice(), params.TxPrice(), params.TxPrice(), nil, nil, true),
		types.NewMessage(senderB, &recv3, 0, big.NewInt(300), params.TxGas, params.TxPrice(), params.TxPrice(), params.TxPrice(), nil, nil, true),
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

func TestExecuteTransactionsMixedPrivacyAndPublicParity(t *testing.T) {
	makeState := func() *state.StateDB {
		db, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		if err != nil {
			t.Fatalf("state.New: %v", err)
		}
		return db
	}
	makePublicTx := func(nonce uint64, from, to common.Address, value int64) (*types.Transaction, types.Message) {
		tx := types.NewTx(&types.SignerTx{
			ChainID: big.NewInt(1),
			Nonce:   nonce,
			To:      &to,
			Gas:     params.TxGas,
			Value:   big.NewInt(value),
			V:       new(big.Int),
			R:       new(big.Int),
			S:       new(big.Int),
		})
		msg := types.NewMessage(from, &to, nonce, big.NewInt(value), params.TxGas, params.TxPrice(), params.TxPrice(), params.TxPrice(), nil, nil, true)
		return tx, msg
	}

	config := &params.ChainConfig{ChainID: big.NewInt(1)}
	coinbase := common.HexToAddress("0xCAFE")
	publicSender := common.HexToAddress("0x1234")
	publicRecipient := common.HexToAddress("0x5678")

	senderPub, senderPriv := mustPoolElgamalKeypair(t)
	receiverPub, _ := mustPoolElgamalKeypair(t)
	senderAddr := common.BytesToAddress(crypto.Keccak256(senderPub[:]))
	senderBalance := uint64(900)
	fee := priv.EstimateRequiredFee(0)
	amount0 := uint64(120)
	amount1 := uint64(140)

	baseState := makeState()
	baseState.AddBalance(publicSender, new(big.Int).SetUint64(5_000_000_000_000_000_000))
	priv.SetAccountState(baseState, senderAddr, priv.AccountState{
		Ciphertext: mustEncryptPrivBalance(t, senderPub, senderBalance),
	})
	baseState.Finalise(false)

	tx0 := mustMakePrivTransferTx(t, config.ChainID, senderPub, senderPriv, receiverPub, 0, fee, fee, amount0, senderBalance, priv.GetAccountState(baseState, senderAddr).Ciphertext)
	publicTx, publicMsg := makePublicTx(0, publicSender, publicRecipient, 77)
	balanceAfterTx0 := senderBalance - amount0 - fee
	stateAfterTx0 := baseState.Copy()
	prepared0, err := preparePrivacyTxState(config.ChainID, stateAfterTx0, tx0)
	if err != nil {
		t.Fatalf("preparePrivacyTxState(tx0): %v", err)
	}
	if _, err := prepared0.ApplyState(stateAfterTx0); err != nil {
		t.Fatalf("ApplyState(tx0): %v", err)
	}
	tx1 := mustMakePrivTransferTx(t, config.ChainID, senderPub, senderPriv, receiverPub, 1, fee, fee, amount1, balanceAfterTx0, priv.GetAccountState(stateAfterTx0, senderAddr).Ciphertext)

	txs := types.Transactions{tx0, publicTx, tx1}
	msgs := []types.Message{
		makePrivTransferMsg(senderPub, receiverPub, tx0.PrivTransferInner(), 0),
		publicMsg,
		makePrivTransferMsg(senderPub, receiverPub, tx1.PrivTransferInner(), 0),
	}
	blockHash := common.HexToHash("0x1111")
	blockNumber := big.NewInt(5)
	blockCtx := vm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		Coinbase:    coinbase,
		BlockNumber: blockNumber,
		GasLimit:    10_000_000,
		BaseFee:     big.NewInt(1),
	}

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

	dbSingle := baseState.Copy()
	gpSingle := new(GasPool).AddGas(10_000_000)
	var (
		singleReceipts types.Receipts
		singleUsedGas  uint64
	)
	for i := range txs {
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
		if batchReceipts[i].Status != singleReceipts[i].Status {
			t.Fatalf("receipt[%d] status mismatch: batch=%d single=%d", i, batchReceipts[i].Status, singleReceipts[i].Status)
		}
		if batchReceipts[i].CumulativeGasUsed != singleReceipts[i].CumulativeGasUsed {
			t.Fatalf("receipt[%d] cumulative gas mismatch: batch=%d single=%d", i, batchReceipts[i].CumulativeGasUsed, singleReceipts[i].CumulativeGasUsed)
		}
	}
}

func TestExecuteTransactionsPrivacyBatchFallbackParity(t *testing.T) {
	makeState := func() *state.StateDB {
		db, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		if err != nil {
			t.Fatalf("state.New: %v", err)
		}
		return db
	}
	makePublicTx := func(nonce uint64, from, to common.Address, value int64) (*types.Transaction, types.Message) {
		tx := types.NewTx(&types.SignerTx{
			ChainID: big.NewInt(1),
			Nonce:   nonce,
			To:      &to,
			Gas:     params.TxGas,
			Value:   big.NewInt(value),
			V:       new(big.Int),
			R:       new(big.Int),
			S:       new(big.Int),
		})
		msg := types.NewMessage(from, &to, nonce, big.NewInt(value), params.TxGas, params.TxPrice(), params.TxPrice(), params.TxPrice(), nil, nil, true)
		return tx, msg
	}

	config := &params.ChainConfig{ChainID: big.NewInt(1)}
	coinbase := common.HexToAddress("0xCAFE")
	publicSender := common.HexToAddress("0x9999")
	publicRecipient := common.HexToAddress("0xAAAA")

	senderPub, senderPriv := mustPoolElgamalKeypair(t)
	receiverPub, _ := mustPoolElgamalKeypair(t)
	senderAddr := common.BytesToAddress(crypto.Keccak256(senderPub[:]))
	startBalance := uint64(1200)
	fee := priv.EstimateRequiredFee(0)
	amount0 := uint64(130)
	amount1 := uint64(150)
	amount2 := uint64(160)

	baseState := makeState()
	baseState.AddBalance(publicSender, new(big.Int).SetUint64(5_000_000_000_000_000_000))
	baseState.AddBalance(coinbase, big.NewInt(0))
	priv.SetAccountState(baseState, senderAddr, priv.AccountState{
		Ciphertext: mustEncryptPrivBalance(t, senderPub, startBalance),
	})
	baseState.Finalise(false)

	senderCt0 := priv.GetAccountState(baseState, senderAddr).Ciphertext
	tx0 := mustMakePrivTransferTx(t, config.ChainID, senderPub, senderPriv, receiverPub, 0, fee, fee, amount0, startBalance, senderCt0)

	stateAfterTx0 := baseState.Copy()
	prepared0, err := preparePrivacyTxState(config.ChainID, stateAfterTx0, tx0)
	if err != nil {
		t.Fatalf("preparePrivacyTxState(tx0): %v", err)
	}
	if _, err := prepared0.ApplyState(stateAfterTx0); err != nil {
		t.Fatalf("ApplyState(tx0): %v", err)
	}
	balance1 := startBalance - amount0 - fee
	senderCt1 := priv.GetAccountState(stateAfterTx0, senderAddr).Ciphertext
	validTx1 := mustMakePrivTransferTx(t, config.ChainID, senderPub, senderPriv, receiverPub, 1, fee, fee, amount1, balance1, senderCt1)

	stateAfterTx1 := stateAfterTx0.Copy()
	prepared1, err := preparePrivacyTxState(config.ChainID, stateAfterTx1, validTx1)
	if err != nil {
		t.Fatalf("preparePrivacyTxState(validTx1): %v", err)
	}
	if _, err := prepared1.ApplyState(stateAfterTx1); err != nil {
		t.Fatalf("ApplyState(validTx1): %v", err)
	}
	balance2 := balance1 - amount1 - fee
	senderCt2 := priv.GetAccountState(stateAfterTx1, senderAddr).Ciphertext
	tx2 := mustMakePrivTransferTx(t, config.ChainID, senderPub, senderPriv, receiverPub, 2, fee, fee, amount2, balance2, senderCt2)

	badTx1 := types.NewTx(validTx1.PrivTransferInner())
	badInner := badTx1.PrivTransferInner()
	badInner.CommitmentEqProof[0] ^= 0x80

	publicTx, publicMsg := makePublicTx(0, publicSender, publicRecipient, 33)

	txs := types.Transactions{tx0, badTx1, tx2, publicTx}
	msgs := []types.Message{
		makePrivTransferMsg(senderPub, receiverPub, tx0.PrivTransferInner(), 0),
		makePrivTransferMsg(senderPub, receiverPub, badTx1.PrivTransferInner(), 0),
		makePrivTransferMsg(senderPub, receiverPub, tx2.PrivTransferInner(), 0),
		publicMsg,
	}
	blockHash := common.HexToHash("0x2222")
	blockNumber := big.NewInt(7)
	blockCtx := vm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		Coinbase:    coinbase,
		BlockNumber: blockNumber,
		GasLimit:    10_000_000,
		BaseFee:     big.NewInt(1),
	}

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

	dbSingle := baseState.Copy()
	gpSingle := new(GasPool).AddGas(10_000_000)
	var (
		singleReceipts types.Receipts
		singleUsedGas  uint64
	)
	for i := range txs {
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
		if batchReceipts[i].Status != singleReceipts[i].Status {
			t.Fatalf("receipt[%d] status mismatch: batch=%d single=%d", i, batchReceipts[i].Status, singleReceipts[i].Status)
		}
		if batchReceipts[i].CumulativeGasUsed != singleReceipts[i].CumulativeGasUsed {
			t.Fatalf("receipt[%d] cumulative gas mismatch: batch=%d single=%d", i, batchReceipts[i].CumulativeGasUsed, singleReceipts[i].CumulativeGasUsed)
		}
	}
	if batchReceipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("tx0 status = %d, want success", batchReceipts[0].Status)
	}
	if batchReceipts[1].Status != types.ReceiptStatusFailed {
		t.Fatalf("tx1 status = %d, want failed", batchReceipts[1].Status)
	}
	if batchReceipts[2].Status != types.ReceiptStatusFailed {
		t.Fatalf("tx2 status = %d, want failed", batchReceipts[2].Status)
	}
	if batchReceipts[3].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("tx3 status = %d, want success", batchReceipts[3].Status)
	}
}
