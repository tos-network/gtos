package core

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/uno"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto/ristretto255"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
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

func TestExecuteTransactionsBatchVsPerTxParityWithUNO(t *testing.T) {
	makeState := func() *state.StateDB {
		db, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		if err != nil {
			t.Fatalf("state.New: %v", err)
		}
		return db
	}
	makeSignerTx := func(nonce uint64, to common.Address, gas uint64, data []byte) *types.Transaction {
		return types.NewTx(&types.SignerTx{
			ChainID: big.NewInt(1),
			Nonce:   nonce,
			To:      &to,
			Gas:     gas,
			Value:   big.NewInt(0),
			Data:    common.CopyBytes(data),
			V:       new(big.Int),
			R:       new(big.Int),
			S:       new(big.Int),
		})
	}
	makeUNOWire := func(amount uint64, seed byte) []byte {
		var ct uno.Ciphertext
		for i := 0; i < uno.CiphertextSize; i++ {
			ct.Commitment[i] = seed + byte(i)
			ct.Handle[i] = seed + 0x20 + byte(i)
		}
		body, err := uno.EncodeShieldPayload(uno.ShieldPayload{
			Amount:      amount,
			NewSender:   ct,
			ProofBundle: make([]byte, uno.ShieldProofSize),
		})
		if err != nil {
			t.Fatalf("EncodeShieldPayload: %v", err)
		}
		wire, err := uno.EncodeEnvelope(uno.ActionShield, body)
		if err != nil {
			t.Fatalf("EncodeEnvelope: %v", err)
		}
		return wire
	}

	config := &params.ChainConfig{ChainID: big.NewInt(1)}
	coinbase := common.HexToAddress("0xCAFE")
	unoSender1 := common.HexToAddress("0xAA11")
	unoSender2 := common.HexToAddress("0xAA12")
	plainSender := common.HexToAddress("0xAA13")
	plainRecv := common.HexToAddress("0xBB13")

	baseState := makeState()
	huge := new(big.Int)
	huge.SetString("1000000000000000000", 10)
	baseState.AddBalance(unoSender1, huge)
	baseState.AddBalance(unoSender2, huge)
	baseState.AddBalance(plainSender, huge)
	pub1 := ristretto255.NewGeneratorElement().Bytes()
	pub2 := ristretto255.NewIdentityElement().Add(ristretto255.NewGeneratorElement(), ristretto255.NewGeneratorElement()).Bytes()
	accountsigner.Set(baseState, unoSender1, accountsigner.SignerTypeElgamal, hexutil.Encode(pub1))
	accountsigner.Set(baseState, unoSender2, accountsigner.SignerTypeElgamal, hexutil.Encode(pub2))
	baseState.Finalise(false)

	unoWire1 := makeUNOWire(1, 0x01)
	unoWire2 := makeUNOWire(2, 0x31)
	msgs := []types.Message{
		types.NewMessage(unoSender1, &params.PrivacyRouterAddress, 0, big.NewInt(0), 1_200_000, params.GTOSPrice(), params.GTOSPrice(), params.GTOSPrice(), unoWire1, nil, true),
		types.NewMessage(plainSender, &plainRecv, 0, big.NewInt(10), params.TxGas, params.GTOSPrice(), params.GTOSPrice(), params.GTOSPrice(), nil, nil, true),
		types.NewMessage(unoSender2, &params.PrivacyRouterAddress, 0, big.NewInt(0), 1_200_000, params.GTOSPrice(), params.GTOSPrice(), params.GTOSPrice(), unoWire2, nil, true),
	}
	txs := types.Transactions{
		makeSignerTx(0, params.PrivacyRouterAddress, 1_200_000, unoWire1),
		makeSignerTx(1, plainRecv, params.TxGas, nil),
		makeSignerTx(2, params.PrivacyRouterAddress, 1_200_000, unoWire2),
	}
	blockHash := common.HexToHash("0x2233")
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

func TestExecuteTransactionsBatchVsPerTxParityMixedSystemAndUNO(t *testing.T) {
	makeState := func() *state.StateDB {
		db, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		if err != nil {
			t.Fatalf("state.New: %v", err)
		}
		return db
	}
	makeSignerTx := func(nonce uint64, to common.Address, gas uint64, data []byte) *types.Transaction {
		return types.NewTx(&types.SignerTx{
			ChainID: big.NewInt(1),
			Nonce:   nonce,
			To:      &to,
			Gas:     gas,
			Value:   big.NewInt(0),
			Data:    common.CopyBytes(data),
			V:       new(big.Int),
			R:       new(big.Int),
			S:       new(big.Int),
		})
	}
	makeShieldWire := func(amount uint64, seed byte) []byte {
		var ct uno.Ciphertext
		for i := 0; i < uno.CiphertextSize; i++ {
			ct.Commitment[i] = seed + byte(i)
			ct.Handle[i] = seed + 0x20 + byte(i)
		}
		body, err := uno.EncodeShieldPayload(uno.ShieldPayload{
			Amount:      amount,
			NewSender:   ct,
			ProofBundle: make([]byte, uno.ShieldProofSize),
		})
		if err != nil {
			t.Fatalf("EncodeShieldPayload: %v", err)
		}
		wire, err := uno.EncodeEnvelope(uno.ActionShield, body)
		if err != nil {
			t.Fatalf("EncodeEnvelope(shield): %v", err)
		}
		return wire
	}
	makeUnshieldWire := func(to common.Address, amount uint64, next uno.Ciphertext) []byte {
		proof := make([]byte, uno.BalanceProofSize)
		binary.BigEndian.PutUint64(proof[:8], amount)
		body, err := uno.EncodeUnshieldPayload(uno.UnshieldPayload{
			To:          to,
			Amount:      amount,
			NewSender:   next,
			ProofBundle: proof,
		})
		if err != nil {
			t.Fatalf("EncodeUnshieldPayload: %v", err)
		}
		wire, err := uno.EncodeEnvelope(uno.ActionUnshield, body)
		if err != nil {
			t.Fatalf("EncodeEnvelope(unshield): %v", err)
		}
		return wire
	}

	config := &params.ChainConfig{ChainID: big.NewInt(1)}
	coinbase := common.HexToAddress("0xCAFE")
	plainSender := common.HexToAddress("0xCC01")
	plainRecv := common.HexToAddress("0xCC02")
	sysSender := common.HexToAddress("0xCC03")
	unoShieldSender := common.HexToAddress("0xCC11")
	unoUnshieldSender := common.HexToAddress("0xCC12")

	baseState := makeState()
	huge := new(big.Int)
	huge.SetString("1000000000000000000", 10)
	baseState.AddBalance(plainSender, huge)
	baseState.AddBalance(sysSender, huge)
	baseState.AddBalance(unoShieldSender, huge)
	baseState.AddBalance(unoUnshieldSender, huge)

	pub1 := ristretto255.NewGeneratorElement().Bytes()
	pub2 := ristretto255.NewIdentityElement().Add(ristretto255.NewGeneratorElement(), ristretto255.NewGeneratorElement()).Bytes()
	accountsigner.Set(baseState, unoShieldSender, accountsigner.SignerTypeElgamal, hexutil.Encode(pub1))
	accountsigner.Set(baseState, unoUnshieldSender, accountsigner.SignerTypeElgamal, hexutil.Encode(pub2))

	id := ristretto255.NewIdentityElement().Bytes()
	var idCt uno.Ciphertext
	copy(idCt.Commitment[:], id)
	copy(idCt.Handle[:], id)
	uno.SetAccountState(baseState, unoUnshieldSender, uno.AccountState{
		Ciphertext: idCt,
		Version:    1,
	})
	baseState.Finalise(false)

	sysWire, err := sysaction.MakeSysAction(sysaction.ActionKind("UNKNOWN_ACTION"), map[string]interface{}{"k": 1})
	if err != nil {
		t.Fatalf("MakeSysAction: %v", err)
	}
	shieldWire := makeShieldWire(1, 0x41)
	unshieldWire := makeUnshieldWire(plainRecv, 7, idCt)

	msgs := []types.Message{
		types.NewMessage(plainSender, &plainRecv, 0, big.NewInt(10), params.TxGas, params.GTOSPrice(), params.GTOSPrice(), params.GTOSPrice(), nil, nil, true),
		types.NewMessage(sysSender, &params.SystemActionAddress, 0, big.NewInt(0), 500_000, params.GTOSPrice(), params.GTOSPrice(), params.GTOSPrice(), sysWire, nil, true),
		types.NewMessage(unoShieldSender, &params.PrivacyRouterAddress, 0, big.NewInt(0), 1_200_000, params.GTOSPrice(), params.GTOSPrice(), params.GTOSPrice(), shieldWire, nil, true),
		types.NewMessage(unoUnshieldSender, &params.PrivacyRouterAddress, 0, big.NewInt(0), 1_200_000, params.GTOSPrice(), params.GTOSPrice(), params.GTOSPrice(), unshieldWire, nil, true),
	}
	txs := types.Transactions{
		makeSignerTx(0, plainRecv, params.TxGas, nil),
		makeSignerTx(1, params.SystemActionAddress, 500_000, sysWire),
		makeSignerTx(2, params.PrivacyRouterAddress, 1_200_000, shieldWire),
		makeSignerTx(3, params.PrivacyRouterAddress, 1_200_000, unshieldWire),
	}
	blockHash := common.HexToHash("0x3344")
	blockNumber := big.NewInt(1)
	blockCtx := vm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		Coinbase:    coinbase,
		BlockNumber: blockNumber,
		GasLimit:    15_000_000,
		BaseFee:     big.NewInt(1),
	}

	dbBatch := baseState.Copy()
	gpBatch := new(GasPool).AddGas(15_000_000)
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
	gpSingle := new(GasPool).AddGas(15_000_000)
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
