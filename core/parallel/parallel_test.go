package parallel

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/kvstore"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/trie"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func newTestStateDB(t *testing.T) *state.StateDB {
	t.Helper()
	db, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	return db
}

func addr(hex string) common.Address { return common.HexToAddress(hex) }

func plainMsg(from, to common.Address, nonce uint64, value int64) types.Message {
	return types.NewMessage(from, &to, nonce, big.NewInt(value),
		params.TxGas, params.GTOSPrice(), params.GTOSPrice(), params.GTOSPrice(),
		nil, nil, true)
}

func sysActionMsg(from common.Address, nonce uint64) types.Message {
	dst := params.SystemActionAddress
	return types.NewMessage(from, &dst, nonce, big.NewInt(0),
		params.TxGas+params.SysActionGas, params.GTOSPrice(), params.GTOSPrice(), params.GTOSPrice(),
		[]byte(`{"action":"VALIDATOR_REGISTER"}`), nil, true)
}

func kvPutMsg(from common.Address, nonce uint64, ttl uint64) types.Message {
	dst := params.KVRouterAddress
	data, _ := kvstore.EncodePutPayload("ns", []byte("key"), []byte("val"), ttl)
	return types.NewMessage(from, &dst, nonce, big.NewInt(0),
		200_000, params.GTOSPrice(), params.GTOSPrice(), params.GTOSPrice(),
		data, nil, true)
}

// ─── AccessSet.Conflicts ─────────────────────────────────────────────────────

func TestAccessSetConflictsWriteWrite(t *testing.T) {
	a := AccessSet{
		ReadAddrs:  make(map[common.Address]struct{}),
		ReadSlots:  make(map[common.Address]map[common.Hash]struct{}),
		WriteAddrs: map[common.Address]struct{}{addr("0x01"): {}},
		WriteSlots: make(map[common.Address]map[common.Hash]struct{}),
	}
	b := AccessSet{
		ReadAddrs:  make(map[common.Address]struct{}),
		ReadSlots:  make(map[common.Address]map[common.Hash]struct{}),
		WriteAddrs: map[common.Address]struct{}{addr("0x01"): {}},
		WriteSlots: make(map[common.Address]map[common.Hash]struct{}),
	}
	if !a.Conflicts(&b) {
		t.Error("expected conflict on shared write addr")
	}
}

func TestAccessSetConflictsWriteRead(t *testing.T) {
	a := AccessSet{
		ReadAddrs:  make(map[common.Address]struct{}),
		ReadSlots:  make(map[common.Address]map[common.Hash]struct{}),
		WriteAddrs: map[common.Address]struct{}{addr("0x01"): {}},
		WriteSlots: make(map[common.Address]map[common.Hash]struct{}),
	}
	b := AccessSet{
		ReadAddrs:  map[common.Address]struct{}{addr("0x01"): {}},
		ReadSlots:  make(map[common.Address]map[common.Hash]struct{}),
		WriteAddrs: make(map[common.Address]struct{}),
		WriteSlots: make(map[common.Address]map[common.Hash]struct{}),
	}
	if !a.Conflicts(&b) {
		t.Error("expected conflict: a writes what b reads")
	}
}

func TestAccessSetNoConflictDisjoint(t *testing.T) {
	a := AccessSet{
		ReadAddrs:  make(map[common.Address]struct{}),
		ReadSlots:  make(map[common.Address]map[common.Hash]struct{}),
		WriteAddrs: map[common.Address]struct{}{addr("0x01"): {}},
		WriteSlots: make(map[common.Address]map[common.Hash]struct{}),
	}
	b := AccessSet{
		ReadAddrs:  make(map[common.Address]struct{}),
		ReadSlots:  make(map[common.Address]map[common.Hash]struct{}),
		WriteAddrs: map[common.Address]struct{}{addr("0x02"): {}},
		WriteSlots: make(map[common.Address]map[common.Hash]struct{}),
	}
	if a.Conflicts(&b) {
		t.Error("expected no conflict: disjoint write sets")
	}
}

func TestAccessSetSlotConflict(t *testing.T) {
	slotA := crypto.Keccak256Hash([]byte("slotA"))
	addr1 := addr("0xAA")
	a := AccessSet{
		ReadAddrs:  make(map[common.Address]struct{}),
		ReadSlots:  make(map[common.Address]map[common.Hash]struct{}),
		WriteAddrs: make(map[common.Address]struct{}),
		WriteSlots: map[common.Address]map[common.Hash]struct{}{
			addr1: {slotA: {}},
		},
	}
	b := AccessSet{
		ReadAddrs:  make(map[common.Address]struct{}),
		ReadSlots:  map[common.Address]map[common.Hash]struct{}{addr1: {slotA: {}}},
		WriteAddrs: make(map[common.Address]struct{}),
		WriteSlots: make(map[common.Address]map[common.Hash]struct{}),
	}
	if !a.Conflicts(&b) {
		t.Error("expected conflict on shared slot")
	}
}

// ─── AnalyzeTx ───────────────────────────────────────────────────────────────

func TestAnalyzeTxPlainTransfer(t *testing.T) {
	sender := addr("0x11")
	recipient := addr("0x22")
	msg := plainMsg(sender, recipient, 0, 1000)
	as := AnalyzeTx(msg)

	if _, ok := as.WriteAddrs[sender]; !ok {
		t.Error("sender should be in WriteAddrs")
	}
	if _, ok := as.WriteAddrs[recipient]; !ok {
		t.Error("recipient should be in WriteAddrs")
	}
	if _, ok := as.ReadAddrs[recipient]; !ok {
		t.Error("recipient should be in ReadAddrs")
	}
	// No WriteSlots expected for plain transfer
	if len(as.WriteSlots) != 0 {
		t.Errorf("expected no WriteSlots, got %d entries", len(as.WriteSlots))
	}
}

func TestAnalyzeTxSysAction(t *testing.T) {
	sender := addr("0x33")
	msg := sysActionMsg(sender, 0)
	as := AnalyzeTx(msg)

	if _, ok := as.WriteAddrs[sender]; !ok {
		t.Error("sender should be in WriteAddrs for sysaction")
	}
	if _, ok := as.WriteAddrs[params.ValidatorRegistryAddress]; !ok {
		t.Error("ValidatorRegistryAddress should be in WriteAddrs for sysaction")
	}
}

func TestAnalyzeTxKVPut(t *testing.T) {
	sender := addr("0x44")
	msg := kvPutMsg(sender, 0, 100)
	as := AnalyzeTx(msg)

	if _, ok := as.WriteAddrs[sender]; !ok {
		t.Error("sender should be in WriteAddrs for KV put")
	}
	// With lazy expiry, no global index slot — KVRouterAddress must NOT appear.
	if len(as.WriteSlots[params.KVRouterAddress]) != 0 {
		t.Error("KVRouterAddress must have no write slots (lazy expiry: no global index)")
	}
	if _, ok := as.WriteAddrs[params.KVRouterAddress]; ok {
		t.Error("KVRouterAddress must not be in WriteAddrs (lazy expiry: no global index)")
	}
}

func TestAnalyzeTxTwoSysActionsConflict(t *testing.T) {
	a := AnalyzeTx(sysActionMsg(addr("0xAA"), 0))
	b := AnalyzeTx(sysActionMsg(addr("0xBB"), 0))
	if !a.Conflicts(&b) {
		t.Error("two system actions should conflict via ValidatorRegistryAddress")
	}
}

func TestAnalyzeTxSameSenderConflict(t *testing.T) {
	sender := addr("0x5500")
	a := AnalyzeTx(plainMsg(sender, addr("0x0100"), 0, 10))
	b := AnalyzeTx(plainMsg(sender, addr("0x0200"), 1, 10))
	if !a.Conflicts(&b) {
		t.Error("same sender txs should conflict")
	}
}

func TestAnalyzeTxCrossSenderNoConflict(t *testing.T) {
	a := AnalyzeTx(plainMsg(addr("0xA100"), addr("0xB100"), 0, 10))
	b := AnalyzeTx(plainMsg(addr("0xA200"), addr("0xB200"), 0, 10))
	if a.Conflicts(&b) {
		t.Error("independent transfers should not conflict")
	}
}

func TestAnalyzeTxKVDifferentSendersNoConflict(t *testing.T) {
	// With lazy expiry there is no shared global index slot — KV puts from
	// different senders never conflict regardless of TTL.
	a := AnalyzeTx(kvPutMsg(addr("0xC1"), 0, 100))
	b := AnalyzeTx(kvPutMsg(addr("0xC2"), 0, 100))
	if a.Conflicts(&b) {
		t.Error("KV puts from different senders should not conflict (same TTL, lazy expiry)")
	}

	c := AnalyzeTx(kvPutMsg(addr("0xD1"), 0, 100))
	d := AnalyzeTx(kvPutMsg(addr("0xD2"), 0, 200))
	if c.Conflicts(&d) {
		t.Error("KV puts from different senders should not conflict (different TTL, lazy expiry)")
	}
}

// ─── BuildLevels ─────────────────────────────────────────────────────────────

func TestBuildLevelsAllIndependent(t *testing.T) {
	sets := []AccessSet{
		AnalyzeTx(plainMsg(addr("0xAA01"), addr("0xBB01"), 0, 1)),
		AnalyzeTx(plainMsg(addr("0xAA02"), addr("0xBB02"), 0, 1)),
		AnalyzeTx(plainMsg(addr("0xAA03"), addr("0xBB03"), 0, 1)),
	}
	levels := BuildLevels(sets)
	if len(levels) != 1 {
		t.Errorf("expected 1 level (all independent), got %d", len(levels))
	}
	if len(levels[0]) != 3 {
		t.Errorf("expected 3 txs in level 0, got %d", len(levels[0]))
	}
}

func TestBuildLevelsSameSenderSerialized(t *testing.T) {
	sender := addr("0xAA00")
	sets := []AccessSet{
		AnalyzeTx(plainMsg(sender, addr("0xBB01"), 0, 1)),
		AnalyzeTx(plainMsg(sender, addr("0xBB02"), 1, 1)),
		AnalyzeTx(plainMsg(sender, addr("0xBB03"), 2, 1)),
	}
	levels := BuildLevels(sets)
	if len(levels) != 3 {
		t.Errorf("same-sender txs must each be in a separate level, got %d levels", len(levels))
	}
}

func TestBuildLevelsSysActionsAllSerialized(t *testing.T) {
	sets := []AccessSet{
		AnalyzeTx(sysActionMsg(addr("0xE1"), 0)),
		AnalyzeTx(sysActionMsg(addr("0xE2"), 0)),
		AnalyzeTx(sysActionMsg(addr("0xE3"), 0)),
	}
	levels := BuildLevels(sets)
	if len(levels) != 3 {
		t.Errorf("system actions must all be serialized, got %d levels", len(levels))
	}
}

func TestBuildLevelsMixed(t *testing.T) {
	// tx0, tx1, tx2 are independent transfers; tx3 conflicts with tx1 (same sender).
	// Use high-byte addresses to avoid collisions with system addresses (0x01, 0x02, 0x03).
	sets := []AccessSet{
		AnalyzeTx(plainMsg(addr("0xA001"), addr("0xB001"), 0, 1)), // tx0
		AnalyzeTx(plainMsg(addr("0xA002"), addr("0xB002"), 0, 1)), // tx1
		AnalyzeTx(plainMsg(addr("0xA003"), addr("0xB003"), 0, 1)), // tx2
		AnalyzeTx(plainMsg(addr("0xA002"), addr("0xB004"), 1, 1)), // tx3 conflicts with tx1
	}
	levels := BuildLevels(sets)
	// tx0, tx1, tx2 → level 0; tx3 → level 1
	if len(levels) != 2 {
		t.Errorf("expected 2 levels, got %d", len(levels))
	}
	if len(levels[0]) != 3 {
		t.Errorf("expected 3 txs in level 0, got %d", len(levels[0]))
	}
	if len(levels[1]) != 1 || levels[1][0] != 3 {
		t.Errorf("expected tx3 in level 1, got %v", levels[1])
	}
}

func TestBuildLevelsKeepTxIndexOrder(t *testing.T) {
	// tx1 conflicts with tx0; tx2 is independent.
	// Raw DAG levels would be [0,1,0], but BuildLevels must enforce non-decreasing
	// level numbers so flattened execution keeps tx order.
	s := addr("0xA100")
	sets := []AccessSet{
		AnalyzeTx(plainMsg(s, addr("0xB101"), 0, 1)),              // tx0
		AnalyzeTx(plainMsg(s, addr("0xB102"), 1, 1)),              // tx1 (conflicts with tx0)
		AnalyzeTx(plainMsg(addr("0xA200"), addr("0xB201"), 0, 1)), // tx2 (independent)
	}
	levels := BuildLevels(sets)
	if len(levels) != 2 {
		t.Fatalf("expected 2 levels, got %d", len(levels))
	}
	if len(levels[0]) != 1 || levels[0][0] != 0 {
		t.Fatalf("expected level0=[0], got %v", levels[0])
	}
	if len(levels[1]) != 2 || levels[1][0] != 1 || levels[1][1] != 2 {
		t.Fatalf("expected level1=[1,2], got %v", levels[1])
	}
}

func TestBuildLevelsEmpty(t *testing.T) {
	levels := BuildLevels(nil)
	if levels != nil {
		t.Error("expected nil levels for empty input")
	}
}

// ─── WriteBufStateDB ─────────────────────────────────────────────────────────

func TestWriteBufGetSetBalance(t *testing.T) {
	parent := newTestStateDB(t)
	a := addr("0xAA")
	parent.AddBalance(a, big.NewInt(1000))

	buf := NewWriteBufStateDB(parent)

	if got := buf.GetBalance(a); got.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("expected 1000, got %v", got)
	}

	buf.AddBalance(a, big.NewInt(500))
	if got := buf.GetBalance(a); got.Cmp(big.NewInt(1500)) != 0 {
		t.Errorf("expected 1500 after AddBalance, got %v", got)
	}

	buf.SubBalance(a, big.NewInt(200))
	if got := buf.GetBalance(a); got.Cmp(big.NewInt(1300)) != 0 {
		t.Errorf("expected 1300 after SubBalance, got %v", got)
	}
}

func TestWriteBufMergeBalance(t *testing.T) {
	parent := newTestStateDB(t)
	a := addr("0xBB")
	parent.AddBalance(a, big.NewInt(1000))
	parent.Finalise(false)

	snapshot := parent.Copy()
	buf := NewWriteBufStateDB(snapshot)
	buf.AddBalance(a, big.NewInt(500)) // 1000 → 1500

	dst := parent.Copy()
	buf.Merge(dst)

	// delta = 1500 - 1000 = +500 applied to dst
	if got := dst.GetBalance(a); got.Cmp(big.NewInt(1500)) != 0 {
		t.Errorf("expected dst balance 1500, got %v", got)
	}
}

func TestWriteBufMergeNonce(t *testing.T) {
	parent := newTestStateDB(t)
	a := addr("0xCC")
	parent.SetNonce(a, 5)
	parent.Finalise(false)

	snapshot := parent.Copy()
	buf := NewWriteBufStateDB(snapshot)
	buf.SetNonce(a, 6)

	dst := parent.Copy()
	buf.Merge(dst)

	if got := dst.GetNonce(a); got != 6 {
		t.Errorf("expected nonce 6, got %d", got)
	}
}

func TestWriteBufMergeStorage(t *testing.T) {
	parent := newTestStateDB(t)
	a := addr("0xDD")
	// Keep account alive so storage isn't pruned
	parent.AddBalance(a, big.NewInt(1))
	slot := crypto.Keccak256Hash([]byte("testslot"))
	parent.SetState(a, slot, common.BigToHash(big.NewInt(42)))
	parent.Finalise(false)

	snapshot := parent.Copy()
	buf := NewWriteBufStateDB(snapshot)
	buf.SetState(a, slot, common.BigToHash(big.NewInt(99)))

	dst := parent.Copy()
	buf.Merge(dst)

	if got := dst.GetState(a, slot); got != common.BigToHash(big.NewInt(99)) {
		t.Errorf("expected storage slot 99, got %v", got)
	}
}

func TestWriteBufGetCommittedState(t *testing.T) {
	parent := newTestStateDB(t)
	a := addr("0xEE")
	parent.AddBalance(a, big.NewInt(1))
	slot := crypto.Keccak256Hash([]byte("committed"))
	parent.SetState(a, slot, common.BigToHash(big.NewInt(77)))
	parent.Finalise(false)

	snapshot := parent.Copy()
	buf := NewWriteBufStateDB(snapshot)

	// Uncommitted write to overlay
	buf.SetState(a, slot, common.BigToHash(big.NewInt(88)))

	// GetCommittedState should return parent's value, not overlay
	if got := buf.GetCommittedState(a, slot); got != common.BigToHash(big.NewInt(77)) {
		t.Errorf("GetCommittedState should return parent value 77, got %v", got)
	}
	// GetState should return overlay value
	if got := buf.GetState(a, slot); got != common.BigToHash(big.NewInt(88)) {
		t.Errorf("GetState should return overlay value 88, got %v", got)
	}
}

func TestWriteBufMultipleMergeDeltaCorrectness(t *testing.T) {
	// Two WriteBufs backed by the same snapshot, each adding to a different addr.
	// Merge both into dst: the coinbase (miner fee) pattern.
	parent := newTestStateDB(t)
	coinbase := addr("0xCB")
	sender1 := addr("0x01")
	sender2 := addr("0x02")
	parent.AddBalance(coinbase, big.NewInt(0))
	parent.AddBalance(sender1, big.NewInt(10000))
	parent.AddBalance(sender2, big.NewInt(10000))
	parent.Finalise(false)

	snapshot := parent.Copy()

	// Buf1: sender1 pays fee1=100 to coinbase
	buf1 := NewWriteBufStateDB(snapshot)
	buf1.SubBalance(sender1, big.NewInt(100))
	buf1.AddBalance(coinbase, big.NewInt(100))

	// Buf2: sender2 pays fee2=200 to coinbase
	buf2 := NewWriteBufStateDB(snapshot)
	buf2.SubBalance(sender2, big.NewInt(200))
	buf2.AddBalance(coinbase, big.NewInt(200))

	// Serial merge: apply buf1 then buf2 to dst
	dst := parent.Copy()
	buf1.Merge(dst)
	dst.Finalise(true)
	buf2.Merge(dst)
	dst.Finalise(true)

	// Expected: coinbase = 0 + 100 + 200 = 300
	if got := dst.GetBalance(coinbase); got.Cmp(big.NewInt(300)) != 0 {
		t.Errorf("expected coinbase 300, got %v", got)
	}
	if got := dst.GetBalance(sender1); got.Cmp(big.NewInt(9900)) != 0 {
		t.Errorf("expected sender1 9900, got %v", got)
	}
	if got := dst.GetBalance(sender2); got.Cmp(big.NewInt(9800)) != 0 {
		t.Errorf("expected sender2 9800, got %v", got)
	}
}

// ─── ExecuteParallel ─────────────────────────────────────────────────────────

// simpleGasPool is a minimal BlockGasPool for tests.
type simpleGasPool uint64

func (g *simpleGasPool) SubGas(amount uint64) error {
	if uint64(*g) < amount {
		return ErrGasLimitReached
	}
	*(*uint64)(g) -= amount
	return nil
}

func (g *simpleGasPool) Gas() uint64 { return uint64(*g) }

// mockApplyMsg is an ApplyMsgFn that performs a plain balance transfer.
// It subtracts gasUsed=1000 from sender and adds value to recipient.
func mockApplyMsg(gasUsed uint64) ApplyMsgFn {
	return func(blockCtx vm.BlockContext, config *params.ChainConfig, msg types.Message, statedb vm.StateDB) (*TxResult, error) {
		from := msg.From()
		// Deduct gas fee
		fee := new(big.Int).SetUint64(gasUsed)
		statedb.SubBalance(from, fee)
		// Apply value transfer
		if msg.To() != nil && msg.Value() != nil && msg.Value().Sign() > 0 {
			statedb.SubBalance(from, msg.Value())
			statedb.AddBalance(*msg.To(), msg.Value())
		}
		// Increment nonce
		statedb.SetNonce(from, statedb.GetNonce(from)+1)
		// Pay miner fee
		statedb.AddBalance(blockCtx.Coinbase, fee)
		return &TxResult{UsedGas: gasUsed}, nil
	}
}

func makeTestBlock(t *testing.T, txs []*types.Transaction) *types.Block {
	if t != nil {
		t.Helper()
	}
	header := &types.Header{
		Number:     big.NewInt(1),
		GasLimit:   10_000_000,
		Difficulty: big.NewInt(1),
	}
	return types.NewBlock(header, txs, nil, nil, trie.NewStackTrie(nil))
}

func makeFakeTx(nonce uint64) *types.Transaction {
	return types.NewTx(&types.SignerTx{
		ChainID: big.NewInt(1),
		Nonce:   nonce,
		Gas:     params.TxGas,
		Value:   big.NewInt(0),
		V:       new(big.Int),
		R:       new(big.Int),
		S:       new(big.Int),
	})
}

func TestExecuteParallelEmpty(t *testing.T) {
	db := newTestStateDB(t)
	block := makeTestBlock(t, nil)
	gp := simpleGasPool(1_000_000)

	receipts, logs, gas, err := ExecuteParallel(
		&params.ChainConfig{},
		vm.BlockContext{
			BlockNumber: big.NewInt(1),
			Difficulty:  big.NewInt(1),
		},
		db, block.Transactions(), block.Hash(), block.Header().Number, &gp, nil, mockApplyMsg(1000),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(receipts) != 0 || len(logs) != 0 || gas != 0 {
		t.Error("expected empty results for empty block")
	}
}

func TestExecuteParallelIndependentTxs(t *testing.T) {
	// 3 independent transfers: different senders, different recipients.
	// All should land in level 0 and run in parallel.
	// Use 4-digit hex to avoid collision with system addresses (0x01, 0x02, 0x03).
	coinbase := addr("0xCBCB")
	senders := []common.Address{addr("0xAA01"), addr("0xAA02"), addr("0xAA03")}
	recipients := []common.Address{addr("0xBB01"), addr("0xBB02"), addr("0xBB03")}
	const fee = uint64(1000)
	const value = int64(500)
	const initialBalance = int64(10_000)

	db := newTestStateDB(t)
	for _, s := range senders {
		db.AddBalance(s, big.NewInt(initialBalance))
	}
	db.Finalise(false)

	msgs := make([]types.Message, 3)
	for i := range msgs {
		msgs[i] = plainMsg(senders[i], recipients[i], 0, value)
	}

	txs := []*types.Transaction{makeFakeTx(0), makeFakeTx(1), makeFakeTx(2)}
	block := makeTestBlock(t, txs)
	gp := simpleGasPool(10_000_000)

	apply := mockApplyMsg(fee)
	receipts, _, totalGas, err := ExecuteParallel(
		&params.ChainConfig{},
		vm.BlockContext{
			BlockNumber: big.NewInt(1),
			Difficulty:  big.NewInt(1),
			Coinbase:    coinbase,
		},
		db, block.Transactions(), block.Hash(), block.Header().Number, &gp, msgs, apply,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(receipts) != 3 {
		t.Errorf("expected 3 receipts, got %d", len(receipts))
	}
	if totalGas != uint64(3)*fee {
		t.Errorf("expected totalGas %d, got %d", 3*fee, totalGas)
	}

	// Verify cumulative gas in receipts is monotonically increasing.
	for i, r := range receipts {
		expected := uint64(i+1) * fee
		if r.CumulativeGasUsed != expected {
			t.Errorf("receipt[%d].CumulativeGasUsed = %d, want %d", i, r.CumulativeGasUsed, expected)
		}
	}

	// Verify recipients received value.
	for i, rec := range recipients {
		if got := db.GetBalance(rec); got.Cmp(big.NewInt(value)) != 0 {
			t.Errorf("recipient[%d] balance = %v, want %d", i, got, value)
		}
	}

	// Verify coinbase received 3 fees.
	expectedCoinbase := big.NewInt(int64(3) * int64(fee))
	if got := db.GetBalance(coinbase); got.Cmp(expectedCoinbase) != 0 {
		t.Errorf("coinbase balance = %v, want %v", got, expectedCoinbase)
	}
}

func TestExecuteParallelStateRootParity(t *testing.T) {
	// Run ExecuteParallel on the same initial state twice (with 4 independent txs)
	// and verify the statedb hash is deterministic.
	coinbase := addr("0xCBCC")
	senders := []common.Address{addr("0xA101"), addr("0xA102"), addr("0xA103"), addr("0xA104")}
	recipients := []common.Address{addr("0xB101"), addr("0xB102"), addr("0xB103"), addr("0xB104")}

	makeDB := func() *state.StateDB {
		db := newTestStateDB(t)
		for _, s := range senders {
			db.AddBalance(s, big.NewInt(100_000))
		}
		db.Finalise(false)
		return db
	}

	msgs := make([]types.Message, 4)
	for i := range msgs {
		msgs[i] = plainMsg(senders[i], recipients[i], 0, 1000)
	}
	txs := []*types.Transaction{makeFakeTx(0), makeFakeTx(1), makeFakeTx(2), makeFakeTx(3)}
	block := makeTestBlock(t, txs)

	runOnce := func() common.Hash {
		db := makeDB()
		gp := simpleGasPool(10_000_000)
		_, _, _, err := ExecuteParallel(
			&params.ChainConfig{},
			vm.BlockContext{
				BlockNumber: big.NewInt(1),
				Difficulty:  big.NewInt(1),
				Coinbase:    coinbase,
			},
			db, block.Transactions(), block.Hash(), block.Header().Number, &gp, msgs, mockApplyMsg(500),
		)
		if err != nil {
			t.Fatalf("ExecuteParallel failed: %v", err)
		}
		root, _ := db.Commit(false)
		return root
	}

	root1 := runOnce()
	root2 := runOnce()

	if root1 != root2 {
		t.Errorf("state root is not deterministic: %v vs %v", root1, root2)
	}
}

func TestExecuteParallelSerialEquivalence(t *testing.T) {
	// Verify that parallel execution produces the same state root as a
	// hand-rolled serial execution for conflicting (same-sender) txs.
	coinbase := addr("0xCC01")
	sender := addr("0xDD01")
	r1 := addr("0xEE01")
	r2 := addr("0xEE02")

	const fee = uint64(100)
	const val = int64(50)

	makeDB := func() *state.StateDB {
		db := newTestStateDB(t)
		db.AddBalance(sender, big.NewInt(10_000))
		db.Finalise(false)
		return db
	}

	msgs := []types.Message{
		plainMsg(sender, r1, 0, val),
		plainMsg(sender, r2, 1, val),
	}
	txs := []*types.Transaction{makeFakeTx(0), makeFakeTx(1)}
	block := makeTestBlock(t, txs)

	applyFn := mockApplyMsg(fee)

	// Parallel run
	dbParallel := makeDB()
	gp1 := simpleGasPool(10_000_000)
	_, _, _, err := ExecuteParallel(
		&params.ChainConfig{},
		vm.BlockContext{
			BlockNumber: big.NewInt(1),
			Difficulty:  big.NewInt(1),
			Coinbase:    coinbase,
		},
		dbParallel, block.Transactions(), block.Hash(), block.Header().Number, &gp1, msgs, applyFn,
	)
	if err != nil {
		t.Fatalf("parallel: %v", err)
	}
	parallelRoot, _ := dbParallel.Commit(false)

	// Serial run (manually apply msgs in order)
	dbSerial := makeDB()
	for i, msg := range msgs {
		buf := NewWriteBufStateDB(dbSerial)
		buf.Prepare(txs[i].Hash(), i)
		res, serr := applyFn(vm.BlockContext{
			BlockNumber: big.NewInt(1),
			Difficulty:  big.NewInt(1),
			Coinbase:    coinbase,
		}, &params.ChainConfig{}, msg, buf)
		if serr != nil {
			t.Fatalf("serial apply[%d]: %v", i, serr)
		}
		_ = res
		buf.Merge(dbSerial)
		dbSerial.Finalise(true)
	}
	serialRoot, _ := dbSerial.Commit(false)

	if parallelRoot != serialRoot {
		t.Errorf("state root mismatch: parallel=%v serial=%v", parallelRoot, serialRoot)
	}
}

func TestExecuteParallelReceiptsFollowTxOrder(t *testing.T) {
	coinbase := addr("0xCA01")
	sameSender := addr("0xAA11")
	otherSender := addr("0xAA22")
	r1 := addr("0xBB11")
	r2 := addr("0xBB22")
	r3 := addr("0xBB33")

	db := newTestStateDB(t)
	db.AddBalance(sameSender, big.NewInt(100_000))
	db.AddBalance(otherSender, big.NewInt(100_000))
	db.Finalise(false)

	msgs := []types.Message{
		plainMsg(sameSender, r1, 0, 10),  // tx0
		plainMsg(sameSender, r2, 1, 20),  // tx1 (conflicts with tx0)
		plainMsg(otherSender, r3, 0, 30), // tx2 (independent)
	}
	txs := []*types.Transaction{makeFakeTx(0), makeFakeTx(1), makeFakeTx(2)}
	block := makeTestBlock(t, txs)
	gp := simpleGasPool(10_000_000)

	apply := func(blockCtx vm.BlockContext, _ *params.ChainConfig, msg types.Message, sdb vm.StateDB) (*TxResult, error) {
		var gasUsed uint64
		switch *msg.To() {
		case r1:
			gasUsed = 100
		case r2:
			gasUsed = 200
		case r3:
			gasUsed = 300
		default:
			return nil, fmt.Errorf("unexpected recipient %s", msg.To().Hex())
		}
		fee := new(big.Int).SetUint64(gasUsed)
		sdb.SubBalance(msg.From(), fee)
		sdb.SubBalance(msg.From(), msg.Value())
		sdb.AddBalance(*msg.To(), msg.Value())
		sdb.SetNonce(msg.From(), sdb.GetNonce(msg.From())+1)
		sdb.AddBalance(blockCtx.Coinbase, fee)
		return &TxResult{UsedGas: gasUsed}, nil
	}

	receipts, _, totalGas, err := ExecuteParallel(
		&params.ChainConfig{},
		vm.BlockContext{
			BlockNumber: big.NewInt(1),
			Difficulty:  big.NewInt(1),
			Coinbase:    coinbase,
		},
		db, block.Transactions(), block.Hash(), block.Header().Number, &gp, msgs, apply,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if totalGas != 600 {
		t.Fatalf("unexpected total gas: have %d want %d", totalGas, 600)
	}
	for i := range txs {
		if receipts[i].TxHash != txs[i].Hash() {
			t.Fatalf("receipt[%d] hash mismatch: have %s want %s", i, receipts[i].TxHash, txs[i].Hash())
		}
	}
	if receipts[0].CumulativeGasUsed != 100 || receipts[1].CumulativeGasUsed != 300 || receipts[2].CumulativeGasUsed != 600 {
		t.Fatalf("unexpected cumulative gas sequence: [%d %d %d]",
			receipts[0].CumulativeGasUsed, receipts[1].CumulativeGasUsed, receipts[2].CumulativeGasUsed)
	}
}

func TestExecuteParallelCoinbaseSenderForcesSerialFallback(t *testing.T) {
	coinbase := addr("0xCB01")
	sender := addr("0xAA01")
	receiver := addr("0xDD01")
	beneficiary := addr("0xEE01")

	db := newTestStateDB(t)
	db.AddBalance(sender, big.NewInt(10_000))
	db.AddBalance(coinbase, big.NewInt(0))
	db.Finalise(false)

	msgs := []types.Message{
		plainMsg(sender, beneficiary, 0, 0), // tx0: pays fee to coinbase
		plainMsg(coinbase, receiver, 0, 0),  // tx1: requires coinbase balance from tx0
	}
	txs := []*types.Transaction{makeFakeTx(0), makeFakeTx(1)}
	block := makeTestBlock(t, txs)
	gp := simpleGasPool(10_000_000)

	apply := func(blockCtx vm.BlockContext, _ *params.ChainConfig, msg types.Message, sdb vm.StateDB) (*TxResult, error) {
		const gasUsed = uint64(100)
		fee := new(big.Int).SetUint64(gasUsed)
		required := new(big.Int).Add(fee, msg.Value())
		if sdb.GetBalance(msg.From()).Cmp(required) < 0 {
			return nil, fmt.Errorf("insufficient balance for %s", msg.From().Hex())
		}
		sdb.SubBalance(msg.From(), required)
		if msg.Value().Sign() > 0 {
			sdb.AddBalance(*msg.To(), msg.Value())
		}
		sdb.SetNonce(msg.From(), sdb.GetNonce(msg.From())+1)
		sdb.AddBalance(blockCtx.Coinbase, fee)
		return &TxResult{UsedGas: gasUsed}, nil
	}

	_, _, _, err := ExecuteParallel(
		&params.ChainConfig{},
		vm.BlockContext{
			BlockNumber: big.NewInt(1),
			Difficulty:  big.NewInt(1),
			Coinbase:    coinbase,
		},
		db, block.Transactions(), block.Hash(), block.Header().Number, &gp, msgs, apply,
	)
	if err != nil {
		t.Fatalf("expected success with serial fallback, got error: %v", err)
	}
	if got := db.GetNonce(coinbase); got != 1 {
		t.Fatalf("coinbase tx should be applied after fee credit, nonce=%d want=1", got)
	}
}

// ─── Benchmark ───────────────────────────────────────────────────────────────

func BenchmarkParallelExec(b *testing.B) {
	const N = 100
	const fee = uint64(500)

	coinbase := addr("0xCBCBCBCB")
	senders := make([]common.Address, N)
	recipients := make([]common.Address, N)
	for i := 0; i < N; i++ {
		// Use addresses starting at byte 10 to avoid collisions with system addresses (0x01-0x03).
		senders[i] = common.BytesToAddress([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i + 10)})
		recipients[i] = common.BytesToAddress([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, byte(i + 10)})
	}

	msgs := make([]types.Message, N)
	txs := make([]*types.Transaction, N)
	for i := 0; i < N; i++ {
		msgs[i] = plainMsg(senders[i], recipients[i], 0, 100)
		txs[i] = makeFakeTx(uint64(i))
	}
	_ = txs // used below

	makeDB := func() *state.StateDB {
		db, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		if err != nil {
			b.Fatalf("state.New: %v", err)
		}
		for _, s := range senders {
			db.AddBalance(s, big.NewInt(1_000_000))
		}
		db.Finalise(false)
		return db
	}

	header := &types.Header{
		Number:     big.NewInt(1),
		GasLimit:   100_000_000,
		Difficulty: big.NewInt(1),
	}
	benchBlock := types.NewBlock(header, txs, nil, nil, trie.NewStackTrie(nil))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db := makeDB()
		gp := simpleGasPool(100_000_000)
		_, _, _, err := ExecuteParallel(
			&params.ChainConfig{},
			vm.BlockContext{
				BlockNumber: big.NewInt(1),
				Difficulty:  big.NewInt(1),
				Coinbase:    coinbase,
			},
			db, benchBlock.Transactions(), benchBlock.Hash(), benchBlock.Header().Number, &gp, msgs, mockApplyMsg(fee),
		)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}
