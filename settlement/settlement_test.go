package settlement

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
)

// ---------- mock StateDB ----------

type mockStateDB struct {
	storage map[common.Address]map[common.Hash]common.Hash
}

func newMockStateDB() *mockStateDB {
	return &mockStateDB{
		storage: make(map[common.Address]map[common.Hash]common.Hash),
	}
}

func (m *mockStateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	if slots, ok := m.storage[addr]; ok {
		return slots[key]
	}
	return common.Hash{}
}

func (m *mockStateDB) SetState(addr common.Address, key common.Hash, val common.Hash) {
	if _, ok := m.storage[addr]; !ok {
		m.storage[addr] = make(map[common.Hash]common.Hash)
	}
	m.storage[addr][key] = val
}

// ---------- test data ----------

var (
	testCreator   = common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")
	testTarget    = common.HexToAddress("0x473302ca547d5f9877e272cffe58d4def43198b66ba35cff4b2e584be19efa05")
	testFulfiller = common.HexToAddress("0xdf96edbc954f43d46dc80e0180291bb781ac0a8a3a69c785631d4193e9a9d5e7")
	testTxHash    = common.HexToHash("0xdeadbeef")
	testCbID      = common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	testCbID2     = common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
	testFfID      = common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333")
)

// ---------- Callback exists ----------

func TestCallbackExists(t *testing.T) {
	db := newMockStateDB()

	if ReadCallbackExists(db, testCbID) {
		t.Fatal("callback should not exist by default")
	}

	WriteCallbackExists(db, testCbID)
	if !ReadCallbackExists(db, testCbID) {
		t.Fatal("callback should exist after write")
	}

	// Different ID should not exist.
	if ReadCallbackExists(db, testCbID2) {
		t.Fatal("unrelated callback should not exist")
	}
}

// ---------- Callback TxHash ----------

func TestCallbackTxHash(t *testing.T) {
	db := newMockStateDB()

	WriteCallbackTxHash(db, testCbID, testTxHash)
	got := ReadCallbackTxHash(db, testCbID)
	if got != testTxHash {
		t.Fatalf("txHash mismatch: got %s, want %s", got.Hex(), testTxHash.Hex())
	}
}

// ---------- Callback type ----------

func TestCallbackType(t *testing.T) {
	db := newMockStateDB()

	for _, cbType := range []CallbackType{CallbackOnSettle, CallbackOnFail, CallbackOnTimeout, CallbackOnRefund} {
		WriteCallbackType(db, testCbID, cbType)
		got := ReadCallbackType(db, testCbID)
		if got != cbType {
			t.Errorf("callback type mismatch: got %q, want %q", got, cbType)
		}
	}
}

func TestCallbackType_Empty(t *testing.T) {
	db := newMockStateDB()

	got := ReadCallbackType(db, testCbID)
	if got != "" {
		t.Fatalf("expected empty callback type, got %q", got)
	}
}

// ---------- Callback target ----------

func TestCallbackTarget(t *testing.T) {
	db := newMockStateDB()

	WriteCallbackTarget(db, testCbID, testTarget)
	got := ReadCallbackTarget(db, testCbID)
	if got != testTarget {
		t.Fatalf("target mismatch: got %s, want %s", got.Hex(), testTarget.Hex())
	}
}

// ---------- Callback data / policy hash ----------

func TestCallbackDataAndPolicyHash(t *testing.T) {
	db := newMockStateDB()

	data := common.HexToHash("0xfeedface")
	policy := common.HexToHash("0xcafebabe")

	WriteCallbackData(db, testCbID, data)
	WriteCallbackPolicyHash(db, testCbID, policy)

	if got := ReadCallbackData(db, testCbID); got != data {
		t.Errorf("callback data mismatch: got %s", got.Hex())
	}
	if got := ReadCallbackPolicyHash(db, testCbID); got != policy {
		t.Errorf("policy hash mismatch: got %s", got.Hex())
	}
}

// ---------- Callback timing fields ----------

func TestCallbackMaxGas(t *testing.T) {
	db := newMockStateDB()

	WriteCallbackMaxGas(db, testCbID, 500_000)
	if got := ReadCallbackMaxGas(db, testCbID); got != 500_000 {
		t.Fatalf("max_gas mismatch: got %d, want 500000", got)
	}
}

func TestCallbackCreatedAt(t *testing.T) {
	db := newMockStateDB()

	WriteCallbackCreatedAt(db, testCbID, 100)
	if got := ReadCallbackCreatedAt(db, testCbID); got != 100 {
		t.Fatalf("created_at mismatch: got %d, want 100", got)
	}
}

func TestCallbackExpiresAt(t *testing.T) {
	db := newMockStateDB()

	WriteCallbackExpiresAt(db, testCbID, 200)
	if got := ReadCallbackExpiresAt(db, testCbID); got != 200 {
		t.Fatalf("expires_at mismatch: got %d, want 200", got)
	}
}

func TestCallbackExecutedAt(t *testing.T) {
	db := newMockStateDB()

	WriteCallbackExecutedAt(db, testCbID, 150)
	if got := ReadCallbackExecutedAt(db, testCbID); got != 150 {
		t.Fatalf("executed_at mismatch: got %d, want 150", got)
	}
}

// ---------- Callback status ----------

func TestCallbackStatus(t *testing.T) {
	db := newMockStateDB()

	if got := ReadCallbackStatus(db, testCbID); got != "" {
		t.Fatalf("expected empty status, got %q", got)
	}

	for _, status := range []string{StatusPending, StatusExecuted, StatusExpired, StatusFailed} {
		WriteCallbackStatus(db, testCbID, status)
		got := ReadCallbackStatus(db, testCbID)
		if got != status {
			t.Errorf("status mismatch: got %q, want %q", got, status)
		}
	}
}

// ---------- Callback creator ----------

func TestCallbackCreator(t *testing.T) {
	db := newMockStateDB()

	WriteCallbackCreator(db, testCbID, testCreator)
	got := ReadCallbackCreator(db, testCbID)
	if got != testCreator {
		t.Fatalf("creator mismatch: got %s, want %s", got.Hex(), testCreator.Hex())
	}
}

// ---------- Full SettlementCallback round-trip ----------

func TestSettlementCallback_RoundTrip(t *testing.T) {
	db := newMockStateDB()

	cb := SettlementCallback{
		CallbackID:    testCbID,
		TxHash:        testTxHash,
		CallbackType:  CallbackOnSettle,
		TargetAddress: testTarget,
		CallbackData:  common.HexToHash("0xfeed"),
		PolicyHash:    common.HexToHash("0xcafe"),
		MaxGas:        300_000,
		CreatedAt:     100,
		ExpiresAt:     1100,
		Status:        StatusPending,
		Creator:       testCreator,
	}

	WriteCallbackExists(db, cb.CallbackID)
	WriteCallbackTxHash(db, cb.CallbackID, cb.TxHash)
	WriteCallbackType(db, cb.CallbackID, cb.CallbackType)
	WriteCallbackTarget(db, cb.CallbackID, cb.TargetAddress)
	WriteCallbackData(db, cb.CallbackID, cb.CallbackData)
	WriteCallbackPolicyHash(db, cb.CallbackID, cb.PolicyHash)
	WriteCallbackMaxGas(db, cb.CallbackID, cb.MaxGas)
	WriteCallbackCreatedAt(db, cb.CallbackID, cb.CreatedAt)
	WriteCallbackExpiresAt(db, cb.CallbackID, cb.ExpiresAt)
	WriteCallbackStatus(db, cb.CallbackID, cb.Status)
	WriteCallbackCreator(db, cb.CallbackID, cb.Creator)

	if !ReadCallbackExists(db, cb.CallbackID) {
		t.Error("callback should exist")
	}
	if got := ReadCallbackTxHash(db, cb.CallbackID); got != cb.TxHash {
		t.Errorf("TxHash: got %s, want %s", got.Hex(), cb.TxHash.Hex())
	}
	if got := ReadCallbackType(db, cb.CallbackID); got != cb.CallbackType {
		t.Errorf("CallbackType: got %q, want %q", got, cb.CallbackType)
	}
	if got := ReadCallbackTarget(db, cb.CallbackID); got != cb.TargetAddress {
		t.Errorf("Target: got %s", got.Hex())
	}
	if got := ReadCallbackData(db, cb.CallbackID); got != cb.CallbackData {
		t.Errorf("CallbackData: got %s", got.Hex())
	}
	if got := ReadCallbackPolicyHash(db, cb.CallbackID); got != cb.PolicyHash {
		t.Errorf("PolicyHash: got %s", got.Hex())
	}
	if got := ReadCallbackMaxGas(db, cb.CallbackID); got != cb.MaxGas {
		t.Errorf("MaxGas: got %d, want %d", got, cb.MaxGas)
	}
	if got := ReadCallbackCreatedAt(db, cb.CallbackID); got != cb.CreatedAt {
		t.Errorf("CreatedAt: got %d, want %d", got, cb.CreatedAt)
	}
	if got := ReadCallbackExpiresAt(db, cb.CallbackID); got != cb.ExpiresAt {
		t.Errorf("ExpiresAt: got %d, want %d", got, cb.ExpiresAt)
	}
	if got := ReadCallbackStatus(db, cb.CallbackID); got != cb.Status {
		t.Errorf("Status: got %q, want %q", got, cb.Status)
	}
	if got := ReadCallbackCreator(db, cb.CallbackID); got != cb.Creator {
		t.Errorf("Creator: got %s", got.Hex())
	}
}

// ---------- Callback status transitions ----------

func TestCallbackStatusTransitions(t *testing.T) {
	db := newMockStateDB()

	// Start as pending.
	WriteCallbackStatus(db, testCbID, StatusPending)
	if got := ReadCallbackStatus(db, testCbID); got != StatusPending {
		t.Fatalf("expected pending, got %q", got)
	}

	// Transition to executed.
	WriteCallbackStatus(db, testCbID, StatusExecuted)
	WriteCallbackExecutedAt(db, testCbID, 150)
	if got := ReadCallbackStatus(db, testCbID); got != StatusExecuted {
		t.Fatalf("expected executed, got %q", got)
	}
	if got := ReadCallbackExecutedAt(db, testCbID); got != 150 {
		t.Fatalf("executed_at should be 150, got %d", got)
	}
}

func TestCallbackStatusTransition_PendingToExpired(t *testing.T) {
	db := newMockStateDB()

	WriteCallbackStatus(db, testCbID, StatusPending)
	WriteCallbackStatus(db, testCbID, StatusExpired)

	if got := ReadCallbackStatus(db, testCbID); got != StatusExpired {
		t.Fatalf("expected expired, got %q", got)
	}
}

func TestCallbackStatusTransition_PendingToFailed(t *testing.T) {
	db := newMockStateDB()

	WriteCallbackStatus(db, testCbID, StatusPending)
	WriteCallbackStatus(db, testCbID, StatusFailed)

	if got := ReadCallbackStatus(db, testCbID); got != StatusFailed {
		t.Fatalf("expected failed, got %q", got)
	}
}

// ---------- Multiple callbacks for same tx ----------

func TestMultipleCallbacksSameTx(t *testing.T) {
	db := newMockStateDB()

	// Register two callbacks for the same tx hash but different IDs.
	WriteCallbackExists(db, testCbID)
	WriteCallbackTxHash(db, testCbID, testTxHash)
	WriteCallbackType(db, testCbID, CallbackOnSettle)
	WriteCallbackTarget(db, testCbID, testTarget)
	WriteCallbackStatus(db, testCbID, StatusPending)
	WriteCallbackCreator(db, testCbID, testCreator)

	WriteCallbackExists(db, testCbID2)
	WriteCallbackTxHash(db, testCbID2, testTxHash)
	WriteCallbackType(db, testCbID2, CallbackOnFail)
	WriteCallbackTarget(db, testCbID2, testTarget)
	WriteCallbackStatus(db, testCbID2, StatusPending)
	WriteCallbackCreator(db, testCbID2, testCreator)

	// Verify they are independent.
	if ReadCallbackType(db, testCbID) != CallbackOnSettle {
		t.Error("cb1 type should be on_settle")
	}
	if ReadCallbackType(db, testCbID2) != CallbackOnFail {
		t.Error("cb2 type should be on_fail")
	}

	// Execute one, the other stays pending.
	WriteCallbackStatus(db, testCbID, StatusExecuted)
	WriteCallbackExecutedAt(db, testCbID, 200)

	if ReadCallbackStatus(db, testCbID) != StatusExecuted {
		t.Error("cb1 should be executed")
	}
	if ReadCallbackStatus(db, testCbID2) != StatusPending {
		t.Error("cb2 should still be pending")
	}
}

// ---------- Fulfillment CRUD ----------

func TestFulfillmentExists(t *testing.T) {
	db := newMockStateDB()

	if ReadFulfillmentExists(db, testFfID) {
		t.Fatal("fulfillment should not exist by default")
	}

	WriteFulfillmentExists(db, testFfID)
	if !ReadFulfillmentExists(db, testFfID) {
		t.Fatal("fulfillment should exist after write")
	}
}

func TestFulfillmentOriginalTxHash(t *testing.T) {
	db := newMockStateDB()

	WriteFulfillmentOriginalTxHash(db, testFfID, testTxHash)
	got := ReadFulfillmentOriginalTxHash(db, testFfID)
	if got != testTxHash {
		t.Fatalf("original tx hash mismatch: got %s, want %s", got.Hex(), testTxHash.Hex())
	}
}

func TestFulfillmentFulfiller(t *testing.T) {
	db := newMockStateDB()

	WriteFulfillmentFulfiller(db, testFfID, testFulfiller)
	got := ReadFulfillmentFulfiller(db, testFfID)
	if got != testFulfiller {
		t.Fatalf("fulfiller mismatch: got %s, want %s", got.Hex(), testFulfiller.Hex())
	}
}

func TestFulfillmentResultData(t *testing.T) {
	db := newMockStateDB()

	data := common.HexToHash("0xabcdef")
	WriteFulfillmentResultData(db, testFfID, data)
	got := ReadFulfillmentResultData(db, testFfID)
	if got != data {
		t.Fatalf("result data mismatch: got %s, want %s", got.Hex(), data.Hex())
	}
}

func TestFulfillmentPolicyCheck(t *testing.T) {
	db := newMockStateDB()

	if ReadFulfillmentPolicyCheck(db, testFfID) {
		t.Fatal("policy check should be false by default")
	}

	WriteFulfillmentPolicyCheck(db, testFfID, true)
	if !ReadFulfillmentPolicyCheck(db, testFfID) {
		t.Fatal("policy check should be true after write")
	}

	WriteFulfillmentPolicyCheck(db, testFfID, false)
	if ReadFulfillmentPolicyCheck(db, testFfID) {
		t.Fatal("policy check should be false after reset")
	}
}

func TestFulfillmentFulfilledAt(t *testing.T) {
	db := newMockStateDB()

	WriteFulfillmentFulfilledAt(db, testFfID, 999)
	if got := ReadFulfillmentFulfilledAt(db, testFfID); got != 999 {
		t.Fatalf("fulfilled_at mismatch: got %d, want 999", got)
	}
}

func TestFulfillmentReceiptRef(t *testing.T) {
	db := newMockStateDB()

	ref := common.HexToHash("0x7777")
	WriteFulfillmentReceiptRef(db, testFfID, ref)
	if got := ReadFulfillmentReceiptRef(db, testFfID); got != ref {
		t.Fatalf("receipt ref mismatch: got %s, want %s", got.Hex(), ref.Hex())
	}
}

// ---------- Full AsyncFulfillment round-trip ----------

func TestAsyncFulfillment_RoundTrip(t *testing.T) {
	db := newMockStateDB()

	ff := AsyncFulfillment{
		FulfillmentID:    testFfID,
		OriginalTxHash:   testTxHash,
		FulfillerAddress: testFulfiller,
		ResultData:       common.HexToHash("0xbeef"),
		PolicyCheck:      true,
		FulfilledAt:      500,
		ReceiptRef:       common.HexToHash("0xface"),
	}

	WriteFulfillmentExists(db, ff.FulfillmentID)
	WriteFulfillmentOriginalTxHash(db, ff.FulfillmentID, ff.OriginalTxHash)
	WriteFulfillmentFulfiller(db, ff.FulfillmentID, ff.FulfillerAddress)
	WriteFulfillmentResultData(db, ff.FulfillmentID, ff.ResultData)
	WriteFulfillmentPolicyCheck(db, ff.FulfillmentID, ff.PolicyCheck)
	WriteFulfillmentFulfilledAt(db, ff.FulfillmentID, ff.FulfilledAt)
	WriteFulfillmentReceiptRef(db, ff.FulfillmentID, ff.ReceiptRef)

	if !ReadFulfillmentExists(db, ff.FulfillmentID) {
		t.Error("fulfillment should exist")
	}
	if got := ReadFulfillmentOriginalTxHash(db, ff.FulfillmentID); got != ff.OriginalTxHash {
		t.Errorf("OriginalTxHash: got %s", got.Hex())
	}
	if got := ReadFulfillmentFulfiller(db, ff.FulfillmentID); got != ff.FulfillerAddress {
		t.Errorf("Fulfiller: got %s", got.Hex())
	}
	if got := ReadFulfillmentResultData(db, ff.FulfillmentID); got != ff.ResultData {
		t.Errorf("ResultData: got %s", got.Hex())
	}
	if !ReadFulfillmentPolicyCheck(db, ff.FulfillmentID) {
		t.Error("PolicyCheck should be true")
	}
	if got := ReadFulfillmentFulfilledAt(db, ff.FulfillmentID); got != ff.FulfilledAt {
		t.Errorf("FulfilledAt: got %d, want %d", got, ff.FulfilledAt)
	}
	if got := ReadFulfillmentReceiptRef(db, ff.FulfillmentID); got != ff.ReceiptRef {
		t.Errorf("ReceiptRef: got %s", got.Hex())
	}
}

// ---------- Counters ----------

func TestCallbackCount(t *testing.T) {
	db := newMockStateDB()

	if ReadCallbackCount(db) != 0 {
		t.Fatal("callback count should be 0 initially")
	}

	IncrementCallbackCount(db)
	IncrementCallbackCount(db)
	if got := ReadCallbackCount(db); got != 2 {
		t.Fatalf("callback count: got %d, want 2", got)
	}
}

func TestFulfillmentCount(t *testing.T) {
	db := newMockStateDB()

	if ReadFulfillmentCount(db) != 0 {
		t.Fatal("fulfillment count should be 0 initially")
	}

	IncrementFulfillmentCount(db)
	if got := ReadFulfillmentCount(db); got != 1 {
		t.Fatalf("fulfillment count: got %d, want 1", got)
	}
}

// ---------- mintCallbackID determinism ----------

func TestMintCallbackID_Deterministic(t *testing.T) {
	id1 := mintCallbackID(testCreator, testTxHash, CallbackOnSettle, 0)
	id2 := mintCallbackID(testCreator, testTxHash, CallbackOnSettle, 0)
	if id1 != id2 {
		t.Fatal("mintCallbackID should be deterministic")
	}
	if id1 == (common.Hash{}) {
		t.Fatal("mintCallbackID should not produce zero hash")
	}

	// Different nonce should produce different ID.
	id3 := mintCallbackID(testCreator, testTxHash, CallbackOnSettle, 1)
	if id1 == id3 {
		t.Fatal("different nonce should produce different callback ID")
	}

	// Different callback type should produce different ID.
	id4 := mintCallbackID(testCreator, testTxHash, CallbackOnFail, 0)
	if id1 == id4 {
		t.Fatal("different callback type should produce different callback ID")
	}
}

// ---------- mintFulfillmentID determinism ----------

func TestMintFulfillmentID_Deterministic(t *testing.T) {
	id1 := mintFulfillmentID(testFulfiller, testTxHash, 0)
	id2 := mintFulfillmentID(testFulfiller, testTxHash, 0)
	if id1 != id2 {
		t.Fatal("mintFulfillmentID should be deterministic")
	}
	if id1 == (common.Hash{}) {
		t.Fatal("mintFulfillmentID should not produce zero hash")
	}

	id3 := mintFulfillmentID(testFulfiller, testTxHash, 1)
	if id1 == id3 {
		t.Fatal("different nonce should produce different fulfillment ID")
	}
}

// ---------- Callback count is used as nonce (regression) ----------

func TestCallbackCountAsNonce(t *testing.T) {
	db := newMockStateDB()

	// Simulate registering two callbacks to verify count-based nonce produces unique IDs.
	nonce0 := ReadCallbackCount(db)
	id0 := mintCallbackID(testCreator, testTxHash, CallbackOnSettle, nonce0)
	IncrementCallbackCount(db)

	nonce1 := ReadCallbackCount(db)
	id1 := mintCallbackID(testCreator, testTxHash, CallbackOnSettle, nonce1)
	IncrementCallbackCount(db)

	if id0 == id1 {
		t.Fatal("sequential callbacks should have different IDs due to nonce increment")
	}
	if nonce1 != nonce0+1 {
		t.Fatalf("nonce should increment: got %d, want %d", nonce1, nonce0+1)
	}
}

// ---------- unused import guard ----------

var _ = new(big.Int) // ensure math/big import is used
