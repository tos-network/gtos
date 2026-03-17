package settlement

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/sysaction"
)

// ---------- full vmtypes.StateDB mock ----------

type handlerMockStateDB struct {
	storage map[common.Address]map[common.Hash]common.Hash
}

func newHandlerMockStateDB() *handlerMockStateDB {
	return &handlerMockStateDB{
		storage: make(map[common.Address]map[common.Hash]common.Hash),
	}
}

func (m *handlerMockStateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	if slots, ok := m.storage[addr]; ok {
		return slots[key]
	}
	return common.Hash{}
}

func (m *handlerMockStateDB) SetState(addr common.Address, key common.Hash, val common.Hash) {
	if _, ok := m.storage[addr]; !ok {
		m.storage[addr] = make(map[common.Hash]common.Hash)
	}
	m.storage[addr][key] = val
}

func (m *handlerMockStateDB) CreateAccount(common.Address)                           {}
func (m *handlerMockStateDB) SubBalance(common.Address, *big.Int)                    {}
func (m *handlerMockStateDB) AddBalance(common.Address, *big.Int)                    {}
func (m *handlerMockStateDB) GetBalance(common.Address) *big.Int                     { return big.NewInt(0) }
func (m *handlerMockStateDB) GetNonce(common.Address) uint64                         { return 0 }
func (m *handlerMockStateDB) SetNonce(common.Address, uint64)                        {}
func (m *handlerMockStateDB) GetCodeHash(common.Address) common.Hash                 { return common.Hash{} }
func (m *handlerMockStateDB) GetCode(common.Address) []byte                          { return nil }
func (m *handlerMockStateDB) SetCode(common.Address, []byte)                         {}
func (m *handlerMockStateDB) GetCodeSize(common.Address) int                         { return 0 }
func (m *handlerMockStateDB) AddRefund(uint64)                                       {}
func (m *handlerMockStateDB) SubRefund(uint64)                                       {}
func (m *handlerMockStateDB) GetRefund() uint64                                      { return 0 }
func (m *handlerMockStateDB) GetCommittedState(common.Address, common.Hash) common.Hash {
	return common.Hash{}
}
func (m *handlerMockStateDB) Suicide(common.Address) bool    { return false }
func (m *handlerMockStateDB) HasSuicided(common.Address) bool { return false }
func (m *handlerMockStateDB) Exist(common.Address) bool      { return false }
func (m *handlerMockStateDB) Empty(common.Address) bool      { return true }
func (m *handlerMockStateDB) PrepareAccessList(common.Address, *common.Address, []common.Address, types.AccessList) {
}
func (m *handlerMockStateDB) AddressInAccessList(common.Address) bool { return false }
func (m *handlerMockStateDB) SlotInAccessList(common.Address, common.Hash) (bool, bool) {
	return false, false
}
func (m *handlerMockStateDB) AddAddressToAccessList(common.Address)             {}
func (m *handlerMockStateDB) AddSlotToAccessList(common.Address, common.Hash)   {}
func (m *handlerMockStateDB) RevertToSnapshot(int)                              {}
func (m *handlerMockStateDB) Snapshot() int                                     { return 0 }
func (m *handlerMockStateDB) AddLog(*types.Log)                                 {}
func (m *handlerMockStateDB) Logs() []*types.Log                                { return nil }
func (m *handlerMockStateDB) AddPreimage(common.Hash, []byte)                   {}
func (m *handlerMockStateDB) ForEachStorage(common.Address, func(common.Hash, common.Hash) bool) error {
	return nil
}

// ---------- helpers ----------

func makeCtx(db *handlerMockStateDB, from common.Address, blockNum uint64) *sysaction.Context {
	return &sysaction.Context{
		From:        from,
		Value:       big.NewInt(0),
		BlockNumber: new(big.Int).SetUint64(blockNum),
		StateDB:     db,
	}
}

func makeSysAction(kind sysaction.ActionKind, payload interface{}) *sysaction.SysAction {
	raw, _ := json.Marshal(payload)
	return &sysaction.SysAction{
		Action:  kind,
		Payload: raw,
	}
}

var (
	creatorAddr  = common.HexToAddress("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	targetHex    = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	txHashHex    = "0x00000000000000000000000000000000000000000000000000000000deadbeef"
	strangerAddr = common.HexToAddress("0x9999999999999999999999999999999999999999")
)

// registerTestCallback is a helper that registers a callback and returns its ID.
func registerTestCallback(t *testing.T, db *handlerMockStateDB, h *settlementHandler, from common.Address, blockNum uint64) common.Hash {
	t.Helper()

	ctx := makeCtx(db, from, blockNum)
	sa := makeSysAction(sysaction.ActionSettlementRegisterCallback, RegisterCallbackPayload{
		TxHash:       txHashHex,
		CallbackType: string(CallbackOnSettle),
		Target:       targetHex,
		MaxGas:       300_000,
		TTLBlocks:    1000,
	})

	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("register callback failed: %v", err)
	}

	// The callback ID is deterministic based on creator, txHash, type, and nonce.
	// Nonce was 0 before registration.
	nonce := ReadCallbackCount(db) - 1
	txHash := common.HexToHash(txHashHex)
	return mintCallbackID(from, txHash, CallbackOnSettle, nonce)
}

// ---------- RegisterCallback ----------

func TestHandleRegisterCallback_Success(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &settlementHandler{}

	ctx := makeCtx(db, creatorAddr, 100)
	sa := makeSysAction(sysaction.ActionSettlementRegisterCallback, RegisterCallbackPayload{
		TxHash:       txHashHex,
		CallbackType: string(CallbackOnSettle),
		Target:       targetHex,
		MaxGas:       300_000,
		TTLBlocks:    1000,
	})

	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify callback count incremented.
	if got := ReadCallbackCount(db); got != 1 {
		t.Fatalf("callback count should be 1, got %d", got)
	}

	// Verify callback state by computing the ID.
	txHash := common.HexToHash(txHashHex)
	cbID := mintCallbackID(creatorAddr, txHash, CallbackOnSettle, 0)

	if !ReadCallbackExists(db, cbID) {
		t.Fatal("callback should exist")
	}
	if got := ReadCallbackStatus(db, cbID); got != StatusPending {
		t.Fatalf("status should be pending, got %q", got)
	}
	if got := ReadCallbackType(db, cbID); got != CallbackOnSettle {
		t.Fatalf("callback type mismatch: got %q", got)
	}
	if got := ReadCallbackMaxGas(db, cbID); got != 300_000 {
		t.Fatalf("max_gas mismatch: got %d", got)
	}
	if got := ReadCallbackCreatedAt(db, cbID); got != 100 {
		t.Fatalf("created_at mismatch: got %d", got)
	}
	if got := ReadCallbackExpiresAt(db, cbID); got != 1100 {
		t.Fatalf("expires_at mismatch: got %d, want 1100", got)
	}
	if got := ReadCallbackCreator(db, cbID); got != creatorAddr {
		t.Fatalf("creator mismatch: got %s", got.Hex())
	}
}

func TestHandleRegisterCallback_MissingTxHash(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &settlementHandler{}

	ctx := makeCtx(db, creatorAddr, 100)
	sa := makeSysAction(sysaction.ActionSettlementRegisterCallback, RegisterCallbackPayload{
		TxHash:       "", // zero hash
		CallbackType: string(CallbackOnSettle),
		Target:       targetHex,
		MaxGas:       300_000,
		TTLBlocks:    1000,
	})

	if err := h.Handle(ctx, sa); err != ErrInvalidTxHash {
		t.Fatalf("expected ErrInvalidTxHash, got %v", err)
	}
}

func TestHandleRegisterCallback_MissingTarget(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &settlementHandler{}

	ctx := makeCtx(db, creatorAddr, 100)
	sa := makeSysAction(sysaction.ActionSettlementRegisterCallback, RegisterCallbackPayload{
		TxHash:       txHashHex,
		CallbackType: string(CallbackOnSettle),
		Target:       "", // zero address
		MaxGas:       300_000,
		TTLBlocks:    1000,
	})

	if err := h.Handle(ctx, sa); err != ErrInvalidTarget {
		t.Fatalf("expected ErrInvalidTarget, got %v", err)
	}
}

func TestHandleRegisterCallback_InvalidCallbackType(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &settlementHandler{}

	ctx := makeCtx(db, creatorAddr, 100)
	sa := makeSysAction(sysaction.ActionSettlementRegisterCallback, RegisterCallbackPayload{
		TxHash:       txHashHex,
		CallbackType: "invalid_type",
		Target:       targetHex,
		MaxGas:       300_000,
		TTLBlocks:    1000,
	})

	if err := h.Handle(ctx, sa); err != ErrInvalidCallbackType {
		t.Fatalf("expected ErrInvalidCallbackType, got %v", err)
	}
}

func TestHandleRegisterCallback_ZeroMaxGas(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &settlementHandler{}

	ctx := makeCtx(db, creatorAddr, 100)
	sa := makeSysAction(sysaction.ActionSettlementRegisterCallback, RegisterCallbackPayload{
		TxHash:       txHashHex,
		CallbackType: string(CallbackOnSettle),
		Target:       targetHex,
		MaxGas:       0,
		TTLBlocks:    1000,
	})

	if err := h.Handle(ctx, sa); err != ErrMaxGasZero {
		t.Fatalf("expected ErrMaxGasZero, got %v", err)
	}
}

func TestHandleRegisterCallback_ZeroTTL(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &settlementHandler{}

	ctx := makeCtx(db, creatorAddr, 100)
	sa := makeSysAction(sysaction.ActionSettlementRegisterCallback, RegisterCallbackPayload{
		TxHash:       txHashHex,
		CallbackType: string(CallbackOnSettle),
		Target:       targetHex,
		MaxGas:       300_000,
		TTLBlocks:    0,
	})

	if err := h.Handle(ctx, sa); err != ErrTTLZero {
		t.Fatalf("expected ErrTTLZero, got %v", err)
	}
}

// ---------- ExecuteCallback ----------

func TestHandleExecuteCallback_Success(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &settlementHandler{}

	cbID := registerTestCallback(t, db, h, creatorAddr, 100)

	// Execute at block 200 (within TTL: expires at 1100).
	ctx := makeCtx(db, creatorAddr, 200)
	sa := makeSysAction(sysaction.ActionSettlementExecuteCallback, ExecuteCallbackPayload{
		CallbackID: cbID.Hex(),
	})

	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := ReadCallbackStatus(db, cbID); got != StatusExecuted {
		t.Fatalf("status should be executed, got %q", got)
	}
	if got := ReadCallbackExecutedAt(db, cbID); got != 200 {
		t.Fatalf("executed_at should be 200, got %d", got)
	}
}

func TestHandleExecuteCallback_NotPending(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &settlementHandler{}

	cbID := registerTestCallback(t, db, h, creatorAddr, 100)

	// Execute once.
	ctx := makeCtx(db, creatorAddr, 200)
	sa := makeSysAction(sysaction.ActionSettlementExecuteCallback, ExecuteCallbackPayload{
		CallbackID: cbID.Hex(),
	})
	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("first execute failed: %v", err)
	}

	// Try to execute again.
	if err := h.Handle(ctx, sa); err != ErrCallbackNotPending {
		t.Fatalf("expected ErrCallbackNotPending, got %v", err)
	}
}

func TestHandleExecuteCallback_Expired(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &settlementHandler{}

	cbID := registerTestCallback(t, db, h, creatorAddr, 100)

	// Execute at block 1200 (after expiry at 1100).
	ctx := makeCtx(db, creatorAddr, 1200)
	sa := makeSysAction(sysaction.ActionSettlementExecuteCallback, ExecuteCallbackPayload{
		CallbackID: cbID.Hex(),
	})

	if err := h.Handle(ctx, sa); err != ErrCallbackExpired {
		t.Fatalf("expected ErrCallbackExpired, got %v", err)
	}

	// Verify it was marked expired.
	if got := ReadCallbackStatus(db, cbID); got != StatusExpired {
		t.Fatalf("status should be expired, got %q", got)
	}
}

func TestHandleExecuteCallback_NotCreator(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &settlementHandler{}

	cbID := registerTestCallback(t, db, h, creatorAddr, 100)

	// Stranger tries to execute.
	ctx := makeCtx(db, strangerAddr, 200)
	sa := makeSysAction(sysaction.ActionSettlementExecuteCallback, ExecuteCallbackPayload{
		CallbackID: cbID.Hex(),
	})

	if err := h.Handle(ctx, sa); err != ErrNotCallbackCreator {
		t.Fatalf("expected ErrNotCallbackCreator, got %v", err)
	}
}

// ---------- FulfillAsync ----------

func TestHandleFulfillAsync_Success(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &settlementHandler{}

	fulfillerAddr := common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")

	ctx := makeCtx(db, fulfillerAddr, 500)
	sa := makeSysAction(sysaction.ActionSettlementFulfillAsync, FulfillAsyncPayload{
		OriginalTxHash: txHashHex,
		ResultData:     "0x00000000000000000000000000000000000000000000000000000000000000ab",
		PolicyCheck:    true,
		ReceiptRef:     "0x00000000000000000000000000000000000000000000000000000000000000cd",
	})

	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify fulfillment count.
	if got := ReadFulfillmentCount(db); got != 1 {
		t.Fatalf("fulfillment count should be 1, got %d", got)
	}

	// Compute the fulfillment ID.
	txHash := common.HexToHash(txHashHex)
	ffID := mintFulfillmentID(fulfillerAddr, txHash, 0)

	if !ReadFulfillmentExists(db, ffID) {
		t.Fatal("fulfillment should exist")
	}
	if got := ReadFulfillmentFulfiller(db, ffID); got != fulfillerAddr {
		t.Fatalf("fulfiller mismatch: got %s", got.Hex())
	}
	if got := ReadFulfillmentOriginalTxHash(db, ffID); got != txHash {
		t.Fatalf("original tx hash mismatch: got %s", got.Hex())
	}
	if !ReadFulfillmentPolicyCheck(db, ffID) {
		t.Fatal("policy check should be true")
	}
	if got := ReadFulfillmentFulfilledAt(db, ffID); got != 500 {
		t.Fatalf("fulfilled_at mismatch: got %d", got)
	}
}
