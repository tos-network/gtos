package policywallet

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

// Stubs for the rest of vmtypes.StateDB.
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

// ---------- helper ----------

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

// ---------- SetSpendCaps ----------

func TestHandleSetSpendCaps_Success(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	// Owner not set yet; first caller becomes owner.
	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicySetSpendCaps, SetSpendCapsPayload{
		Account:       walletAddr,
		DailyLimit:    "5000000",
		SingleTxLimit: "1000000",
	})

	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := ReadDailyLimit(db, walletAddr); got.Cmp(big.NewInt(5_000_000)) != 0 {
		t.Fatalf("daily limit mismatch: got %s", got)
	}
	if got := ReadSingleTxLimit(db, walletAddr); got.Cmp(big.NewInt(1_000_000)) != 0 {
		t.Fatalf("single tx limit mismatch: got %s", got)
	}
}

func TestHandleSetSpendCaps_NotOwner(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	// Set owner first.
	WriteOwner(db, walletAddr, ownerAddr)

	stranger := common.HexToAddress("0xf71d99c2b05b3ab38ebabfae54f08b149f9dffa9fd49cf69e20b9f0ea86514f2")
	ctx := makeCtx(db, stranger, 100)
	sa := makeSysAction(sysaction.ActionPolicySetSpendCaps, SetSpendCapsPayload{
		Account:       walletAddr,
		DailyLimit:    "100",
		SingleTxLimit: "50",
	})

	err := h.Handle(ctx, sa)
	if err != ErrNotOwner {
		t.Fatalf("expected ErrNotOwner, got %v", err)
	}
}

// ---------- SetAllowlist ----------

func TestHandleSetAllowlist_Success(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)

	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicySetAllowlist, SetAllowlistPayload{
		Account: walletAddr,
		Target:  targetAddr,
		Allowed: true,
	})

	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ReadAllowlisted(db, walletAddr, targetAddr) {
		t.Fatal("target should be allowlisted")
	}
}

func TestHandleSetAllowlist_NotOwner(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)

	ctx := makeCtx(db, guardianAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicySetAllowlist, SetAllowlistPayload{
		Account: walletAddr,
		Target:  targetAddr,
		Allowed: true,
	})

	if err := h.Handle(ctx, sa); err != ErrNotOwner {
		t.Fatalf("expected ErrNotOwner, got %v", err)
	}
}

// ---------- SetTerminalPolicy ----------

func TestHandleSetTerminalPolicy_Success(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)

	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicySetTerminalPolicy, SetTerminalPolicyPayload{
		Account:       walletAddr,
		TerminalClass: TerminalApp,
		MaxSingle:     "10000",
		MaxDaily:      "100000",
		MinTrustTier:  TrustMedium,
	})

	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tp := ReadTerminalPolicy(db, walletAddr, TerminalApp)
	if !tp.Enabled {
		t.Fatal("terminal policy should be enabled")
	}
	if tp.MaxSingleValue.Cmp(big.NewInt(10000)) != 0 {
		t.Fatalf("max single mismatch: got %s", tp.MaxSingleValue)
	}
	if tp.MaxDailyValue.Cmp(big.NewInt(100000)) != 0 {
		t.Fatalf("max daily mismatch: got %s", tp.MaxDailyValue)
	}
	if tp.MinTrustTier != TrustMedium {
		t.Fatalf("min trust tier mismatch: got %d", tp.MinTrustTier)
	}
}

// ---------- AuthorizeDelegate ----------

func TestHandleAuthorizeDelegate_Success(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)

	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicyAuthorizeDelegate, AuthorizeDelegatePayload{
		Account:   walletAddr,
		Delegate:  delegateAddr,
		Allowance: "999000",
		Expiry:    1700001000,
	})

	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	da := ReadDelegateAuth(db, walletAddr, delegateAddr)
	if !da.Active {
		t.Fatal("delegate should be active")
	}
	if da.Allowance.Cmp(big.NewInt(999_000)) != 0 {
		t.Fatalf("allowance mismatch: got %s", da.Allowance)
	}
	if da.Expiry != 1700001000 {
		t.Fatalf("expiry mismatch: got %d", da.Expiry)
	}
}

func TestHandleAuthorizeDelegate_NotOwner(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)

	ctx := makeCtx(db, guardianAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicyAuthorizeDelegate, AuthorizeDelegatePayload{
		Account:   walletAddr,
		Delegate:  delegateAddr,
		Allowance: "100",
		Expiry:    9999,
	})

	if err := h.Handle(ctx, sa); err != ErrNotOwner {
		t.Fatalf("expected ErrNotOwner, got %v", err)
	}
}

// ---------- RevokeDelegate ----------

func TestHandleRevokeDelegate_Success(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteDelegateAuth(db, walletAddr, DelegateAuth{
		Delegate:  delegateAddr,
		Allowance: big.NewInt(500),
		Expiry:    9999,
		Active:    true,
	})

	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicyRevokeDelegate, RevokeDelegatePayload{
		Account:  walletAddr,
		Delegate: delegateAddr,
	})

	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	da := ReadDelegateAuth(db, walletAddr, delegateAddr)
	if da.Active {
		t.Fatal("delegate should be inactive after revoke")
	}
}

// ---------- SetGuardian ----------

func TestHandleSetGuardian_Success(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)

	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicySetGuardian, SetGuardianPayload{
		Account:  walletAddr,
		Guardian: guardianAddr,
	})

	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := ReadGuardian(db, walletAddr); got != guardianAddr {
		t.Fatalf("guardian mismatch: got %s", got.Hex())
	}
}

func TestHandleSetGuardian_NotOwner(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)

	ctx := makeCtx(db, guardianAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicySetGuardian, SetGuardianPayload{
		Account:  walletAddr,
		Guardian: guardianAddr,
	})

	if err := h.Handle(ctx, sa); err != ErrNotOwner {
		t.Fatalf("expected ErrNotOwner, got %v", err)
	}
}

// ---------- InitiateRecovery ----------

func TestHandleInitiateRecovery_Success(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteGuardian(db, walletAddr, guardianAddr)

	ctx := makeCtx(db, guardianAddr, 1000)
	sa := makeSysAction(sysaction.ActionPolicyInitiateRecovery, InitiateRecoveryPayload{
		Account:  walletAddr,
		NewOwner: newOwnerAddr,
	})

	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rs := ReadRecoveryState(db, walletAddr)
	if !rs.Active {
		t.Fatal("recovery should be active")
	}
	if rs.Guardian != guardianAddr {
		t.Fatalf("guardian mismatch: got %s", rs.Guardian.Hex())
	}
	if rs.NewOwner != newOwnerAddr {
		t.Fatalf("new owner mismatch: got %s", rs.NewOwner.Hex())
	}
	if rs.InitiatedAt != 1000 {
		t.Fatalf("initiated_at mismatch: got %d", rs.InitiatedAt)
	}
}

func TestHandleInitiateRecovery_NotGuardian(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteGuardian(db, walletAddr, guardianAddr)

	// Owner tries to initiate recovery (should fail).
	ctx := makeCtx(db, ownerAddr, 1000)
	sa := makeSysAction(sysaction.ActionPolicyInitiateRecovery, InitiateRecoveryPayload{
		Account:  walletAddr,
		NewOwner: newOwnerAddr,
	})

	if err := h.Handle(ctx, sa); err != ErrNotGuardian {
		t.Fatalf("expected ErrNotGuardian, got %v", err)
	}
}

func TestHandleInitiateRecovery_AlreadyActive(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteGuardian(db, walletAddr, guardianAddr)
	WriteRecoveryState(db, walletAddr, RecoveryState{
		Active:      true,
		Guardian:    guardianAddr,
		NewOwner:    newOwnerAddr,
		InitiatedAt: 500,
		Timelock:    RecoveryTimelockBlocks,
	})

	ctx := makeCtx(db, guardianAddr, 1000)
	sa := makeSysAction(sysaction.ActionPolicyInitiateRecovery, InitiateRecoveryPayload{
		Account:  walletAddr,
		NewOwner: newOwnerAddr,
	})

	if err := h.Handle(ctx, sa); err != ErrRecoveryAlreadyActive {
		t.Fatalf("expected ErrRecoveryAlreadyActive, got %v", err)
	}
}

// ---------- CancelRecovery ----------

func TestHandleCancelRecovery_Success(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteRecoveryState(db, walletAddr, RecoveryState{
		Active:      true,
		Guardian:    guardianAddr,
		NewOwner:    newOwnerAddr,
		InitiatedAt: 500,
		Timelock:    RecoveryTimelockBlocks,
	})

	ctx := makeCtx(db, ownerAddr, 600)
	sa := makeSysAction(sysaction.ActionPolicyCancelRecovery, CancelRecoveryPayload{
		Account: walletAddr,
	})

	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rs := ReadRecoveryState(db, walletAddr)
	if rs.Active {
		t.Fatal("recovery should not be active after cancel")
	}
}

func TestHandleCancelRecovery_NotOwner(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteRecoveryState(db, walletAddr, RecoveryState{
		Active:      true,
		Guardian:    guardianAddr,
		NewOwner:    newOwnerAddr,
		InitiatedAt: 500,
		Timelock:    RecoveryTimelockBlocks,
	})

	ctx := makeCtx(db, guardianAddr, 600)
	sa := makeSysAction(sysaction.ActionPolicyCancelRecovery, CancelRecoveryPayload{
		Account: walletAddr,
	})

	if err := h.Handle(ctx, sa); err != ErrNotOwner {
		t.Fatalf("expected ErrNotOwner, got %v", err)
	}
}

// ---------- CompleteRecovery ----------

func TestHandleCompleteRecovery_Success(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteGuardian(db, walletAddr, guardianAddr)
	WriteRecoveryState(db, walletAddr, RecoveryState{
		Active:      true,
		Guardian:    guardianAddr,
		NewOwner:    newOwnerAddr,
		InitiatedAt: 1000,
		Timelock:    RecoveryTimelockBlocks,
	})

	// Block number after timelock has elapsed.
	ctx := makeCtx(db, guardianAddr, 1000+RecoveryTimelockBlocks+1)
	sa := makeSysAction(sysaction.ActionPolicyCompleteRecovery, CompleteRecoveryPayload{
		Account: walletAddr,
	})

	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Owner should be transferred.
	if got := ReadOwner(db, walletAddr); got != newOwnerAddr {
		t.Fatalf("owner should be new owner, got %s", got.Hex())
	}
	// Recovery state should be cleared.
	rs := ReadRecoveryState(db, walletAddr)
	if rs.Active {
		t.Fatal("recovery should be cleared after completion")
	}
}

func TestHandleCompleteRecovery_BeforeTimelock(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteGuardian(db, walletAddr, guardianAddr)
	WriteRecoveryState(db, walletAddr, RecoveryState{
		Active:      true,
		Guardian:    guardianAddr,
		NewOwner:    newOwnerAddr,
		InitiatedAt: 1000,
		Timelock:    RecoveryTimelockBlocks,
	})

	// Block number before timelock elapsed.
	ctx := makeCtx(db, guardianAddr, 1000+RecoveryTimelockBlocks-1)
	sa := makeSysAction(sysaction.ActionPolicyCompleteRecovery, CompleteRecoveryPayload{
		Account: walletAddr,
	})

	if err := h.Handle(ctx, sa); err != ErrRecoveryTimelockNotMet {
		t.Fatalf("expected ErrRecoveryTimelockNotMet, got %v", err)
	}
}

// ---------- Suspend ----------

func TestHandleSuspend_ByOwner(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteGuardian(db, walletAddr, guardianAddr)

	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicySuspend, SuspendPayload{
		Account: walletAddr,
	})

	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ReadSuspended(db, walletAddr) {
		t.Fatal("wallet should be suspended")
	}
}

func TestHandleSuspend_ByGuardian(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteGuardian(db, walletAddr, guardianAddr)

	ctx := makeCtx(db, guardianAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicySuspend, SuspendPayload{
		Account: walletAddr,
	})

	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ReadSuspended(db, walletAddr) {
		t.Fatal("wallet should be suspended by guardian")
	}
}

func TestHandleSuspend_Unauthorized(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteGuardian(db, walletAddr, guardianAddr)

	stranger := common.HexToAddress("0xf71d99c2b05b3ab38ebabfae54f08b149f9dffa9fd49cf69e20b9f0ea86514f2")
	ctx := makeCtx(db, stranger, 100)
	sa := makeSysAction(sysaction.ActionPolicySuspend, SuspendPayload{
		Account: walletAddr,
	})

	if err := h.Handle(ctx, sa); err != ErrNotOwner {
		t.Fatalf("expected ErrNotOwner, got %v", err)
	}
}

// ---------- Unsuspend ----------

func TestHandleUnsuspend_Success(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteSuspended(db, walletAddr, true)

	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicyUnsuspend, SuspendPayload{
		Account: walletAddr,
	})

	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ReadSuspended(db, walletAddr) {
		t.Fatal("wallet should not be suspended after unsuspend")
	}
}

func TestHandleUnsuspend_NotOwner(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteSuspended(db, walletAddr, true)

	ctx := makeCtx(db, guardianAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicyUnsuspend, SuspendPayload{
		Account: walletAddr,
	})

	if err := h.Handle(ctx, sa); err != ErrNotOwner {
		t.Fatalf("expected ErrNotOwner, got %v", err)
	}
}
