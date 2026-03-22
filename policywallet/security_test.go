package policywallet

import (
	"math"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/sysaction"
)

// ---------- Authorization bypass ----------

func TestSecurity_ZeroAddressOwnerCannotSetPolicies(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	// Caller is the zero address.
	zeroAddr := common.Address{}
	ctx := makeCtx(db, zeroAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicySetSpendCaps, SetSpendCapsPayload{
		Account:       walletAddr,
		DailyLimit:    "1000",
		SingleTxLimit: "500",
	})

	err := h.Handle(ctx, sa)
	if err != ErrZeroAddress {
		t.Fatalf("expected ErrZeroAddress for zero-address caller, got %v", err)
	}

	// Verify no owner was written.
	owner := ReadOwner(db, walletAddr)
	if owner != (common.Address{}) {
		t.Fatalf("owner should not be set, got %s", owner.Hex())
	}
}

func TestSecurity_ZeroAddressOwnerCannotSetAllowlist(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	zeroAddr := common.Address{}
	ctx := makeCtx(db, zeroAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicySetAllowlist, SetAllowlistPayload{
		Account: walletAddr,
		Target:  targetAddr,
		Allowed: true,
	})

	err := h.Handle(ctx, sa)
	if err != ErrZeroAddress {
		t.Fatalf("expected ErrZeroAddress, got %v", err)
	}
}

func TestSecurity_ZeroAddressOwnerCannotAuthorizeDelegate(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	zeroAddr := common.Address{}
	ctx := makeCtx(db, zeroAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicyAuthorizeDelegate, AuthorizeDelegatePayload{
		Account:   walletAddr,
		Delegate:  delegateAddr,
		Allowance: "1000",
		Expiry:    9999,
	})

	err := h.Handle(ctx, sa)
	if err != ErrZeroAddress {
		t.Fatalf("expected ErrZeroAddress, got %v", err)
	}
}

// ---------- Integer overflow / negative values ----------

func TestSecurity_NegativeSpendCapsRejected(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	ctx := makeCtx(db, ownerAddr, 100)

	// Negative daily limit.
	sa := makeSysAction(sysaction.ActionPolicySetSpendCaps, SetSpendCapsPayload{
		Account:       walletAddr,
		DailyLimit:    "-1000",
		SingleTxLimit: "500",
	})
	if err := h.Handle(ctx, sa); err != ErrNegativeAmount {
		t.Fatalf("expected ErrNegativeAmount for negative daily limit, got %v", err)
	}

	// Negative single tx limit.
	sa = makeSysAction(sysaction.ActionPolicySetSpendCaps, SetSpendCapsPayload{
		Account:       walletAddr,
		DailyLimit:    "1000",
		SingleTxLimit: "-500",
	})
	if err := h.Handle(ctx, sa); err != ErrNegativeAmount {
		t.Fatalf("expected ErrNegativeAmount for negative single tx limit, got %v", err)
	}
}

func TestSecurity_NegativeTerminalPolicyValuesRejected(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	ctx := makeCtx(db, ownerAddr, 100)

	// Negative max single value.
	sa := makeSysAction(sysaction.ActionPolicySetTerminalPolicy, SetTerminalPolicyPayload{
		Account:       walletAddr,
		TerminalClass: TerminalApp,
		MaxSingle:     "-100",
		MaxDaily:      "1000",
		MinTrustTier:  TrustLow,
	})
	if err := h.Handle(ctx, sa); err != ErrNegativeAmount {
		t.Fatalf("expected ErrNegativeAmount for negative max single, got %v", err)
	}

	// Negative max daily value.
	sa = makeSysAction(sysaction.ActionPolicySetTerminalPolicy, SetTerminalPolicyPayload{
		Account:       walletAddr,
		TerminalClass: TerminalApp,
		MaxSingle:     "100",
		MaxDaily:      "-1000",
		MinTrustTier:  TrustLow,
	})
	if err := h.Handle(ctx, sa); err != ErrNegativeAmount {
		t.Fatalf("expected ErrNegativeAmount for negative max daily, got %v", err)
	}
}

func TestSecurity_NegativeDelegateAllowanceRejected(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	ctx := makeCtx(db, ownerAddr, 100)

	sa := makeSysAction(sysaction.ActionPolicyAuthorizeDelegate, AuthorizeDelegatePayload{
		Account:   walletAddr,
		Delegate:  delegateAddr,
		Allowance: "-500",
		Expiry:    9999,
	})

	if err := h.Handle(ctx, sa); err != ErrNegativeAmount {
		t.Fatalf("expected ErrNegativeAmount for negative delegate allowance, got %v", err)
	}
}

func TestSecurity_ZeroAllowanceDelegateRejected(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	ctx := makeCtx(db, ownerAddr, 100)

	sa := makeSysAction(sysaction.ActionPolicyAuthorizeDelegate, AuthorizeDelegatePayload{
		Account:   walletAddr,
		Delegate:  delegateAddr,
		Allowance: "0",
		Expiry:    9999,
	})

	if err := h.Handle(ctx, sa); err != ErrZeroAllowance {
		t.Fatalf("expected ErrZeroAllowance, got %v", err)
	}
}

// ---------- Recovery edge cases ----------

func TestSecurity_RecoveryToZeroAddressRejected(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteGuardian(db, walletAddr, guardianAddr)

	ctx := makeCtx(db, guardianAddr, 1000)
	sa := makeSysAction(sysaction.ActionPolicyInitiateRecovery, InitiateRecoveryPayload{
		Account:  walletAddr,
		NewOwner: common.Address{},
	})

	if err := h.Handle(ctx, sa); err != ErrZeroAddress {
		t.Fatalf("expected ErrZeroAddress for recovery to zero address, got %v", err)
	}
}

func TestSecurity_RecoveryTimelockOverflow(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteGuardian(db, walletAddr, guardianAddr)

	// Manually write a recovery state with InitiatedAt near max uint64 to
	// trigger overflow in InitiatedAt + Timelock.
	WriteRecoveryState(db, walletAddr, RecoveryState{
		Active:      true,
		Guardian:    guardianAddr,
		NewOwner:    newOwnerAddr,
		InitiatedAt: math.MaxUint64 - 100,
		Timelock:    RecoveryTimelockBlocks, // 240_000 >> 100, will overflow
	})

	ctx := makeCtx(db, guardianAddr, math.MaxUint64)
	sa := makeSysAction(sysaction.ActionPolicyCompleteRecovery, CompleteRecoveryPayload{
		Account: walletAddr,
	})

	err := h.Handle(ctx, sa)
	if err != ErrTimelockOverflow {
		t.Fatalf("expected ErrTimelockOverflow, got %v", err)
	}
}

func TestSecurity_MultipleConcurrentRecoveryAttempts(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteGuardian(db, walletAddr, guardianAddr)

	// First recovery initiation.
	ctx := makeCtx(db, guardianAddr, 1000)
	sa := makeSysAction(sysaction.ActionPolicyInitiateRecovery, InitiateRecoveryPayload{
		Account:  walletAddr,
		NewOwner: newOwnerAddr,
	})
	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("first recovery should succeed: %v", err)
	}

	// Second recovery attempt should fail.
	otherNewOwner := common.HexToAddress("0xc56e1aa20e343822f1ec16c0a9230f7a17603f07dafd3ad5dbb1dd43ee34fdad")
	sa2 := makeSysAction(sysaction.ActionPolicyInitiateRecovery, InitiateRecoveryPayload{
		Account:  walletAddr,
		NewOwner: otherNewOwner,
	})
	if err := h.Handle(ctx, sa2); err != ErrRecoveryAlreadyActive {
		t.Fatalf("expected ErrRecoveryAlreadyActive, got %v", err)
	}

	// Verify original recovery state is preserved.
	rs := ReadRecoveryState(db, walletAddr)
	if rs.NewOwner != newOwnerAddr {
		t.Fatalf("recovery new owner should still be %s, got %s", newOwnerAddr.Hex(), rs.NewOwner.Hex())
	}
}

// ---------- Suspension blocks operations ----------

func TestSecurity_SuspendedAccountBlocksSetSpendCaps(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteSuspended(db, walletAddr, true)

	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicySetSpendCaps, SetSpendCapsPayload{
		Account:       walletAddr,
		DailyLimit:    "1000",
		SingleTxLimit: "500",
	})

	if err := h.Handle(ctx, sa); err != ErrWalletSuspended {
		t.Fatalf("expected ErrWalletSuspended, got %v", err)
	}
}

func TestSecurity_SuspendedAccountBlocksSetAllowlist(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteSuspended(db, walletAddr, true)

	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicySetAllowlist, SetAllowlistPayload{
		Account: walletAddr,
		Target:  targetAddr,
		Allowed: true,
	})

	if err := h.Handle(ctx, sa); err != ErrWalletSuspended {
		t.Fatalf("expected ErrWalletSuspended, got %v", err)
	}
}

func TestSecurity_SuspendedAccountBlocksAuthorizeDelegate(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteSuspended(db, walletAddr, true)

	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicyAuthorizeDelegate, AuthorizeDelegatePayload{
		Account:   walletAddr,
		Delegate:  delegateAddr,
		Allowance: "1000",
		Expiry:    9999,
	})

	if err := h.Handle(ctx, sa); err != ErrWalletSuspended {
		t.Fatalf("expected ErrWalletSuspended, got %v", err)
	}
}

func TestSecurity_SuspendedAccountBlocksSetGuardian(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteSuspended(db, walletAddr, true)

	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicySetGuardian, SetGuardianPayload{
		Account:  walletAddr,
		Guardian: guardianAddr,
	})

	if err := h.Handle(ctx, sa); err != ErrWalletSuspended {
		t.Fatalf("expected ErrWalletSuspended, got %v", err)
	}
}

func TestSecurity_SuspendedAccountBlocksSetTerminalPolicy(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteSuspended(db, walletAddr, true)

	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicySetTerminalPolicy, SetTerminalPolicyPayload{
		Account:       walletAddr,
		TerminalClass: TerminalApp,
		MaxSingle:     "100",
		MaxDaily:      "1000",
		MinTrustTier:  TrustLow,
	})

	if err := h.Handle(ctx, sa); err != ErrWalletSuspended {
		t.Fatalf("expected ErrWalletSuspended, got %v", err)
	}
}

// ---------- Delegate edge cases ----------

func TestSecurity_ExpiredDelegateState(t *testing.T) {
	db := newMockStateDB()

	// Write a delegate with an expiry in the past.
	WriteDelegateAuth(db, walletAddr, DelegateAuth{
		Delegate:  delegateAddr,
		Allowance: big.NewInt(1000),
		Expiry:    100, // expired at block 100
		Active:    true,
	})

	da := ReadDelegateAuth(db, walletAddr, delegateAddr)
	// The delegate is still marked Active in state (callers must check Expiry).
	// Verify the expiry is correctly stored so callers can check it.
	if da.Expiry != 100 {
		t.Fatalf("expiry should be 100, got %d", da.Expiry)
	}
	if !da.Active {
		t.Fatal("active flag should be true in storage")
	}
}

func TestSecurity_RevokedDelegateClearsAllState(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteDelegateAuth(db, walletAddr, DelegateAuth{
		Delegate:  delegateAddr,
		Allowance: big.NewInt(5000),
		Expiry:    999999,
		Active:    true,
	})

	// Revoke the delegate.
	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicyRevokeDelegate, RevokeDelegatePayload{
		Account:  walletAddr,
		Delegate: delegateAddr,
	})
	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	// Verify all fields are cleared.
	da := ReadDelegateAuth(db, walletAddr, delegateAddr)
	if da.Active {
		t.Fatal("delegate should be inactive after revoke")
	}
	if da.Allowance.Sign() != 0 {
		t.Fatalf("allowance should be zero after revoke, got %s", da.Allowance)
	}
	if da.Expiry != 0 {
		t.Fatalf("expiry should be zero after revoke, got %d", da.Expiry)
	}
}

// ---------- Guardian edge cases ----------

func TestSecurity_SetGuardianToZeroAddressRejected(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)

	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicySetGuardian, SetGuardianPayload{
		Account:  walletAddr,
		Guardian: common.Address{},
	})

	if err := h.Handle(ctx, sa); err != ErrZeroAddress {
		t.Fatalf("expected ErrZeroAddress for zero guardian, got %v", err)
	}
}

// ---------- Suspend edge cases ----------

func TestSecurity_SuspendUninitializedWalletRejected(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	// Wallet has no owner set. A zero-address caller should not be able
	// to suspend via the owner==zero==from path.
	ctx := makeCtx(db, common.Address{}, 100)
	sa := makeSysAction(sysaction.ActionPolicySuspend, SuspendPayload{
		Account: walletAddr,
	})

	if err := h.Handle(ctx, sa); err != ErrOwnerNotSet {
		t.Fatalf("expected ErrOwnerNotSet, got %v", err)
	}
}

func TestSecurity_SuspendByStrangerRejected(t *testing.T) {
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

// ---------- Storage slot isolation ----------

func TestSecurity_StorageSlotIsolationBetweenAccounts(t *testing.T) {
	db := newMockStateDB()

	wallet1 := common.HexToAddress("0x0791868d8f29ea735f26a17a9aea038cd4255baac26eac5a74e58a07ed2f1975")
	wallet2 := common.HexToAddress("0xc56e1aa20e343822f1ec16c0a9230f7a17603f07dafd3ad5dbb1dd43ee34fdad")

	// Set different owners for each wallet.
	owner1 := common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")
	owner2 := common.HexToAddress("0x473302ca547d5f9877e272cffe58d4def43198b66ba35cff4b2e584be19efa05")

	WriteOwner(db, wallet1, owner1)
	WriteOwner(db, wallet2, owner2)

	if ReadOwner(db, wallet1) != owner1 {
		t.Fatal("wallet1 owner corrupted")
	}
	if ReadOwner(db, wallet2) != owner2 {
		t.Fatal("wallet2 owner corrupted")
	}

	// Set different daily limits.
	WriteDailyLimit(db, wallet1, big.NewInt(1000))
	WriteDailyLimit(db, wallet2, big.NewInt(2000))

	if ReadDailyLimit(db, wallet1).Cmp(big.NewInt(1000)) != 0 {
		t.Fatal("wallet1 daily limit corrupted")
	}
	if ReadDailyLimit(db, wallet2).Cmp(big.NewInt(2000)) != 0 {
		t.Fatal("wallet2 daily limit corrupted")
	}

	// Set different allowlists.
	WriteAllowlisted(db, wallet1, targetAddr, true)
	if ReadAllowlisted(db, wallet2, targetAddr) {
		t.Fatal("wallet2 should not inherit wallet1 allowlist")
	}

	// Set different delegates.
	WriteDelegateAuth(db, wallet1, DelegateAuth{
		Delegate:  delegateAddr,
		Allowance: big.NewInt(500),
		Expiry:    9999,
		Active:    true,
	})
	da2 := ReadDelegateAuth(db, wallet2, delegateAddr)
	if da2.Active {
		t.Fatal("wallet2 should not inherit wallet1 delegate")
	}

	// Set different suspension states.
	WriteSuspended(db, wallet1, true)
	if ReadSuspended(db, wallet2) {
		t.Fatal("wallet2 should not inherit wallet1 suspension")
	}

	// Set different terminal policies.
	WriteTerminalPolicy(db, wallet1, TerminalApp, TerminalPolicy{
		MaxSingleValue: big.NewInt(100),
		MaxDailyValue:  big.NewInt(1000),
		MinTrustTier:   TrustHigh,
		Enabled:        true,
	})
	tp2 := ReadTerminalPolicy(db, wallet2, TerminalApp)
	if tp2.Enabled {
		t.Fatal("wallet2 should not inherit wallet1 terminal policy")
	}

	// Set different recovery states.
	WriteRecoveryState(db, wallet1, RecoveryState{
		Active:      true,
		Guardian:    guardianAddr,
		NewOwner:    newOwnerAddr,
		InitiatedAt: 1000,
		Timelock:    RecoveryTimelockBlocks,
	})
	rs2 := ReadRecoveryState(db, wallet2)
	if rs2.Active {
		t.Fatal("wallet2 should not inherit wallet1 recovery state")
	}
}

func TestSecurity_StorageSlotIsolationBetweenFields(t *testing.T) {
	db := newMockStateDB()

	// Setting the owner should not affect the guardian slot.
	WriteOwner(db, walletAddr, ownerAddr)
	if ReadGuardian(db, walletAddr) != (common.Address{}) {
		t.Fatal("guardian should be zero after setting only owner")
	}

	// Setting daily limit should not affect single tx limit.
	WriteDailyLimit(db, walletAddr, big.NewInt(5000))
	if ReadSingleTxLimit(db, walletAddr).Sign() != 0 {
		t.Fatal("single tx limit should be zero after setting only daily limit")
	}

	// Setting suspended should not affect owner.
	WriteSuspended(db, walletAddr, true)
	if ReadOwner(db, walletAddr) != ownerAddr {
		t.Fatal("owner corrupted after setting suspended")
	}
}

// ---------- Allowlist edge cases ----------

func TestSecurity_AllowlistZeroTargetRejected(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)

	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicySetAllowlist, SetAllowlistPayload{
		Account: walletAddr,
		Target:  common.Address{},
		Allowed: true,
	})

	if err := h.Handle(ctx, sa); err != ErrZeroAddress {
		t.Fatalf("expected ErrZeroAddress for zero target, got %v", err)
	}
}

func TestSecurity_RevokeDelegateZeroAddressRejected(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)

	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicyRevokeDelegate, RevokeDelegatePayload{
		Account:  walletAddr,
		Delegate: common.Address{},
	})

	if err := h.Handle(ctx, sa); err != ErrZeroAddress {
		t.Fatalf("expected ErrZeroAddress for zero delegate revoke, got %v", err)
	}
}

func TestSecurity_AuthorizeDelegateZeroAddressRejected(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)

	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicyAuthorizeDelegate, AuthorizeDelegatePayload{
		Account:   walletAddr,
		Delegate:  common.Address{},
		Allowance: "1000",
		Expiry:    9999,
	})

	if err := h.Handle(ctx, sa); err != ErrZeroAddress {
		t.Fatalf("expected ErrZeroAddress for zero delegate, got %v", err)
	}
}

// ---------- Recovery non-guardian callers ----------

func TestSecurity_NonGuardianCannotInitiateRecovery(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	WriteGuardian(db, walletAddr, guardianAddr)

	// A stranger (not owner, not guardian) tries to initiate recovery.
	stranger := common.HexToAddress("0xf71d99c2b05b3ab38ebabfae54f08b149f9dffa9fd49cf69e20b9f0ea86514f2")
	ctx := makeCtx(db, stranger, 1000)
	sa := makeSysAction(sysaction.ActionPolicyInitiateRecovery, InitiateRecoveryPayload{
		Account:  walletAddr,
		NewOwner: newOwnerAddr,
	})

	if err := h.Handle(ctx, sa); err != ErrNotGuardian {
		t.Fatalf("expected ErrNotGuardian, got %v", err)
	}
}

func TestSecurity_NonGuardianCannotCompleteRecovery(t *testing.T) {
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

	// A stranger tries to complete recovery after timelock.
	stranger := common.HexToAddress("0xf71d99c2b05b3ab38ebabfae54f08b149f9dffa9fd49cf69e20b9f0ea86514f2")
	ctx := makeCtx(db, stranger, 1000+RecoveryTimelockBlocks+1)
	sa := makeSysAction(sysaction.ActionPolicyCompleteRecovery, CompleteRecoveryPayload{
		Account: walletAddr,
	})

	if err := h.Handle(ctx, sa); err != ErrNotGuardian {
		t.Fatalf("expected ErrNotGuardian, got %v", err)
	}

	// Owner should remain unchanged.
	if ReadOwner(db, walletAddr) != ownerAddr {
		t.Fatal("owner should not have changed")
	}
}

func TestSecurity_RecoveryWithNoGuardianRejected(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	// No guardian set.

	ctx := makeCtx(db, ownerAddr, 1000)
	sa := makeSysAction(sysaction.ActionPolicyInitiateRecovery, InitiateRecoveryPayload{
		Account:  walletAddr,
		NewOwner: newOwnerAddr,
	})

	if err := h.Handle(ctx, sa); err != ErrNoGuardianSet {
		t.Fatalf("expected ErrNoGuardianSet, got %v", err)
	}
}

// ---------- Invalid terminal class ----------

func TestSecurity_InvalidTerminalClassRejected(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	ctx := makeCtx(db, ownerAddr, 100)

	sa := makeSysAction(sysaction.ActionPolicySetTerminalPolicy, SetTerminalPolicyPayload{
		Account:       walletAddr,
		TerminalClass: TerminalAPI + 1, // out of range
		MaxSingle:     "100",
		MaxDaily:      "1000",
		MinTrustTier:  TrustLow,
	})

	if err := h.Handle(ctx, sa); err != ErrInvalidTerminalClass {
		t.Fatalf("expected ErrInvalidTerminalClass, got %v", err)
	}
}

// ---------- Unsuspend edge cases ----------

func TestSecurity_UnsuspendNotSuspendedRejected(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &policyWalletHandler{}

	WriteOwner(db, walletAddr, ownerAddr)
	// Not suspended.

	ctx := makeCtx(db, ownerAddr, 100)
	sa := makeSysAction(sysaction.ActionPolicyUnsuspend, SuspendPayload{
		Account: walletAddr,
	})

	if err := h.Handle(ctx, sa); err != ErrWalletNotSuspended {
		t.Fatalf("expected ErrWalletNotSuspended, got %v", err)
	}
}
