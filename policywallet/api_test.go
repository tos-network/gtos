package policywallet

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
)

func newTestPolicyWalletAPI(db *mockStateDB) *PublicPolicyWalletAPI {
	return NewPublicPolicyWalletAPI(func() stateDB { return db })
}

func TestAPIGetSpendCaps(t *testing.T) {
	db := newMockStateDB()
	WriteDailyLimit(db, walletAddr, big.NewInt(1000))
	WriteSingleTxLimit(db, walletAddr, big.NewInt(100))
	WriteDailySpent(db, walletAddr, big.NewInt(250))
	WriteSpendDay(db, walletAddr, 42)

	api := newTestPolicyWalletAPI(db)
	result, err := api.GetSpendCaps(walletAddr)
	if err != nil {
		t.Fatal(err)
	}
	if result.DailyLimit != "1000" {
		t.Errorf("DailyLimit = %s, want 1000", result.DailyLimit)
	}
	if result.SingleTxLimit != "100" {
		t.Errorf("SingleTxLimit = %s, want 100", result.SingleTxLimit)
	}
	if result.DailySpent != "250" {
		t.Errorf("DailySpent = %s, want 250", result.DailySpent)
	}
	if result.SpendDay != 42 {
		t.Errorf("SpendDay = %d, want 42", result.SpendDay)
	}
}

func TestAPIGetTerminalPolicy(t *testing.T) {
	db := newMockStateDB()
	WriteTerminalPolicy(db, walletAddr, TerminalPOS, TerminalPolicy{
		MaxSingleValue: big.NewInt(500),
		MaxDailyValue:  big.NewInt(5000),
		MinTrustTier:   TrustMedium,
		Enabled:        true,
	})

	api := newTestPolicyWalletAPI(db)
	result, err := api.GetTerminalPolicy(walletAddr, TerminalPOS)
	if err != nil {
		t.Fatal(err)
	}
	if result.MaxSingleValue != "500" {
		t.Errorf("MaxSingleValue = %s, want 500", result.MaxSingleValue)
	}
	if result.MaxDailyValue != "5000" {
		t.Errorf("MaxDailyValue = %s, want 5000", result.MaxDailyValue)
	}
	if result.MinTrustTier != TrustMedium {
		t.Errorf("MinTrustTier = %d, want %d", result.MinTrustTier, TrustMedium)
	}
	if !result.Enabled {
		t.Error("Enabled = false, want true")
	}
}

func TestAPIGetDelegateAuth(t *testing.T) {
	db := newMockStateDB()
	WriteDelegateAuth(db, walletAddr, DelegateAuth{
		Delegate:  delegateAddr,
		Allowance: big.NewInt(300),
		Expiry:    99999,
		Active:    true,
	})

	api := newTestPolicyWalletAPI(db)
	result, err := api.GetDelegateAuth(walletAddr, delegateAddr)
	if err != nil {
		t.Fatal(err)
	}
	if result.Delegate != delegateAddr {
		t.Errorf("Delegate = %s, want %s", result.Delegate.Hex(), delegateAddr.Hex())
	}
	if result.Allowance != "300" {
		t.Errorf("Allowance = %s, want 300", result.Allowance)
	}
	if result.Expiry != 99999 {
		t.Errorf("Expiry = %d, want 99999", result.Expiry)
	}
	if !result.Active {
		t.Error("Active = false, want true")
	}
}

func TestAPIGetRecoveryState(t *testing.T) {
	db := newMockStateDB()
	WriteRecoveryState(db, walletAddr, RecoveryState{
		Active:      true,
		Guardian:    guardianAddr,
		NewOwner:    newOwnerAddr,
		InitiatedAt: 1000,
		Timelock:    RecoveryTimelockBlocks,
	})

	api := newTestPolicyWalletAPI(db)
	result, err := api.GetRecoveryState(walletAddr)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Active {
		t.Error("Active = false, want true")
	}
	if result.Guardian != guardianAddr {
		t.Errorf("Guardian = %s, want %s", result.Guardian.Hex(), guardianAddr.Hex())
	}
	if result.NewOwner != newOwnerAddr {
		t.Errorf("NewOwner = %s, want %s", result.NewOwner.Hex(), newOwnerAddr.Hex())
	}
	if result.InitiatedAt != 1000 {
		t.Errorf("InitiatedAt = %d, want 1000", result.InitiatedAt)
	}
	if result.Timelock != RecoveryTimelockBlocks {
		t.Errorf("Timelock = %d, want %d", result.Timelock, RecoveryTimelockBlocks)
	}
}

func TestAPIIsSuspended(t *testing.T) {
	db := newMockStateDB()
	WriteSuspended(db, walletAddr, true)

	api := newTestPolicyWalletAPI(db)
	suspended, err := api.IsSuspended(walletAddr)
	if err != nil {
		t.Fatal(err)
	}
	if !suspended {
		t.Error("IsSuspended = false, want true")
	}

	// Check unsuspended wallet.
	other := common.HexToAddress("0xf71d99c2b05b3ab38ebabfae54f08b149f9dffa9fd49cf69e20b9f0ea86514f2")
	suspended, err = api.IsSuspended(other)
	if err != nil {
		t.Fatal(err)
	}
	if suspended {
		t.Error("IsSuspended = true, want false")
	}
}

func TestAPIGetOwner(t *testing.T) {
	db := newMockStateDB()
	WriteOwner(db, walletAddr, ownerAddr)

	api := newTestPolicyWalletAPI(db)
	owner, err := api.GetOwner(walletAddr)
	if err != nil {
		t.Fatal(err)
	}
	if owner != ownerAddr {
		t.Errorf("Owner = %s, want %s", owner.Hex(), ownerAddr.Hex())
	}
}

func TestAPIGetGuardian(t *testing.T) {
	db := newMockStateDB()
	WriteGuardian(db, walletAddr, guardianAddr)

	api := newTestPolicyWalletAPI(db)
	guardian, err := api.GetGuardian(walletAddr)
	if err != nil {
		t.Fatal(err)
	}
	if guardian != guardianAddr {
		t.Errorf("Guardian = %s, want %s", guardian.Hex(), guardianAddr.Hex())
	}
}
