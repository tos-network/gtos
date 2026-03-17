package policywallet

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

// ---------- test addresses ----------

var (
	walletAddr   = common.HexToAddress("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	ownerAddr    = common.HexToAddress("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	guardianAddr = common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	targetAddr   = common.HexToAddress("0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")
	delegateAddr = common.HexToAddress("0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")
	newOwnerAddr = common.HexToAddress("0x1111111111111111111111111111111111111111")
)

// ---------- Owner / Guardian ----------

func TestWriteReadOwner(t *testing.T) {
	db := newMockStateDB()

	// Zero by default.
	got := ReadOwner(db, walletAddr)
	if got != (common.Address{}) {
		t.Fatalf("expected zero owner, got %s", got.Hex())
	}

	WriteOwner(db, walletAddr, ownerAddr)
	got = ReadOwner(db, walletAddr)
	if got != ownerAddr {
		t.Fatalf("owner mismatch: got %s, want %s", got.Hex(), ownerAddr.Hex())
	}
}

func TestWriteReadGuardian(t *testing.T) {
	db := newMockStateDB()

	got := ReadGuardian(db, walletAddr)
	if got != (common.Address{}) {
		t.Fatalf("expected zero guardian, got %s", got.Hex())
	}

	WriteGuardian(db, walletAddr, guardianAddr)
	got = ReadGuardian(db, walletAddr)
	if got != guardianAddr {
		t.Fatalf("guardian mismatch: got %s, want %s", got.Hex(), guardianAddr.Hex())
	}
}

// ---------- Suspension ----------

func TestSuspendedToggle(t *testing.T) {
	db := newMockStateDB()

	if ReadSuspended(db, walletAddr) {
		t.Fatal("wallet should not be suspended by default")
	}

	WriteSuspended(db, walletAddr, true)
	if !ReadSuspended(db, walletAddr) {
		t.Fatal("wallet should be suspended after write")
	}

	WriteSuspended(db, walletAddr, false)
	if ReadSuspended(db, walletAddr) {
		t.Fatal("wallet should not be suspended after unsuspend")
	}
}

// ---------- Spend caps ----------

func TestWriteReadDailyLimit(t *testing.T) {
	db := newMockStateDB()

	if ReadDailyLimit(db, walletAddr).Sign() != 0 {
		t.Fatal("expected zero daily limit")
	}

	limit := big.NewInt(5_000_000)
	WriteDailyLimit(db, walletAddr, limit)
	got := ReadDailyLimit(db, walletAddr)
	if got.Cmp(limit) != 0 {
		t.Fatalf("daily limit mismatch: got %s, want %s", got, limit)
	}
}

func TestWriteReadSingleTxLimit(t *testing.T) {
	db := newMockStateDB()

	limit := big.NewInt(1_000_000)
	WriteSingleTxLimit(db, walletAddr, limit)
	got := ReadSingleTxLimit(db, walletAddr)
	if got.Cmp(limit) != 0 {
		t.Fatalf("single tx limit mismatch: got %s, want %s", got, limit)
	}
}

func TestWriteReadDailySpent(t *testing.T) {
	db := newMockStateDB()

	spent := big.NewInt(42)
	WriteDailySpent(db, walletAddr, spent)
	got := ReadDailySpent(db, walletAddr)
	if got.Cmp(spent) != 0 {
		t.Fatalf("daily spent mismatch: got %s, want %s", got, spent)
	}
}

func TestWriteReadSpendDay(t *testing.T) {
	db := newMockStateDB()

	WriteSpendDay(db, walletAddr, 12345)
	got := ReadSpendDay(db, walletAddr)
	if got != 12345 {
		t.Fatalf("spend day mismatch: got %d, want 12345", got)
	}
}

// ---------- Allowlist ----------

func TestWriteReadAllowlist(t *testing.T) {
	db := newMockStateDB()

	if ReadAllowlisted(db, walletAddr, targetAddr) {
		t.Fatal("target should not be allowlisted by default")
	}

	WriteAllowlisted(db, walletAddr, targetAddr, true)
	if !ReadAllowlisted(db, walletAddr, targetAddr) {
		t.Fatal("target should be allowlisted after write")
	}

	// Different target should not be allowlisted.
	if ReadAllowlisted(db, walletAddr, delegateAddr) {
		t.Fatal("unrelated address should not be allowlisted")
	}

	WriteAllowlisted(db, walletAddr, targetAddr, false)
	if ReadAllowlisted(db, walletAddr, targetAddr) {
		t.Fatal("target should not be allowlisted after removal")
	}
}

// ---------- Terminal policies ----------

func TestWriteReadTerminalPolicy_AllClasses(t *testing.T) {
	db := newMockStateDB()

	classes := []uint8{TerminalApp, TerminalCard, TerminalPOS, TerminalVoice, TerminalKiosk, TerminalRobot, TerminalAPI}

	for _, class := range classes {
		tp := TerminalPolicy{
			MaxSingleValue: big.NewInt(int64(class+1) * 1000),
			MaxDailyValue:  big.NewInt(int64(class+1) * 10000),
			MinTrustTier:   class % 5,
			Enabled:        true,
		}
		WriteTerminalPolicy(db, walletAddr, class, tp)
	}

	for _, class := range classes {
		got := ReadTerminalPolicy(db, walletAddr, class)
		wantSingle := big.NewInt(int64(class+1) * 1000)
		wantDaily := big.NewInt(int64(class+1) * 10000)
		wantTrust := class % 5

		if got.MaxSingleValue.Cmp(wantSingle) != 0 {
			t.Errorf("class %d: MaxSingleValue mismatch: got %s, want %s", class, got.MaxSingleValue, wantSingle)
		}
		if got.MaxDailyValue.Cmp(wantDaily) != 0 {
			t.Errorf("class %d: MaxDailyValue mismatch: got %s, want %s", class, got.MaxDailyValue, wantDaily)
		}
		if got.MinTrustTier != wantTrust {
			t.Errorf("class %d: MinTrustTier mismatch: got %d, want %d", class, got.MinTrustTier, wantTrust)
		}
		if !got.Enabled {
			t.Errorf("class %d: should be enabled", class)
		}
	}
}

func TestTerminalPolicy_DisabledByDefault(t *testing.T) {
	db := newMockStateDB()

	got := ReadTerminalPolicy(db, walletAddr, TerminalApp)
	if got.Enabled {
		t.Fatal("terminal policy should be disabled by default")
	}
	if got.MaxSingleValue.Sign() != 0 {
		t.Fatal("MaxSingleValue should be zero by default")
	}
}

// ---------- Delegate authorisations ----------

func TestWriteReadDelegateAuth(t *testing.T) {
	db := newMockStateDB()

	da := DelegateAuth{
		Delegate:  delegateAddr,
		Allowance: big.NewInt(999_000),
		Expiry:    1700001000,
		Active:    true,
	}
	WriteDelegateAuth(db, walletAddr, da)

	got := ReadDelegateAuth(db, walletAddr, delegateAddr)
	if got.Delegate != delegateAddr {
		t.Errorf("Delegate mismatch: got %s", got.Delegate.Hex())
	}
	if got.Allowance.Cmp(da.Allowance) != 0 {
		t.Errorf("Allowance mismatch: got %s, want %s", got.Allowance, da.Allowance)
	}
	if got.Expiry != da.Expiry {
		t.Errorf("Expiry mismatch: got %d, want %d", got.Expiry, da.Expiry)
	}
	if !got.Active {
		t.Error("should be active")
	}
}

func TestDelegateAuth_Revoke(t *testing.T) {
	db := newMockStateDB()

	// Authorize.
	WriteDelegateAuth(db, walletAddr, DelegateAuth{
		Delegate:  delegateAddr,
		Allowance: big.NewInt(500),
		Expiry:    9999,
		Active:    true,
	})

	// Revoke.
	WriteDelegateAuth(db, walletAddr, DelegateAuth{
		Delegate:  delegateAddr,
		Allowance: big.NewInt(0),
		Expiry:    0,
		Active:    false,
	})

	got := ReadDelegateAuth(db, walletAddr, delegateAddr)
	if got.Active {
		t.Error("delegate should be inactive after revoke")
	}
	if got.Allowance.Sign() != 0 {
		t.Errorf("allowance should be zero after revoke, got %s", got.Allowance)
	}
}

// ---------- Recovery state ----------

func TestWriteReadRecoveryState(t *testing.T) {
	db := newMockStateDB()

	rs := RecoveryState{
		Active:      true,
		Guardian:    guardianAddr,
		NewOwner:    newOwnerAddr,
		InitiatedAt: 100_000,
		Timelock:    RecoveryTimelockBlocks,
	}
	WriteRecoveryState(db, walletAddr, rs)

	got := ReadRecoveryState(db, walletAddr)
	if !got.Active {
		t.Error("recovery should be active")
	}
	if got.Guardian != guardianAddr {
		t.Errorf("Guardian mismatch: got %s, want %s", got.Guardian.Hex(), guardianAddr.Hex())
	}
	if got.NewOwner != newOwnerAddr {
		t.Errorf("NewOwner mismatch: got %s, want %s", got.NewOwner.Hex(), newOwnerAddr.Hex())
	}
	if got.InitiatedAt != 100_000 {
		t.Errorf("InitiatedAt mismatch: got %d, want 100000", got.InitiatedAt)
	}
	if got.Timelock != RecoveryTimelockBlocks {
		t.Errorf("Timelock mismatch: got %d, want %d", got.Timelock, RecoveryTimelockBlocks)
	}
}

func TestRecoveryState_ClearOnComplete(t *testing.T) {
	db := newMockStateDB()

	WriteRecoveryState(db, walletAddr, RecoveryState{
		Active:      true,
		Guardian:    guardianAddr,
		NewOwner:    newOwnerAddr,
		InitiatedAt: 1,
		Timelock:    1000,
	})

	// Clear recovery.
	WriteRecoveryState(db, walletAddr, RecoveryState{})

	got := ReadRecoveryState(db, walletAddr)
	if got.Active {
		t.Error("recovery should not be active after clear")
	}
	if got.Guardian != (common.Address{}) {
		t.Errorf("Guardian should be zero after clear, got %s", got.Guardian.Hex())
	}
}

// ---------- Privacy terminal policies ----------

func TestWriteReadPrivacyTerminalPolicy(t *testing.T) {
	db := newMockStateDB()

	policy := PrivacyTerminalPolicy{
		TerminalClass:     TerminalApp,
		MaxPrivateValue:   big.NewInt(5_000_000),
		AllowShield:       true,
		AllowUnshield:     true,
		AllowPrivTransfer: false,
		MinTrustTier:      TrustMedium,
	}
	WritePrivacyTerminalPolicy(db, walletAddr, policy)

	got := ReadPrivacyTerminalPolicy(db, walletAddr, TerminalApp)
	if got.TerminalClass != TerminalApp {
		t.Errorf("TerminalClass mismatch: got %d", got.TerminalClass)
	}
	if got.MaxPrivateValue.Cmp(policy.MaxPrivateValue) != 0 {
		t.Errorf("MaxPrivateValue mismatch: got %s, want %s", got.MaxPrivateValue, policy.MaxPrivateValue)
	}
	if !got.AllowShield {
		t.Error("AllowShield should be true")
	}
	if !got.AllowUnshield {
		t.Error("AllowUnshield should be true")
	}
	if got.AllowPrivTransfer {
		t.Error("AllowPrivTransfer should be false")
	}
	if got.MinTrustTier != TrustMedium {
		t.Errorf("MinTrustTier mismatch: got %d, want %d", got.MinTrustTier, TrustMedium)
	}
}

func TestPrivacyTerminalPolicy_AllFlags(t *testing.T) {
	db := newMockStateDB()

	policy := PrivacyTerminalPolicy{
		TerminalClass:     TerminalCard,
		MaxPrivateValue:   big.NewInt(100),
		AllowShield:       true,
		AllowUnshield:     true,
		AllowPrivTransfer: true,
		MinTrustTier:      TrustHigh,
	}
	WritePrivacyTerminalPolicy(db, walletAddr, policy)

	got := ReadPrivacyTerminalPolicy(db, walletAddr, TerminalCard)
	if !got.AllowShield || !got.AllowUnshield || !got.AllowPrivTransfer {
		t.Error("all flags should be true")
	}
}

func TestValidatePrivacyTerminalAccess_Shield(t *testing.T) {
	db := newMockStateDB()

	WritePrivacyTerminalPolicy(db, walletAddr, PrivacyTerminalPolicy{
		TerminalClass:     TerminalApp,
		MaxPrivateValue:   big.NewInt(1000),
		AllowShield:       true,
		AllowUnshield:     false,
		AllowPrivTransfer: false,
		MinTrustTier:      TrustMedium,
	})

	// Shield with sufficient trust should pass.
	if err := ValidatePrivacyTerminalAccess(db, walletAddr, TerminalApp, TrustMedium, PrivacyActionShield, big.NewInt(500)); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Unshield should be denied.
	if err := ValidatePrivacyTerminalAccess(db, walletAddr, TerminalApp, TrustMedium, PrivacyActionUnshield, big.NewInt(500)); err != ErrPrivTerminalUnshieldDenied {
		t.Fatalf("expected ErrPrivTerminalUnshieldDenied, got %v", err)
	}

	// Value exceeding limit should fail.
	if err := ValidatePrivacyTerminalAccess(db, walletAddr, TerminalApp, TrustMedium, PrivacyActionShield, big.NewInt(2000)); err != ErrPrivTerminalValueExceeded {
		t.Fatalf("expected ErrPrivTerminalValueExceeded, got %v", err)
	}

	// Trust too low should fail.
	if err := ValidatePrivacyTerminalAccess(db, walletAddr, TerminalApp, TrustLow, PrivacyActionShield, big.NewInt(500)); err != ErrPrivTerminalTrustTooLow {
		t.Fatalf("expected ErrPrivTerminalTrustTooLow, got %v", err)
	}
}

func TestValidatePrivacyTerminalAccess_UnknownAction(t *testing.T) {
	db := newMockStateDB()

	WritePrivacyTerminalPolicy(db, walletAddr, PrivacyTerminalPolicy{
		TerminalClass:     TerminalApp,
		MaxPrivateValue:   big.NewInt(1000),
		AllowShield:       true,
		AllowUnshield:     true,
		AllowPrivTransfer: true,
		MinTrustTier:      TrustMedium,
	})

	if err := ValidatePrivacyTerminalAccess(db, walletAddr, TerminalApp, TrustMedium, "unknown_action", big.NewInt(1)); err != ErrPrivUnknownAction {
		t.Fatalf("expected ErrPrivUnknownAction, got %v", err)
	}
}

// ---------- Sponsor relay validation ----------

func TestValidateSponsoredExecution_Success(t *testing.T) {
	db := newMockStateDB()

	// Set up: owner, allowlist the sponsor, enable terminal.
	WriteOwner(db, walletAddr, ownerAddr)
	WriteAllowlisted(db, walletAddr, targetAddr, true)
	WriteTerminalPolicy(db, walletAddr, TerminalApp, TerminalPolicy{
		MaxSingleValue: big.NewInt(10000),
		MaxDailyValue:  big.NewInt(100000),
		MinTrustTier:   TrustLow,
		Enabled:        true,
	})

	err := ValidateSponsoredExecution(db, walletAddr, targetAddr, big.NewInt(5000), TerminalApp, TrustMedium)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidateSponsoredExecution_Suspended(t *testing.T) {
	db := newMockStateDB()

	WriteSuspended(db, walletAddr, true)

	err := ValidateSponsoredExecution(db, walletAddr, targetAddr, big.NewInt(1), TerminalApp, TrustHigh)
	if err != ErrSponsorWalletSuspended {
		t.Fatalf("expected ErrSponsorWalletSuspended, got %v", err)
	}
}

func TestValidateSponsoredExecution_NotAllowlisted(t *testing.T) {
	db := newMockStateDB()

	err := ValidateSponsoredExecution(db, walletAddr, targetAddr, big.NewInt(1), TerminalApp, TrustHigh)
	if err != ErrSponsorNotAllowlisted {
		t.Fatalf("expected ErrSponsorNotAllowlisted, got %v", err)
	}
}

func TestValidateSponsoredExecution_TerminalDisabled(t *testing.T) {
	db := newMockStateDB()

	WriteAllowlisted(db, walletAddr, targetAddr, true)
	// Terminal not enabled (default).

	err := ValidateSponsoredExecution(db, walletAddr, targetAddr, big.NewInt(1), TerminalApp, TrustHigh)
	if err != ErrSponsorTerminalDisabled {
		t.Fatalf("expected ErrSponsorTerminalDisabled, got %v", err)
	}
}

func TestValidateSponsoredExecution_TrustTooLow(t *testing.T) {
	db := newMockStateDB()

	WriteAllowlisted(db, walletAddr, targetAddr, true)
	WriteTerminalPolicy(db, walletAddr, TerminalApp, TerminalPolicy{
		MaxSingleValue: big.NewInt(10000),
		MaxDailyValue:  big.NewInt(100000),
		MinTrustTier:   TrustHigh,
		Enabled:        true,
	})

	err := ValidateSponsoredExecution(db, walletAddr, targetAddr, big.NewInt(1), TerminalApp, TrustLow)
	if err != ErrSponsorTrustTooLow {
		t.Fatalf("expected ErrSponsorTrustTooLow, got %v", err)
	}
}

func TestValidateSponsoredExecution_ValueExceeded(t *testing.T) {
	db := newMockStateDB()

	WriteAllowlisted(db, walletAddr, targetAddr, true)
	WriteTerminalPolicy(db, walletAddr, TerminalApp, TerminalPolicy{
		MaxSingleValue: big.NewInt(100),
		MaxDailyValue:  big.NewInt(1000),
		MinTrustTier:   TrustLow,
		Enabled:        true,
	})

	err := ValidateSponsoredExecution(db, walletAddr, targetAddr, big.NewInt(500), TerminalApp, TrustMedium)
	if err != ErrSponsorValueExceeded {
		t.Fatalf("expected ErrSponsorValueExceeded, got %v", err)
	}
}

func TestDefaultPrivacyTerminalPolicies(t *testing.T) {
	defaults := DefaultPrivacyTerminalPolicies()
	if len(defaults) != 7 {
		t.Fatalf("expected 7 default policies, got %d", len(defaults))
	}
	// Voice terminal should disallow all privacy actions.
	voice := defaults[TerminalVoice]
	if voice.AllowShield || voice.AllowUnshield || voice.AllowPrivTransfer {
		t.Error("voice terminal should disallow all privacy actions")
	}
	// App terminal should allow all.
	app := defaults[TerminalApp]
	if !app.AllowShield || !app.AllowUnshield || !app.AllowPrivTransfer {
		t.Error("app terminal should allow all privacy actions")
	}
}
