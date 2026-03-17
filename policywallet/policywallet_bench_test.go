package policywallet

import (
	"math/big"
	"testing"
)

func BenchmarkWriteReadSpendCaps(b *testing.B) {
	db := newMockStateDB()
	daily := big.NewInt(10_000_000)
	single := big.NewInt(1_000_000)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		WriteDailyLimit(db, walletAddr, daily)
		WriteSingleTxLimit(db, walletAddr, single)
		_ = ReadDailyLimit(db, walletAddr)
		_ = ReadSingleTxLimit(db, walletAddr)
	}
}

func BenchmarkWriteReadTerminalPolicy(b *testing.B) {
	db := newMockStateDB()
	tp := TerminalPolicy{
		MaxSingleValue: big.NewInt(50_000),
		MaxDailyValue:  big.NewInt(500_000),
		MinTrustTier:   TrustMedium,
		Enabled:        true,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		WriteTerminalPolicy(db, walletAddr, TerminalApp, tp)
		_ = ReadTerminalPolicy(db, walletAddr, TerminalApp)
	}
}

func BenchmarkValidateSponsoredExecution(b *testing.B) {
	db := newMockStateDB()

	// Set up valid state: owner, allowlist sponsor, enable terminal.
	WriteOwner(db, walletAddr, ownerAddr)
	WriteAllowlisted(db, walletAddr, targetAddr, true)
	WriteTerminalPolicy(db, walletAddr, TerminalApp, TerminalPolicy{
		MaxSingleValue: big.NewInt(100_000),
		MaxDailyValue:  big.NewInt(1_000_000),
		MinTrustTier:   TrustLow,
		Enabled:        true,
	})
	value := big.NewInt(5000)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ValidateSponsoredExecution(db, walletAddr, targetAddr, value, TerminalApp, TrustMedium); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidatePrivacyTerminalAccess(b *testing.B) {
	db := newMockStateDB()

	// Set up a permissive privacy terminal policy.
	WritePrivacyTerminalPolicy(db, walletAddr, PrivacyTerminalPolicy{
		TerminalClass:     TerminalApp,
		MaxPrivateValue:   big.NewInt(10_000_000),
		AllowShield:       true,
		AllowUnshield:     true,
		AllowPrivTransfer: true,
		MinTrustTier:      TrustMedium,
	})
	value := big.NewInt(5000)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ValidatePrivacyTerminalAccess(db, walletAddr, TerminalApp, TrustMedium, PrivacyActionShield, value); err != nil {
			b.Fatal(err)
		}
	}
}
