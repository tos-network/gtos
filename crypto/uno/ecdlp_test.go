//go:build cgo && ed25519c

package uno

import (
	"bytes"
	"testing"
)

// TestSolveDiscreteLogRoundTrip encrypts an amount, decrypts to a point,
// then verifies SolveDiscreteLog recovers the original amount.
func TestSolveDiscreteLogRoundTrip(t *testing.T) {
	priv := bytes.Repeat([]byte{3}, 32)
	pub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}

	amounts := []uint64{0, 1, 100, 65535, 65536, 1_000_000}
	const maxAmount = uint64(2_000_000)

	for _, amount := range amounts {
		amount := amount
		t.Run("", func(t *testing.T) {
			ct, err := Encrypt(pub, amount)
			if err != nil {
				t.Fatalf("Encrypt(%d): %v", amount, err)
			}
			msgPoint, err := DecryptToPoint(priv, ct)
			if err != nil {
				t.Fatalf("DecryptToPoint(%d): %v", amount, err)
			}
			got, found, err := SolveDiscreteLog(msgPoint, maxAmount)
			if err != nil {
				t.Fatalf("SolveDiscreteLog(%d): %v", amount, err)
			}
			if !found {
				t.Fatalf("SolveDiscreteLog(%d): not found within maxAmount=%d", amount, maxAmount)
			}
			if got != amount {
				t.Fatalf("SolveDiscreteLog(%d): got %d", amount, got)
			}
		})
	}
}

// TestSolveDiscreteLogExceedsMax verifies that an amount above maxAmount returns found=false.
func TestSolveDiscreteLogExceedsMax(t *testing.T) {
	priv := bytes.Repeat([]byte{5}, 32)
	pub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}

	const actualAmount = uint64(10_000)
	const maxAmount = uint64(9_999)

	ct, err := Encrypt(pub, actualAmount)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	msgPoint, err := DecryptToPoint(priv, ct)
	if err != nil {
		t.Fatalf("DecryptToPoint: %v", err)
	}
	_, found, err := SolveDiscreteLog(msgPoint, maxAmount)
	if err != nil {
		t.Fatalf("SolveDiscreteLog: unexpected error %v", err)
	}
	if found {
		t.Fatal("expected found=false for amount > maxAmount")
	}
}

// TestSolveDiscreteLogBadInput verifies error handling for invalid msgPoint length.
func TestSolveDiscreteLogBadInput(t *testing.T) {
	_, _, err := SolveDiscreteLog(make([]byte, 31), 100)
	if err == nil {
		t.Fatal("expected error for 31-byte msgPoint")
	}
	_, _, err = SolveDiscreteLog(make([]byte, 33), 100)
	if err == nil {
		t.Fatal("expected error for 33-byte msgPoint")
	}
}
