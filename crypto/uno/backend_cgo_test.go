//go:build cgo && ed25519c

package uno

import (
	"bytes"
	"errors"
	"testing"
)

func TestBackendEnabledWithCgo(t *testing.T) {
	if !BackendEnabled() {
		t.Fatal("expected UNO backend enabled with cgo build")
	}
}

func TestElgamalRoundTripOpsWithCgo(t *testing.T) {
	priv := bytes.Repeat([]byte{1}, 32)
	pub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}
	ct5, err := Encrypt(pub, 5)
	if err != nil {
		t.Fatalf("Encrypt(5): %v", err)
	}
	ct3, err := Encrypt(pub, 3)
	if err != nil {
		t.Fatalf("Encrypt(3): %v", err)
	}
	sum, err := AddCompressedCiphertexts(ct5, ct3)
	if err != nil {
		t.Fatalf("AddCompressedCiphertexts: %v", err)
	}
	back, err := SubCompressedCiphertexts(sum, ct3)
	if err != nil {
		t.Fatalf("SubCompressedCiphertexts: %v", err)
	}
	norm5, err := NormalizeCompressed(ct5)
	if err != nil {
		t.Fatalf("NormalizeCompressed(ct5): %v", err)
	}
	normBack, err := NormalizeCompressed(back)
	if err != nil {
		t.Fatalf("NormalizeCompressed(back): %v", err)
	}
	if !bytes.Equal(norm5, normBack) {
		t.Fatal("ct add/sub roundtrip mismatch")
	}

	added, err := AddAmountCompressed(ct5, 2)
	if err != nil {
		t.Fatalf("AddAmountCompressed: %v", err)
	}
	restored, err := SubAmountCompressed(added, 2)
	if err != nil {
		t.Fatalf("SubAmountCompressed: %v", err)
	}
	normRestored, err := NormalizeCompressed(restored)
	if err != nil {
		t.Fatalf("NormalizeCompressed(restored): %v", err)
	}
	if !bytes.Equal(norm5, normRestored) {
		t.Fatal("ct add/sub amount roundtrip mismatch")
	}
}

func TestProofVerifyBackendPathWithCgo(t *testing.T) {
	// Zero bytes are invalid proofs; with cgo path enabled we should not hit backend-unavailable.
	err := VerifyShieldProof(make([]byte, 96), make([]byte, 32), make([]byte, 32), make([]byte, 32), 1)
	if err == nil {
		t.Fatal("expected invalid proof error")
	}
	if errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("unexpected backend unavailable: %v", err)
	}
}

func TestEncryptWithOpeningConsistencyWithCommitmentAndHandle(t *testing.T) {
	priv := make([]byte, 32)
	priv[0] = 7
	pub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}
	opening := make([]byte, 32)
	opening[0] = 1 // canonical scalar value 1

	commitment, err := PedersenCommitmentWithOpening(opening, 9)
	if err != nil {
		t.Fatalf("PedersenCommitmentWithOpening: %v", err)
	}
	handle, err := DecryptHandleWithOpening(pub, opening)
	if err != nil {
		t.Fatalf("DecryptHandleWithOpening: %v", err)
	}
	ct, err := EncryptWithOpening(pub, 9, opening)
	if err != nil {
		t.Fatalf("EncryptWithOpening: %v", err)
	}
	if len(ct) != 64 {
		t.Fatalf("unexpected ciphertext length %d", len(ct))
	}
	if !bytes.Equal(ct[:32], commitment) {
		t.Fatal("ciphertext commitment does not match derived commitment")
	}
	if !bytes.Equal(ct[32:], handle) {
		t.Fatal("ciphertext handle does not match derived decrypt handle")
	}
}
