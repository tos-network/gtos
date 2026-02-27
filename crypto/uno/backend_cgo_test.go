//go:build cgo && ed25519c

package uno

import (
	"bytes"
	"encoding/hex"
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

func TestDeterministicVectorsWithOpening(t *testing.T) {
	tests := []struct {
		name          string
		privHex       string
		openingHex    string
		amount        uint64
		wantPubHex    string
		wantComHex    string
		wantHandleHex string
		wantCtHex     string
	}{
		{
			name:          "v1_small",
			privHex:       "0700000000000000000000000000000000000000000000000000000000000000",
			openingHex:    "0100000000000000000000000000000000000000000000000000000000000000",
			amount:        9,
			wantPubHex:    "c236d1e09a12adc6dc4b857420e7dbef41e4553cc06168495b941398bee59531",
			wantComHex:    "485a24569a15c2abc6d5b0703e281a8b3410a0a43a99740827dc644a399b2234",
			wantHandleHex: "c236d1e09a12adc6dc4b857420e7dbef41e4553cc06168495b941398bee59531",
			wantCtHex:     "485a24569a15c2abc6d5b0703e281a8b3410a0a43a99740827dc644a399b2234c236d1e09a12adc6dc4b857420e7dbef41e4553cc06168495b941398bee59531",
		},
		{
			name:          "v2_medium",
			privHex:       "2a00000000000000000000000000000000000000000000000000000000000000",
			openingHex:    "0500000000000000000000000000000000000000000000000000000000000000",
			amount:        123456,
			wantPubHex:    "a669f6823d30d946754e8876ef9176f2687653b0346dea026d1347f19756ac4d",
			wantComHex:    "fcc46ed0de317fc075efd3f9f38beaf7d0cd3c44da2ad2f8b3ec44d6fce25f3f",
			wantHandleHex: "d22a6b009c78a404981d98e3fff81308dc62389d0e97aade7456f22f16029454",
			wantCtHex:     "fcc46ed0de317fc075efd3f9f38beaf7d0cd3c44da2ad2f8b3ec44d6fce25f3fd22a6b009c78a404981d98e3fff81308dc62389d0e97aade7456f22f16029454",
		},
	}

	mustDecode := func(h string) []byte {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatalf("decode hex %q: %v", h, err)
		}
		return b
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			priv := mustDecode(tc.privHex)
			opening := mustDecode(tc.openingHex)

			pub, err := PublicKeyFromPrivate(priv)
			if err != nil {
				t.Fatalf("PublicKeyFromPrivate: %v", err)
			}
			if !bytes.Equal(pub, mustDecode(tc.wantPubHex)) {
				t.Fatalf("pub mismatch: got=%x want=%s", pub, tc.wantPubHex)
			}

			commitment, err := PedersenCommitmentWithOpening(opening, tc.amount)
			if err != nil {
				t.Fatalf("PedersenCommitmentWithOpening: %v", err)
			}
			if !bytes.Equal(commitment, mustDecode(tc.wantComHex)) {
				t.Fatalf("commitment mismatch: got=%x want=%s", commitment, tc.wantComHex)
			}

			handle, err := DecryptHandleWithOpening(pub, opening)
			if err != nil {
				t.Fatalf("DecryptHandleWithOpening: %v", err)
			}
			if !bytes.Equal(handle, mustDecode(tc.wantHandleHex)) {
				t.Fatalf("handle mismatch: got=%x want=%s", handle, tc.wantHandleHex)
			}

			ct, err := EncryptWithOpening(pub, tc.amount, opening)
			if err != nil {
				t.Fatalf("EncryptWithOpening: %v", err)
			}
			if !bytes.Equal(ct, mustDecode(tc.wantCtHex)) {
				t.Fatalf("ciphertext mismatch: got=%x want=%s", ct, tc.wantCtHex)
			}
		})
	}
}
