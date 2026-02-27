package uno

import (
	"errors"
	"testing"
)

func TestElgamalCompressedOpsDefaultBuild(t *testing.T) {
	a := make([]byte, 64)
	b := make([]byte, 64)
	out, err := AddCompressedCiphertexts(a, b)
	if err == nil {
		if len(out) != 64 {
			t.Fatalf("expected 64-byte ciphertext, got %d", len(out))
		}
		return
	}
	if !errors.Is(err, ErrBackendUnavailable) && !errors.Is(err, ErrInvalidProof) && !errors.Is(err, ErrInvalidInput) && !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = NormalizeCompressed(a)
	if err != nil && !errors.Is(err, ErrBackendUnavailable) && !errors.Is(err, ErrInvalidProof) && !errors.Is(err, ErrInvalidInput) && !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("unexpected normalize error: %v", err)
	}
	_, err = ZeroCiphertextCompressed()
	if err != nil && !errors.Is(err, ErrBackendUnavailable) && !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("unexpected zero-ciphertext error: %v", err)
	}
	_, err = AddScalarCompressed(a, make([]byte, 32))
	if err != nil && !errors.Is(err, ErrBackendUnavailable) && !errors.Is(err, ErrInvalidInput) && !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("unexpected add-scalar error: %v", err)
	}
	_, err = SubScalarCompressed(a, make([]byte, 32))
	if err != nil && !errors.Is(err, ErrBackendUnavailable) && !errors.Is(err, ErrInvalidInput) && !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("unexpected sub-scalar error: %v", err)
	}
	_, err = MulScalarCompressed(a, make([]byte, 32))
	if err != nil && !errors.Is(err, ErrBackendUnavailable) && !errors.Is(err, ErrInvalidInput) && !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("unexpected mul-scalar error: %v", err)
	}

	priv := make([]byte, 32)
	pub, err := PublicKeyFromPrivate(priv)
	if err == nil {
		if len(pub) != 32 {
			t.Fatalf("expected 32-byte pubkey, got %d", len(pub))
		}
	}
	if err != nil && !errors.Is(err, ErrBackendUnavailable) && !errors.Is(err, ErrInvalidProof) && !errors.Is(err, ErrInvalidInput) && !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("unexpected pubkey derive error: %v", err)
	}

	_, err = Encrypt(make([]byte, 32), 1)
	if err != nil && !errors.Is(err, ErrBackendUnavailable) && !errors.Is(err, ErrInvalidProof) && !errors.Is(err, ErrInvalidInput) && !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("unexpected encrypt error: %v", err)
	}

	_, _, err = CommitmentNew(1)
	if err != nil && !errors.Is(err, ErrBackendUnavailable) && !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("unexpected commitment-new error: %v", err)
	}

	_, err = GenerateOpening()
	if err != nil && !errors.Is(err, ErrBackendUnavailable) && !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("unexpected opening-generate error: %v", err)
	}

	_, _, err = EncryptWithGeneratedOpening(make([]byte, 32), 1)
	if err != nil && !errors.Is(err, ErrBackendUnavailable) && !errors.Is(err, ErrOperationFailed) && !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unexpected encrypt-with-generated-opening error: %v", err)
	}

	_, _, err = GenerateKeypair()
	if err != nil && !errors.Is(err, ErrBackendUnavailable) && !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("unexpected keypair-generate error: %v", err)
	}

	_, err = DecryptToPoint(make([]byte, 32), make([]byte, 64))
	if err != nil && !errors.Is(err, ErrBackendUnavailable) && !errors.Is(err, ErrInvalidProof) && !errors.Is(err, ErrInvalidInput) && !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("unexpected decrypt error: %v", err)
	}

	_, err = PublicKeyToAddress(make([]byte, 32), true)
	if err != nil && !errors.Is(err, ErrBackendUnavailable) && !errors.Is(err, ErrOperationFailed) && !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unexpected publickey-to-address error: %v", err)
	}
}
