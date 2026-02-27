package uno

import (
	"errors"
	"testing"
)

func TestShieldVerifyErrorClassByBackendAvailability(t *testing.T) {
	err := VerifyShieldProof(make([]byte, 96), make([]byte, 32), make([]byte, 32), make([]byte, 32), 1)
	if err == nil {
		t.Fatalf("expected verification error")
	}
	if BackendEnabled() {
		if errors.Is(err, ErrBackendUnavailable) {
			t.Fatalf("backend enabled build should not return ErrBackendUnavailable: %v", err)
		}
	} else if !errors.Is(err, ErrBackendUnavailable) && !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("expected ErrBackendUnavailable or ErrInvalidProof, got %v", err)
	}
}

func TestCommitmentEqAndBalanceBackend(t *testing.T) {
	err := VerifyCommitmentEqProof(make([]byte, 192), make([]byte, 32), make([]byte, 64), make([]byte, 32))
	if err != nil && !errors.Is(err, ErrBackendUnavailable) && !errors.Is(err, ErrInvalidProof) && !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("unexpected commitment-eq error: %v", err)
	}
	err = VerifyBalanceProof(make([]byte, 200), make([]byte, 32), make([]byte, 64))
	if err != nil && !errors.Is(err, ErrBackendUnavailable) && !errors.Is(err, ErrInvalidProof) && !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("unexpected balance error: %v", err)
	}

	err = VerifyRangeProof(make([]byte, 1), make([]byte, 32), []byte{64}, 1)
	if err != nil && !errors.Is(err, ErrBackendUnavailable) && !errors.Is(err, ErrInvalidProof) && !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("unexpected rangeproof error: %v", err)
	}
}
