package ed25519

import "errors"

var (
	// ErrUNOBackendUnavailable indicates UNO proof verification backend is not enabled.
	ErrUNOBackendUnavailable = errors.New("ed25519: UNO proof backend unavailable")
	// ErrUNOInvalidInput indicates malformed arguments passed to UNO proof verifier.
	ErrUNOInvalidInput = errors.New("ed25519: invalid UNO proof input")
	// ErrUNOInvalidProof indicates UNO proof verification failed.
	ErrUNOInvalidProof = errors.New("ed25519: invalid UNO proof")
	// ErrUNOOperationFailed indicates non-proof UNO crypto operation failed.
	ErrUNOOperationFailed = errors.New("ed25519: UNO crypto operation failed")
)
