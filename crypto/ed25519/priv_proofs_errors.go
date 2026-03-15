package ed25519

import "errors"

var (
	// ErrPrivBackendUnavailable indicates priv proof verification backend is not enabled.
	ErrPrivBackendUnavailable = errors.New("ed25519: priv proof backend unavailable")
	// ErrPrivInvalidInput indicates malformed arguments passed to priv proof verifier.
	ErrPrivInvalidInput = errors.New("ed25519: invalid priv proof input")
	// ErrPrivInvalidProof indicates priv proof verification failed.
	ErrPrivInvalidProof = errors.New("ed25519: invalid priv proof")
	// ErrPrivOperationFailed indicates non-proof priv crypto operation failed.
	ErrPrivOperationFailed = errors.New("ed25519: priv crypto operation failed")
	// ErrPrivAuthFailed indicates AEAD authentication failed during decryption.
	ErrPrivAuthFailed = errors.New("ed25519: AEAD authentication failed")
)
