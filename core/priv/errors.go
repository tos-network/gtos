package priv

import "errors"

var (
	// ErrInvalidPayload indicates malformed priv payload bytes.
	ErrInvalidPayload = errors.New("priv: invalid payload")

	// ErrUnsupportedAction indicates unknown priv action IDs.
	ErrUnsupportedAction = errors.New("priv: unsupported action")

	// ErrSignerNotConfigured indicates sender/receiver has no configured account signer.
	ErrSignerNotConfigured = errors.New("priv: signer not configured")

	// ErrSignerTypeMismatch indicates account signer exists but is not elgamal.
	ErrSignerTypeMismatch = errors.New("priv: signer type must be elgamal")

	// ErrVersionOverflow indicates account priv version cannot be incremented.
	ErrVersionOverflow = errors.New("priv: version overflow")

	// ErrNonceOverflow indicates account priv nonce cannot be incremented.
	ErrNonceOverflow = errors.New("priv: nonce overflow")

	// ErrProofNotImplemented blocks execution until proof verification is wired.
	ErrProofNotImplemented = errors.New("priv: proof verification not implemented")

	// ErrInsufficientFee indicates the provided fee is below the required minimum.
	ErrInsufficientFee = errors.New("priv: insufficient fee")

	// ErrFeeLimitExceeded indicates the declared fee exceeds the sender's fee limit.
	ErrFeeLimitExceeded = errors.New("priv: fee exceeds fee limit")

	// ErrNonceMismatch indicates the transaction nonce does not match the account nonce.
	ErrNonceMismatch = errors.New("priv: nonce mismatch")
)
