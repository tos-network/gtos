package uno

import "errors"

var (
	// ErrInvalidPayload indicates malformed UNO payload bytes.
	ErrInvalidPayload = errors.New("uno: invalid payload")

	// ErrUnsupportedAction indicates unknown UNO action IDs.
	ErrUnsupportedAction = errors.New("uno: unsupported action")

	// ErrSignerNotConfigured indicates sender/receiver has no configured account signer.
	ErrSignerNotConfigured = errors.New("uno: signer not configured")

	// ErrSignerTypeMismatch indicates account signer exists but is not elgamal.
	ErrSignerTypeMismatch = errors.New("uno: signer type must be elgamal")

	// ErrVersionOverflow indicates account uno version cannot be incremented.
	ErrVersionOverflow = errors.New("uno: version overflow")

	// ErrProofNotImplemented blocks execution until proof verification is wired.
	ErrProofNotImplemented = errors.New("uno: proof verification not implemented")
)
