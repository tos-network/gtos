// Package delegation implements the Agent-Native delegation nonce registry.
// It provides replay protection for off-chain delegation signatures.
package delegation

import "errors"

// Sentinel errors returned by delegation system action handlers.
var (
	ErrNonceAlreadyUsed    = errors.New("delegation: nonce already used")
	ErrUnauthorizedPrincipal = errors.New("delegation: only principal can consume own nonce")
)
