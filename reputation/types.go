// Package reputation implements the Agent-Native reputation hub.
package reputation

import "errors"

// Sentinel errors returned by reputation system action handlers.
var (
	ErrNotAuthorizedScorer  = errors.New("reputation: caller is not an authorized scorer")
	ErrRegistrarRequired    = errors.New("reputation: Registrar capability required")
	ErrInvalidDelta         = errors.New("reputation: invalid delta value")
)
