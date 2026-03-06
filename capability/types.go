// Package capability implements the Agent-Native capability registry.
package capability

import "errors"

// Sentinel errors returned by capability system action handlers.
var (
	ErrCapabilityNameExists = errors.New("capability: name already registered")
	ErrCapabilityBitFull    = errors.New("capability: all 256 bits allocated")
	ErrCapabilityRegistrar  = errors.New("capability: Registrar capability required")
	ErrCapabilityNotFound   = errors.New("capability: name not registered")
)
