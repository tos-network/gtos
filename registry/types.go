// Package registry implements the GTOS protocol registries for capabilities
// and delegations as defined in GTOS_PROTOCOL_REGISTRIES.md.
package registry

import (
	"errors"

	"github.com/tos-network/gtos/common"
)

// GovernorCapabilityBit is the protocol governor override bit for registry
// actions. v1.1 reuses the well-known Registrar capability bit.
const GovernorCapabilityBit uint8 = 0

// CapabilityStatus represents the lifecycle state of a registered capability.
type CapabilityStatus uint8

const (
	CapActive     CapabilityStatus = 0
	CapDeprecated CapabilityStatus = 1
	CapRevoked    CapabilityStatus = 2
)

func (s CapabilityStatus) String() string {
	switch s {
	case CapDeprecated:
		return "deprecated"
	case CapRevoked:
		return "revoked"
	default:
		return "active"
	}
}

func (s CapabilityStatus) CanTransitionTo(next CapabilityStatus) bool {
	switch s {
	case CapActive:
		return next == CapDeprecated || next == CapRevoked
	case CapDeprecated:
		return next == CapRevoked
	default:
		return false
	}
}

// CapabilityRecord is a protocol-level capability entry.
type CapabilityRecord struct {
	Owner       common.Address
	Name        string
	BitIndex    uint16
	Category    uint16
	Version     uint32
	Status      CapabilityStatus
	ManifestRef [32]byte
	CreatedAt   uint64
	UpdatedAt   uint64
}

// DelegationStatus represents the lifecycle state of a delegation.
type DelegationStatus uint8

const (
	DelActive  DelegationStatus = 0
	DelRevoked DelegationStatus = 1
	DelExpired DelegationStatus = 2
)

func (s DelegationStatus) String() string {
	switch s {
	case DelRevoked:
		return "revoked"
	case DelExpired:
		return "expired"
	default:
		return "active"
	}
}

// DelegationRecord is a protocol-level delegation entry.
type DelegationRecord struct {
	Principal     common.Address
	Delegate      common.Address
	ScopeRef      [32]byte
	CapabilityRef [32]byte
	PolicyRef     [32]byte
	NotBeforeMS   uint64
	ExpiryMS      uint64
	Status        DelegationStatus
	CreatedAt     uint64
	UpdatedAt     uint64
}

func (r DelegationRecord) EffectiveStatus(nowMS uint64) DelegationStatus {
	switch r.Status {
	case DelRevoked, DelExpired:
		return r.Status
	default:
		if r.NotBeforeMS > 0 && nowMS < r.NotBeforeMS {
			return DelActive
		}
		if r.ExpiryMS > 0 && nowMS >= r.ExpiryMS {
			return DelExpired
		}
		return DelActive
	}
}

// Sentinel errors returned by registry handlers.
var (
	ErrCapabilityAlreadyRegistered = errors.New("registry: capability already registered")
	ErrCapabilityNotFound          = errors.New("registry: capability not found")
	ErrCapabilityAlreadyDeprecated = errors.New("registry: capability already deprecated")
	ErrCapabilityAlreadyRevoked    = errors.New("registry: capability already revoked")
	ErrUnauthorizedCapability      = errors.New("registry: sender is not capability owner or governor")
	ErrDelegationNotFound          = errors.New("registry: delegation not found")
	ErrDelegationAlreadyRevoked    = errors.New("registry: delegation already revoked")
	ErrDelegationExpired           = errors.New("registry: delegation expired")
	ErrInvalidDelegationWindow     = errors.New("registry: invalid delegation time window")
	ErrInvalidCapabilityName       = errors.New("registry: invalid capability name")
	ErrInvalidDelegation           = errors.New("registry: invalid delegation parameters")
	ErrUnauthorizedDelegation      = errors.New("registry: sender is not delegation principal or governor")
)
