// Package registry implements the GTOS protocol registries for capabilities
// and delegations as defined in GTOS_PROTOCOL_REGISTRIES.md.
package registry

import (
	"errors"

	"github.com/tos-network/gtos/common"
)

// CapabilityStatus represents the lifecycle state of a registered capability.
type CapabilityStatus uint8

const (
	CapActive     CapabilityStatus = 0
	CapDeprecated CapabilityStatus = 1
	CapRevoked    CapabilityStatus = 2
)

// CapabilityRecord is a protocol-level capability entry.
type CapabilityRecord struct {
	Name        string
	BitIndex    uint16
	Category    uint16
	Version     uint32
	Status      CapabilityStatus
	ManifestRef [32]byte
}

// DelegationStatus represents the lifecycle state of a delegation.
type DelegationStatus uint8

const (
	DelActive  DelegationStatus = 0
	DelRevoked DelegationStatus = 1
	DelExpired DelegationStatus = 2
)

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
}

// Sentinel errors returned by registry handlers.
var (
	ErrCapabilityAlreadyRegistered = errors.New("registry: capability already registered")
	ErrCapabilityNotFound          = errors.New("registry: capability not found")
	ErrCapabilityAlreadyRevoked    = errors.New("registry: capability already revoked")
	ErrDelegationNotFound          = errors.New("registry: delegation not found")
	ErrDelegationAlreadyRevoked    = errors.New("registry: delegation already revoked")
	ErrDelegationExpired           = errors.New("registry: delegation expired")
	ErrInvalidCapabilityName       = errors.New("registry: invalid capability name")
	ErrInvalidDelegation           = errors.New("registry: invalid delegation parameters")
)
