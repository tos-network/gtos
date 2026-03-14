package lease

import (
	"errors"
	"math/big"

	"github.com/tos-network/gtos/common"
)

// Status is the runtime lifecycle state of a lease contract.
type Status uint8

const (
	StatusActive Status = iota + 1
	StatusFrozen
	StatusExpired
	StatusPrunable
)

// Meta is the protocol-native metadata tracked for a lease contract.
type Meta struct {
	LeaseOwner          common.Address
	CreatedAtBlock      uint64
	ExpireAtBlock       uint64
	GraceUntilBlock     uint64
	CodeBytes           uint64
	DepositWei          *big.Int
	ScheduledPruneEpoch uint64
	ScheduledPruneSeq   uint64
}

// Tombstone permanently marks a previously-pruned lease address.
type Tombstone struct {
	LastCodeHash   common.Hash
	ExpiredAtBlock uint64
}

// DeployAction is the system-action payload for LEASE_DEPLOY.
type DeployAction struct {
	Code        []byte         `json:"code"`
	LeaseBlocks uint64         `json:"lease_blocks"`
	LeaseOwner  common.Address `json:"lease_owner"`
}

// RenewAction is the system-action payload for LEASE_RENEW.
type RenewAction struct {
	ContractAddr common.Address `json:"contract_addr"`
	DeltaBlocks  uint64         `json:"delta_blocks"`
}

// CloseAction is the system-action payload for LEASE_CLOSE.
type CloseAction struct {
	ContractAddr common.Address `json:"contract_addr"`
}

var (
	ErrLeaseCodeRequired        = errors.New("lease: code is required")
	ErrLeaseInvalidBlocks       = errors.New("lease: invalid lease blocks")
	ErrLeaseOwnerRequired       = errors.New("lease: lease owner is required")
	ErrLeaseOwnerMustBeEOA      = errors.New("lease: lease owner must be an EOA")
	ErrLeaseNotFound            = errors.New("lease: contract is not a lease contract")
	ErrLeaseOwnerOnly           = errors.New("lease: only the lease owner may manage the contract")
	ErrLeaseFrozen              = errors.New("lease: contract is frozen")
	ErrLeaseExpired             = errors.New("lease: contract is expired")
	ErrLeaseTombstoned          = errors.New("lease: address is tombstoned")
	ErrLeaseValueNotAllowed     = errors.New("lease: non-zero tx value is not allowed for this action")
	ErrLeaseInsufficientDeposit = errors.New("lease: insufficient balance for deposit")
	ErrLeaseRegistryInvariant   = errors.New("lease: registry balance invariant violated")
)
