// Package validator implements DPoS validator registration and on-chain state.
package validator

import "errors"

// ValidatorStatus represents the lifecycle state of a validator.
type ValidatorStatus uint8

const (
	// Inactive is the default state; validator has withdrawn or never registered.
	Inactive ValidatorStatus = 0
	// Active means the validator has locked stake and is eligible to produce blocks.
	Active ValidatorStatus = 1
	// Maintenance keeps stake locked but removes the validator from the active
	// producer set until it explicitly exits maintenance.
	Maintenance ValidatorStatus = 2
)

// Sentinel errors returned by system action handlers.
var (
	ErrAlreadyRegistered              = errors.New("validator: already registered")
	ErrNotActive                      = errors.New("validator: not active")
	ErrAlreadyInMaintenance           = errors.New("validator: already in maintenance")
	ErrNotInMaintenance               = errors.New("validator: not in maintenance")
	ErrInsufficientStake              = errors.New("validator: insufficient stake")
	ErrInsufficientBalance            = errors.New("validator: sender balance below stake amount")
	ErrValidatorRegistryBalanceBroken = errors.New("validator: validator registry balance invariant violated")
)
