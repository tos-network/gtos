package paypolicy

import (
	"errors"
	"math/big"

	"github.com/tos-network/gtos/common"
)

type PolicyStatus uint8

const (
	PolicyActive  PolicyStatus = 0
	PolicyRevoked PolicyStatus = 1
)

type PolicyRecord struct {
	PolicyID  [32]byte
	Kind      uint16
	Owner     common.Address
	Asset     string
	MaxAmount *big.Int
	RulesRef  [32]byte
	Status    PolicyStatus
	CreatedAt uint64
	UpdatedAt uint64
	UpdatedBy common.Address
	StatusRef [32]byte
}

var (
	ErrPolicyExists         = errors.New("paypolicy: policy already registered")
	ErrPolicyNotFound       = errors.New("paypolicy: policy not found")
	ErrPolicyAlreadyRevoked = errors.New("paypolicy: policy already revoked")
	ErrInvalidPolicy        = errors.New("paypolicy: invalid policy payload")
	ErrUnauthorizedOwner    = errors.New("paypolicy: sender is not policy owner")
)
