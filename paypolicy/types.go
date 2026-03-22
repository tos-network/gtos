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
}

var (
	ErrPolicyExists      = errors.New("paypolicy: policy already registered")
	ErrPolicyNotFound    = errors.New("paypolicy: policy not found")
	ErrInvalidPolicy     = errors.New("paypolicy: invalid policy payload")
	ErrUnauthorizedOwner = errors.New("paypolicy: sender is not policy owner")
)
