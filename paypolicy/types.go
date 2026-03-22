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

const (
	PolicyKindSponsor       uint16 = 1
	PolicyKindPay           uint16 = 2
	PolicyKindSettlement    uint16 = 3
	PolicyKindRelay         uint16 = 4
	PolicyKindSubscription  uint16 = 5
	PolicyKindMilestone     uint16 = 6
	PolicyKindRefund        uint16 = 7
	PolicyKindEscrowRelease uint16 = 8
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

func PolicyKindName(kind uint16) string {
	switch kind {
	case PolicyKindSponsor:
		return "sponsor"
	case PolicyKindPay:
		return "pay"
	case PolicyKindSettlement:
		return "settlement"
	case PolicyKindRelay:
		return "relay"
	case PolicyKindSubscription:
		return "subscription"
	case PolicyKindMilestone:
		return "milestone"
	case PolicyKindRefund:
		return "refund"
	case PolicyKindEscrowRelease:
		return "escrow_release"
	default:
		return "custom"
	}
}
