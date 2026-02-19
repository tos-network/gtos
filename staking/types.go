package staking

import (
	"math/big"

	"github.com/tos-network/gtos/common"
)

// NodeStatus represents the lifecycle state of a staking node.
type NodeStatus uint8

const (
	NodeStatusInactive NodeStatus = 0
	NodeStatusActive   NodeStatus = 1
	NodeStatusJailed   NodeStatus = 2
	NodeStatusExiting  NodeStatus = 3
)

// NodeRecord is the in-memory view of a node staking state read from StateDB.
type NodeRecord struct {
	Operator           common.Address
	SelfStake          *big.Int
	TotalStake         *big.Int
	CommissionBPS      uint16
	Status             NodeStatus
	RewardPerShare     *big.Int
	UnstakeUnlockBlock uint64
}

// DelegationRecord tracks one delegator->node relationship.
type DelegationRecord struct {
	Delegator              common.Address
	Node                   common.Address
	Shares                 *big.Int
	RewardDebt             *big.Int
	UndelegateUnlockBlock  uint64
}

// RewardPrecision is the fixed-point scale for RewardPerShare.
var RewardPrecision = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
