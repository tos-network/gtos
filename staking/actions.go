package staking

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/params"
)

// Stake records a self-stake from a node operator.
// amount is the value attached to the NODE_STAKE transaction (already transferred
// to params.StakingAddress by state_transition.go before this call).
func Stake(db vm.StateDB, node common.Address, amount *big.Int, commissionBPS uint64) error {
	if amount == nil || amount.Sign() <= 0 {
		return errors.New("stake amount must be positive")
	}
	if commissionBPS > params.MaxCommissionBPS {
		return fmt.Errorf("commission %d bps exceeds maximum %d", commissionBPS, params.MaxCommissionBPS)
	}

	selfStake := getSelfStake(db, node)

	// Commission can only be set on first stake.
	if selfStake.Sign() == 0 {
		setCommissionBPS(db, node, uint16(commissionBPS))
	}

	newSelf := new(big.Int).Add(selfStake, amount)
	newTotal := new(big.Int).Add(getTotalStake(db, node), amount)
	setSelfStake(db, node, newSelf)
	setTotalStake(db, node, newTotal)
	addTotalNetworkStake(db, amount)

	// Activate if now at or above the minimum.
	if getNodeStatus(db, node) == NodeStatusInactive && newSelf.Cmp(params.MinNodeStake) >= 0 {
		setNodeStatus(db, node, NodeStatusActive)
	}
	return nil
}

// Unstake initiates withdrawal of amount from the operator's self-stake.
// If amount is nil or zero, the entire self-stake is removed.
// Funds are returned immediately in this MVP; lock-period enforcement is future work.
func Unstake(db vm.StateDB, node common.Address, amount *big.Int, currentBlock uint64) error {
	selfStake := getSelfStake(db, node)
	if selfStake.Sign() == 0 {
		return errors.New("no stake to unstake")
	}

	remove := amount
	if remove == nil || remove.Sign() == 0 || remove.Cmp(selfStake) > 0 {
		remove = new(big.Int).Set(selfStake)
	}

	newSelf := new(big.Int).Sub(selfStake, remove)
	newTotal := new(big.Int).Sub(getTotalStake(db, node), remove)
	if newTotal.Sign() < 0 {
		newTotal = new(big.Int)
	}
	setSelfStake(db, node, newSelf)
	setTotalStake(db, node, newTotal)
	subTotalNetworkStake(db, remove)

	// Mark lock period (even though funds return immediately in MVP).
	setUnstakeUnlockBlock(db, node, currentBlock+params.UnstakeLockBlocks)

	if getNodeStatus(db, node) == NodeStatusActive && newSelf.Cmp(params.MinNodeStake) < 0 {
		setNodeStatus(db, node, NodeStatusInactive)
	}

	// Return funds to operator.
	db.AddBalance(node, remove)
	return nil
}

// Delegate records a delegation from delegator to node.
// amount is the value transferred in the transaction (already moved to
// params.StakingAddress by state_transition.go).
func Delegate(db vm.StateDB, delegator, node common.Address, amount *big.Int) error {
	if amount == nil || amount.Sign() <= 0 {
		return errors.New("delegation amount must be positive")
	}

	// Shares are issued 1:1 with wei (no share price in phase 1).
	currentShares := getDelegationShares(db, delegator, node)

	// Snapshot rewardPerShare for new delegators.
	if currentShares.Sign() == 0 {
		rps := getRewardPerShare(db, node)
		setRewardDebt(db, delegator, node, rps)
	}

	setDelegationShares(db, delegator, node, new(big.Int).Add(currentShares, amount))
	setTotalStake(db, node, new(big.Int).Add(getTotalStake(db, node), amount))
	addTotalNetworkStake(db, amount)
	return nil
}

// Undelegate removes delegation shares and returns funds to delegator.
// sharesWei == nil or zero means remove all shares.
func Undelegate(db vm.StateDB, delegator, node common.Address, sharesWei *big.Int, currentBlock uint64) error {
	currentShares := getDelegationShares(db, delegator, node)
	if currentShares.Sign() == 0 {
		return errors.New("no delegation to undelegate")
	}

	// Settle accrued rewards first.
	settleDelegatorReward(db, delegator, node)

	remove := sharesWei
	if remove == nil || remove.Sign() == 0 || remove.Cmp(currentShares) > 0 {
		remove = new(big.Int).Set(currentShares)
	}

	setDelegationShares(db, delegator, node, new(big.Int).Sub(currentShares, remove))
	newTotal := new(big.Int).Sub(getTotalStake(db, node), remove)
	if newTotal.Sign() < 0 {
		newTotal = new(big.Int)
	}
	setTotalStake(db, node, newTotal)
	subTotalNetworkStake(db, remove)

	setUndelegateUnlockBlock(db, delegator, node, currentBlock+params.UnstakeLockBlocks)

	// Return funds immediately (lock period is noted but not enforced in MVP).
	db.AddBalance(delegator, remove)
	return nil
}

// ClaimReward pays out pending rewards for addr.
// If nodeAddr is non-nil, first settles delegation earnings for that node.
func ClaimReward(db vm.StateDB, addr common.Address, nodeAddr *common.Address) error {
	if nodeAddr != nil {
		settleDelegatorReward(db, addr, *nodeAddr)
	}

	pending := getPendingReward(db, addr)
	if pending.Sign() <= 0 {
		return nil
	}
	clearPendingReward(db, addr)
	db.AddBalance(addr, pending)
	return nil
}

// settleDelegatorReward moves accrued delegation earnings into pendingReward.
func settleDelegatorReward(db vm.StateDB, delegator, node common.Address) {
	shares := getDelegationShares(db, delegator, node)
	if shares.Sign() == 0 {
		return
	}
	rps := getRewardPerShare(db, node)
	debt := getRewardDebt(db, delegator, node)
	diff := new(big.Int).Sub(rps, debt)
	if diff.Sign() <= 0 {
		return
	}
	earned := new(big.Int).Mul(shares, diff)
	earned.Div(earned, RewardPrecision)
	if earned.Sign() > 0 {
		addPendingReward(db, delegator, earned)
	}
	setRewardDebt(db, delegator, node, new(big.Int).Set(rps))
}
