package staking

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

// --- slot derivation ---

func stakingSlot(addr common.Address, field string) common.Hash {
	key := append(addr.Bytes(), []byte(field)...)
	return common.BytesToHash(crypto.Keccak256(key))
}

func delegationSlot(delegator, node common.Address, field string) common.Hash {
	key := append(delegator.Bytes(), node.Bytes()...)
	key = append(key, []byte(field)...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// --- node state ---

func getSelfStake(db vm.StateDB, node common.Address) *big.Int {
	return db.GetState(params.StakingAddress, stakingSlot(node, "selfStake")).Big()
}

func setSelfStake(db vm.StateDB, node common.Address, amount *big.Int) {
	db.SetState(params.StakingAddress, stakingSlot(node, "selfStake"), common.BigToHash(amount))
}

func getTotalStake(db vm.StateDB, node common.Address) *big.Int {
	return db.GetState(params.StakingAddress, stakingSlot(node, "totalStake")).Big()
}

func setTotalStake(db vm.StateDB, node common.Address, amount *big.Int) {
	db.SetState(params.StakingAddress, stakingSlot(node, "totalStake"), common.BigToHash(amount))
}

func getCommissionBPS(db vm.StateDB, node common.Address) uint16 {
	return uint16(db.GetState(params.StakingAddress, stakingSlot(node, "commission")).Big().Uint64())
}

func setCommissionBPS(db vm.StateDB, node common.Address, bps uint16) {
	db.SetState(params.StakingAddress, stakingSlot(node, "commission"),
		common.BigToHash(new(big.Int).SetUint64(uint64(bps))))
}

func getNodeStatus(db vm.StateDB, node common.Address) NodeStatus {
	return NodeStatus(db.GetState(params.StakingAddress, stakingSlot(node, "status")).Big().Uint64())
}

func setNodeStatus(db vm.StateDB, node common.Address, s NodeStatus) {
	db.SetState(params.StakingAddress, stakingSlot(node, "status"),
		common.BigToHash(new(big.Int).SetUint64(uint64(s))))
}

func getRewardPerShare(db vm.StateDB, node common.Address) *big.Int {
	return db.GetState(params.StakingAddress, stakingSlot(node, "rewardPerShare")).Big()
}

func setRewardPerShare(db vm.StateDB, node common.Address, rps *big.Int) {
	db.SetState(params.StakingAddress, stakingSlot(node, "rewardPerShare"), common.BigToHash(rps))
}

func getPendingReward(db vm.StateDB, addr common.Address) *big.Int {
	return db.GetState(params.StakingAddress, stakingSlot(addr, "pendingReward")).Big()
}

func addPendingReward(db vm.StateDB, addr common.Address, delta *big.Int) {
	cur := getPendingReward(db, addr)
	db.SetState(params.StakingAddress, stakingSlot(addr, "pendingReward"),
		common.BigToHash(new(big.Int).Add(cur, delta)))
}

func clearPendingReward(db vm.StateDB, addr common.Address) {
	db.SetState(params.StakingAddress, stakingSlot(addr, "pendingReward"), common.Hash{})
}

func setUnstakeUnlockBlock(db vm.StateDB, node common.Address, blockNum uint64) {
	db.SetState(params.StakingAddress, stakingSlot(node, "unstakeUnlock"),
		common.BigToHash(new(big.Int).SetUint64(blockNum)))
}

// --- delegation state ---

func getDelegationShares(db vm.StateDB, delegator, node common.Address) *big.Int {
	return db.GetState(params.StakingAddress, delegationSlot(delegator, node, "shares")).Big()
}

func setDelegationShares(db vm.StateDB, delegator, node common.Address, shares *big.Int) {
	db.SetState(params.StakingAddress, delegationSlot(delegator, node, "shares"), common.BigToHash(shares))
}

func getRewardDebt(db vm.StateDB, delegator, node common.Address) *big.Int {
	return db.GetState(params.StakingAddress, delegationSlot(delegator, node, "rewardDebt")).Big()
}

func setRewardDebt(db vm.StateDB, delegator, node common.Address, debt *big.Int) {
	db.SetState(params.StakingAddress, delegationSlot(delegator, node, "rewardDebt"), common.BigToHash(debt))
}

func setUndelegateUnlockBlock(db vm.StateDB, delegator, node common.Address, blockNum uint64) {
	db.SetState(params.StakingAddress, delegationSlot(delegator, node, "undelegateUnlock"),
		common.BigToHash(new(big.Int).SetUint64(blockNum)))
}

// --- network-wide total stake ---

var zeroAddr = common.Address{}

func getTotalNetworkStake(db vm.StateDB) *big.Int {
	return db.GetState(params.StakingAddress, stakingSlot(zeroAddr, "networkStake")).Big()
}

func addTotalNetworkStake(db vm.StateDB, delta *big.Int) {
	cur := getTotalNetworkStake(db)
	db.SetState(params.StakingAddress, stakingSlot(zeroAddr, "networkStake"),
		common.BigToHash(new(big.Int).Add(cur, delta)))
}

func subTotalNetworkStake(db vm.StateDB, delta *big.Int) {
	cur := getTotalNetworkStake(db)
	result := new(big.Int).Sub(cur, delta)
	if result.Sign() < 0 {
		result = new(big.Int)
	}
	db.SetState(params.StakingAddress, stakingSlot(zeroAddr, "networkStake"),
		common.BigToHash(result))
}

// ReadNodeRecord reads the complete NodeRecord for a node from the StateDB.
func ReadNodeRecord(db vm.StateDB, node common.Address) NodeRecord {
	return NodeRecord{
		Operator:           node,
		SelfStake:          getSelfStake(db, node),
		TotalStake:         getTotalStake(db, node),
		CommissionBPS:      getCommissionBPS(db, node),
		Status:             getNodeStatus(db, node),
		RewardPerShare:     getRewardPerShare(db, node),
	}
}

// PendingDelegatorReward computes unclaimed reward for a delegator from a node.
func PendingDelegatorReward(db vm.StateDB, delegator, node common.Address) *big.Int {
	shares := getDelegationShares(db, delegator, node)
	if shares.Sign() == 0 {
		return new(big.Int)
	}
	rps := getRewardPerShare(db, node)
	debt := getRewardDebt(db, delegator, node)
	diff := new(big.Int).Sub(rps, debt)
	if diff.Sign() <= 0 {
		return new(big.Int)
	}
	pending := new(big.Int).Mul(shares, diff)
	pending.Div(pending, RewardPrecision)
	return pending
}

// ReadDelegation reads one delegation record from the StateDB.
func ReadDelegation(db vm.StateDB, delegator, node common.Address) DelegationRecord {
	return DelegationRecord{
		Delegator:             delegator,
		Node:                  node,
		Shares:                getDelegationShares(db, delegator, node),
		RewardDebt:            getRewardDebt(db, delegator, node),
	}
}

// GetPendingReward returns the total pending reward for addr (operator commissions).
func GetPendingReward(db vm.StateDB, addr common.Address) *big.Int {
	return getPendingReward(db, addr)
}

// GetTotalNetworkStake returns the sum of all active stakes across all nodes.
func GetTotalNetworkStake(db vm.StateDB) *big.Int {
	return getTotalNetworkStake(db)
}
