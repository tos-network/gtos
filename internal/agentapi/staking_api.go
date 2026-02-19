package agentapi

import (
	"context"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/staking"
)

// StakingAPI implements the staking_* RPC namespace.
type StakingAPI struct {
	db vm.StateDB
}

// NewStakingAPI creates a StakingAPI backed by the given StateDB.
// The passed db should be a read-only snapshot of the current state.
func NewStakingAPI(db vm.StateDB) *StakingAPI {
	return &StakingAPI{db: db}
}

// NodeInfo returns the staking state for a node operator address.
func (s *StakingAPI) NodeInfo(_ context.Context, nodeAddr common.Address) staking.NodeRecord {
	return staking.ReadNodeRecord(s.db, nodeAddr)
}

// Delegation returns the delegation state for a delegator→node pair.
func (s *StakingAPI) Delegation(_ context.Context, delegator, node common.Address) staking.DelegationRecord {
	return staking.ReadDelegation(s.db, delegator, node)
}

// PendingReward returns the unclaimed reward balance for addr.
func (s *StakingAPI) PendingReward(_ context.Context, addr common.Address) *big.Int {
	return staking.GetPendingReward(s.db, addr)
}

// DelegatorReward returns how much delegation reward addr can claim from node.
func (s *StakingAPI) DelegatorReward(_ context.Context, delegator, node common.Address) *big.Int {
	return staking.PendingDelegatorReward(s.db, delegator, node)
}

// TotalNetworkStake returns the sum of all staked TOS.
func (s *StakingAPI) TotalNetworkStake(_ context.Context) *big.Int {
	return staking.GetTotalNetworkStake(s.db)
}
