package staking

import (
	"fmt"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&stakingHandler{})
}

// stakingHandler implements sysaction.Handler for staking and delegation actions.
type stakingHandler struct{}

func (h *stakingHandler) CanHandle(kind sysaction.ActionKind) bool {
	switch kind {
	case sysaction.ActionNodeRegister,
		sysaction.ActionNodeUpdate,
		sysaction.ActionNodeStake,
		sysaction.ActionNodeUnstake,
		sysaction.ActionDelegate,
		sysaction.ActionUndelegate,
		sysaction.ActionClaimReward:
		return true
	}
	return false
}

func (h *stakingHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	db := ctx.StateDB
	from := ctx.From
	value := ctx.Value
	if value == nil {
		value = new(big.Int)
	}
	var blockNum uint64
	if ctx.BlockNumber != nil {
		blockNum = ctx.BlockNumber.Uint64()
	}

	switch sa.Action {
	case sysaction.ActionNodeRegister, sysaction.ActionNodeUpdate:
		var p sysaction.NodeRegisterPayload
		if err := sysaction.DecodePayload(sa, &p); err != nil {
			return fmt.Errorf("node register: %w", err)
		}
		setCommissionBPS(db, from, p.CommissionBPS)
		if value.Sign() > 0 {
			db.SubBalance(from, value)
			db.AddBalance(stakingContractAddr(), value)
			return Stake(db, from, value, uint64(p.CommissionBPS))
		}
		return nil

	case sysaction.ActionNodeStake:
		if value.Sign() == 0 {
			return fmt.Errorf("NODE_STAKE: tx.Value must be > 0")
		}
		var p sysaction.NodeRegisterPayload
		sysaction.DecodePayload(sa, &p)
		return Stake(db, from, value, uint64(p.CommissionBPS))

	case sysaction.ActionNodeUnstake:
		return Unstake(db, from, nil, blockNum)

	case sysaction.ActionDelegate:
		var p sysaction.DelegatePayload
		if err := sysaction.DecodePayload(sa, &p); err != nil {
			return fmt.Errorf("delegate: %w", err)
		}
		if !common.IsHexAddress(p.NodeAddress) {
			return fmt.Errorf("delegate: invalid node address: %s", p.NodeAddress)
		}
		if value.Sign() == 0 {
			return fmt.Errorf("DELEGATE: tx.Value must be > 0")
		}
		return Delegate(db, from, common.HexToAddress(p.NodeAddress), value)

	case sysaction.ActionUndelegate:
		var p sysaction.UndelegatePayload
		if err := sysaction.DecodePayload(sa, &p); err != nil {
			return fmt.Errorf("undelegate: %w", err)
		}
		if !common.IsHexAddress(p.NodeAddress) {
			return fmt.Errorf("undelegate: invalid node address: %s", p.NodeAddress)
		}
		nodeAddr := common.HexToAddress(p.NodeAddress)
		var sharesWei *big.Int
		if p.Shares != "" {
			sharesWei = new(big.Int)
			if _, ok := sharesWei.SetString(p.Shares, 10); !ok {
				return fmt.Errorf("undelegate: invalid shares: %s", p.Shares)
			}
		}
		return Undelegate(db, from, nodeAddr, sharesWei, blockNum)

	case sysaction.ActionClaimReward:
		return ClaimReward(db, from, nil)
	}
	return fmt.Errorf("staking handler: unsupported action %q", sa.Action)
}

// stakingContractAddr returns the StakingAddress constant without importing params
// (to avoid a potential cycle); the value matches params.StakingAddress.
func stakingContractAddr() common.Address {
	return common.HexToAddress("0x0000000000000000000000000000000054534F33")
}
