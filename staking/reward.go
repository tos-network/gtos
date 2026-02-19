package staking

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/log"
	"github.com/tos-network/gtos/params"
)

// DistributeBlockRewards mints params.BlockReward TOS and distributes it
// to active nodes proportionally to their total stake.
//
// Called from consensus/tosash Finalize() after standard uncle reward logic.
// In Phase 1, activeNodes contains only the block coinbase (proposer).
func DistributeBlockRewards(db vm.StateDB, header *types.Header, activeNodes []common.Address) {
	if len(activeNodes) == 0 {
		return
	}

	totalNet := getTotalNetworkStake(db)
	if totalNet.Sign() == 0 {
		return
	}

	blockReward := new(big.Int).Set(params.BlockReward)

	for _, nodeAddr := range activeNodes {
		rec := ReadNodeRecord(db, nodeAddr)
		if rec.Status != NodeStatusActive || rec.TotalStake.Sign() == 0 {
			continue
		}

		// nodeShare = blockReward * nodeTotalStake / totalNetworkStake
		nodeShare := new(big.Int).Mul(blockReward, rec.TotalStake)
		nodeShare.Div(nodeShare, totalNet)
		if nodeShare.Sign() == 0 {
			continue
		}

		// commissionPart = nodeShare * commissionBPS / 10000
		commission := new(big.Int).Mul(nodeShare, new(big.Int).SetUint64(uint64(rec.CommissionBPS)))
		commission.Div(commission, big.NewInt(10_000))

		delegatorPool := new(big.Int).Sub(nodeShare, commission)

		// Credit commission to operator's pending reward pool.
		if commission.Sign() > 0 {
			addPendingReward(db, nodeAddr, commission)
		}

		// Increment rewardPerShare for delegators.
		if rec.TotalStake.Sign() > 0 && delegatorPool.Sign() > 0 {
			delta := new(big.Int).Mul(delegatorPool, RewardPrecision)
			delta.Div(delta, rec.TotalStake)
			newRPS := new(big.Int).Add(rec.RewardPerShare, delta)
			setRewardPerShare(db, nodeAddr, newRPS)
		}

		// Mint the total nodeShare into the staking reserve address.
		db.AddBalance(params.StakingAddress, nodeShare)

		log.Trace("staking: distributed block reward",
			"node", nodeAddr,
			"share", nodeShare,
			"commission", commission,
			"block", header.Number)
	}
}
