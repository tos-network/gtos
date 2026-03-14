package lease

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	vmtypes "github.com/tos-network/gtos/core/vmtypes"
	"github.com/tos-network/gtos/params"
)

// RunPruneSweep processes the lease-prune queue deterministically at epoch boundaries.
func RunPruneSweep(db vmtypes.StateDB, currentBlock uint64, chainConfig *params.ChainConfig) {
	epochLength := EpochLength(chainConfig)
	if epochLength == 0 || currentBlock == 0 || currentBlock%epochLength != 0 {
		return
	}
	currentEpoch := currentBlock / epochLength
	count := ReadPruneEntryCount(db, currentEpoch)
	if count == 0 {
		return
	}

	for seq := uint64(0); seq < count; seq++ {
		addr := ReadPruneEntry(db, currentEpoch, seq)
		if addr == (common.Address{}) {
			continue
		}
		meta, ok := ReadMeta(db, addr)
		if !ok {
			continue
		}
		if meta.ScheduledPruneEpoch != currentEpoch || meta.ScheduledPruneSeq != seq {
			continue
		}
		if status := EffectiveStatus(meta, currentBlock); status == StatusActive || status == StatusFrozen {
			continue
		}

		refund := RefundFor(meta.DepositWei)
		if refund.Sign() > 0 {
			payout := refund
			if registryBalance := db.GetBalance(params.LeaseRegistryAddress); registryBalance.Cmp(payout) < 0 {
				payout = new(big.Int).Set(registryBalance)
			}
			if payout.Sign() > 0 {
				db.SubBalance(params.LeaseRegistryAddress, payout)
				db.AddBalance(meta.LeaseOwner, payout)
			}
		}

		WriteTombstone(db, addr, Tombstone{
			LastCodeHash:   db.GetCodeHash(addr),
			ExpiredAtBlock: currentBlock,
		})
		ClearMeta(db, addr)
		db.Suicide(addr)
	}

	ClearPruneEpoch(db, currentEpoch)
}
