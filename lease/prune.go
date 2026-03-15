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
	runPruneSweep(db, currentBlock, chainConfig, params.LeasePruneBudgetPerSweep)
}

func runPruneSweep(db vmtypes.StateDB, currentBlock uint64, chainConfig *params.ChainConfig, budget uint64) {
	epochLength := EpochLength(chainConfig)
	if epochLength == 0 {
		return
	}
	currentEpoch := currentBlock / epochLength
	headEpoch := ReadPruneHeadEpoch(db)
	if headEpoch == 0 || headEpoch > currentEpoch {
		return
	}

	processed := uint64(0)
	for epoch := headEpoch; epoch <= currentEpoch; epoch++ {
		count := ReadPruneEntryCount(db, epoch)
		cursor := ReadPruneCursor(db, epoch)
		if cursor >= count {
			ClearPruneEpoch(db, epoch)
			headEpoch = epoch + 1
			continue
		}

		for cursor < count {
			if budget != 0 && processed >= budget {
				WritePruneCursor(db, epoch, cursor)
				WritePruneHeadEpoch(db, epoch)
				return
			}

			addr := ReadPruneEntry(db, epoch, cursor)
			cursor++
			processed++
			if addr == (common.Address{}) {
				continue
			}
			meta, ok := ReadMeta(db, addr)
			if !ok {
				continue
			}
			if meta.ScheduledPruneEpoch != epoch || meta.ScheduledPruneSeq != cursor-1 {
				continue
			}
			if EffectiveStatus(meta, currentBlock, chainConfig) != StatusPrunable {
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

		ClearPruneEpoch(db, epoch)
		headEpoch = epoch + 1
	}

	WritePruneHeadEpoch(db, headEpoch)
}
