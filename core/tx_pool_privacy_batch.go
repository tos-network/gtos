package core

import (
	"bytes"
	"math/big"
	"sort"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
)

type privTxKey struct {
	addr  common.Address
	nonce uint64
}

type txPoolPrivBatch struct {
	pool     *TxPool
	existing map[privTxKey]*types.Transaction
	accepted map[privTxKey]*types.Transaction
}

func newTxPoolPrivBatch(pool *TxPool) *txPoolPrivBatch {
	return &txPoolPrivBatch{
		pool:     pool,
		existing: collectPoolPrivacyTxs(pool),
		accepted: make(map[privTxKey]*types.Transaction),
	}
}

func (b *txPoolPrivBatch) accept(tx *types.Transaction) {
	if key, ok := privacyTxKey(tx); ok {
		b.accepted[key] = tx
	}
}

func (b *txPoolPrivBatch) buildState(tx *types.Transaction) *state.StateDB {
	key, ok := privacyTxKey(tx)
	if !ok {
		return nil
	}
	statedb := b.pool.currentState.Copy()
	candidates := make([]*types.Transaction, 0, len(b.existing)+len(b.accepted))
	for existingKey, existingTx := range b.existing {
		if _, overridden := b.accepted[existingKey]; overridden {
			continue
		}
		if existingKey.addr == key.addr && existingKey.nonce >= key.nonce {
			continue
		}
		candidates = append(candidates, existingTx)
	}
	for acceptedKey, acceptedTx := range b.accepted {
		if acceptedKey.addr == key.addr && acceptedKey.nonce >= key.nonce {
			continue
		}
		candidates = append(candidates, acceptedTx)
	}
	sortPrivacyReplayTxs(candidates)
	replayPrivacyTxs(b.pool.chainconfig.ChainID, statedb, candidates)
	return statedb
}

func collectPoolPrivacyTxs(pool *TxPool) map[privTxKey]*types.Transaction {
	txs := make(map[privTxKey]*types.Transaction)
	for _, lists := range []map[common.Address]*txList{pool.pending, pool.queue} {
		for _, list := range lists {
			for _, tx := range list.Flatten() {
				if key, ok := privacyTxKey(tx); ok {
					txs[key] = tx
				}
			}
		}
	}
	return txs
}

func privacyTxKey(tx *types.Transaction) (privTxKey, bool) {
	from, ok := tx.PrivTxFrom()
	if !ok {
		return privTxKey{}, false
	}
	return privTxKey{addr: from, nonce: tx.Nonce()}, true
}

func sortPrivacyReplayTxs(txs []*types.Transaction) {
	sort.Slice(txs, func(i, j int) bool {
		if txs[i].Nonce() != txs[j].Nonce() {
			return txs[i].Nonce() < txs[j].Nonce()
		}
		fromI, _ := txs[i].PrivTxFrom()
		fromJ, _ := txs[j].PrivTxFrom()
		if cmp := bytes.Compare(fromI[:], fromJ[:]); cmp != 0 {
			return cmp < 0
		}
		return bytes.Compare(txs[i].Hash().Bytes(), txs[j].Hash().Bytes()) < 0
	})
}

func replayPrivacyTxs(chainID *big.Int, statedb *state.StateDB, txs []*types.Transaction) {
	remaining := make([]*types.Transaction, len(txs))
	copy(remaining, txs)
	for {
		progress := false
		for i, tx := range remaining {
			if tx == nil {
				continue
			}
			snap := statedb.Snapshot()
			if _, err := applyPrivacyTxState(chainID, statedb, tx); err != nil {
				statedb.RevertToSnapshot(snap)
				continue
			}
			remaining[i] = nil
			progress = true
		}
		if !progress {
			return
		}
	}
}
