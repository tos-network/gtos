package tos

import (
	"fmt"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus/bft"
	"github.com/tos-network/gtos/core/types"
)

func (h *handler) setLatestQC(qc *bft.QC) {
	h.bftMu.Lock()
	h.bftLatestQC = cloneQC(qc)
	h.bftMu.Unlock()
	h.applyQCFinality(qc)
}

func (h *handler) markQCSeen(qc *bft.QC) bool {
	if qc == nil {
		return false
	}
	key := qcCacheKey(qc.Height, qc.Round, qc.BlockHash)
	h.bftMu.Lock()
	defer h.bftMu.Unlock()
	if _, ok := h.bftSeenQCs[key]; ok {
		return false
	}
	h.bftSeenQCs[key] = struct{}{}
	return true
}

func (h *handler) applyQCFinality(qc *bft.QC) {
	if qc == nil || h.chain == nil {
		return
	}
	block := h.chain.GetBlockByHash(qc.BlockHash)
	if block == nil {
		return
	}
	// Only advance finality on canonical blocks.
	if canonical := h.chain.GetBlockByNumber(block.NumberU64()); canonical == nil || canonical.Hash() != block.Hash() {
		return
	}
	if !shouldAdvanceFinality(h.chain.CurrentFinalizedBlock(), block) {
		return
	}
	h.chain.SetSafe(block)
	h.chain.SetFinalized(block)
	if h.onQCFinalized != nil {
		go h.onQCFinalized(block)
	}
}

func shouldAdvanceFinality(currentFinalized, candidate *types.Block) bool {
	if candidate == nil {
		return false
	}
	if currentFinalized == nil {
		return true
	}
	return candidate.NumberU64() > currentFinalized.NumberU64()
}

func qcCacheKey(height, round uint64, blockHash common.Hash) string {
	return fmt.Sprintf("%d/%d/%s", height, round, blockHash.Hex())
}
