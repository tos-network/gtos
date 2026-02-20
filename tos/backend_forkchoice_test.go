package tos

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
)

func makeTestBlock(number uint64, parent common.Hash) *types.Block {
	return types.NewBlockWithHeader(&types.Header{
		ParentHash: parent,
		Number:     new(big.Int).SetUint64(number),
		Time:       number,
	})
}

func TestResolveForkchoiceStateFallbacks(t *testing.T) {
	head := makeTestBlock(10, common.HexToHash("0x01"))
	state := resolveForkchoiceState(head, nil, nil)
	if state == nil {
		t.Fatalf("expected non-nil forkchoice state")
	}
	if state.HeadHash != head.Hash().Hex() {
		t.Fatalf("unexpected head hash: have %s want %s", state.HeadHash, head.Hash().Hex())
	}
	if state.SafeHash != head.Hash().Hex() {
		t.Fatalf("unexpected safe hash fallback: have %s want %s", state.SafeHash, head.Hash().Hex())
	}
	if state.FinalizedHash != head.Hash().Hex() {
		t.Fatalf("unexpected finalized hash fallback: have %s want %s", state.FinalizedHash, head.Hash().Hex())
	}
}

func TestResolveForkchoiceStateUsesSafeAndFinalized(t *testing.T) {
	head := makeTestBlock(12, common.HexToHash("0x02"))
	safe := makeTestBlock(11, common.HexToHash("0x03"))
	finalized := makeTestBlock(9, common.HexToHash("0x04"))

	state := resolveForkchoiceState(head, safe, finalized)
	if state.HeadHash != head.Hash().Hex() {
		t.Fatalf("unexpected head hash: have %s want %s", state.HeadHash, head.Hash().Hex())
	}
	if state.SafeHash != safe.Hash().Hex() {
		t.Fatalf("unexpected safe hash: have %s want %s", state.SafeHash, safe.Hash().Hex())
	}
	if state.FinalizedHash != finalized.Hash().Hex() {
		t.Fatalf("unexpected finalized hash: have %s want %s", state.FinalizedHash, finalized.Hash().Hex())
	}
}

func TestSameForkchoiceState(t *testing.T) {
	base := resolveForkchoiceState(
		makeTestBlock(5, common.HexToHash("0x11")),
		makeTestBlock(4, common.HexToHash("0x22")),
		makeTestBlock(3, common.HexToHash("0x33")),
	)
	copy := cloneForkchoiceState(base)
	if !sameForkchoiceState(base, copy) {
		t.Fatalf("expected states to be equal")
	}

	copy.FinalizedHash = common.HexToHash("0x44").Hex()
	if sameForkchoiceState(base, copy) {
		t.Fatalf("expected states to differ after finalized hash change")
	}
}
