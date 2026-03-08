package dpos

import (
	"fmt"

	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&checkpointEvidenceHandler{})
}

type checkpointEvidenceHandler struct{}

func (h *checkpointEvidenceHandler) CanHandle(kind sysaction.ActionKind) bool {
	return kind == sysaction.ActionCheckpointSubmitMaliciousVoteEvidence
}

func (h *checkpointEvidenceHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var evidence types.MaliciousVoteEvidence
	if err := sysaction.DecodePayload(sa, &evidence); err != nil {
		return fmt.Errorf("dpos: invalid malicious vote evidence payload: %w", err)
	}
	if err := evidence.Validate(); err != nil {
		return err
	}
	if ctx == nil || ctx.StateDB == nil || ctx.ChainConfig == nil || ctx.ChainConfig.ChainID == nil {
		return fmt.Errorf("dpos: missing execution context for malicious vote evidence")
	}
	if evidence.ChainID == nil || evidence.ChainID.Cmp(ctx.ChainConfig.ChainID) != 0 {
		return fmt.Errorf("dpos: malicious vote evidence chain ID mismatch")
	}
	hash := evidence.Hash()
	if HasSubmittedMaliciousVoteEvidence(ctx.StateDB, hash) {
		return fmt.Errorf("dpos: malicious vote evidence already submitted: %s", hash.Hex())
	}
	blockNumber := uint64(0)
	if ctx.BlockNumber != nil {
		blockNumber = ctx.BlockNumber.Uint64()
	}
	appendMaliciousVoteEvidenceRecord(ctx.StateDB, hash, evidence.Number, evidence.Signer, ctx.From, blockNumber)
	return nil
}
