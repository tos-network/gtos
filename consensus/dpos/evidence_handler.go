package dpos

import (
	"fmt"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
	"github.com/tos-network/gtos/validator"
)

func init() {
	sysaction.DefaultRegistry.Register(&checkpointEvidenceHandler{})
}

type checkpointEvidenceHandler struct{}

type AdjudicateMaliciousVoteEvidencePayload struct {
	EvidenceHash common.Hash `json:"evidenceHash"`
}

func (h *checkpointEvidenceHandler) CanHandle(kind sysaction.ActionKind) bool {
	return kind == sysaction.ActionCheckpointSubmitMaliciousVoteEvidence ||
		kind == sysaction.ActionCheckpointAdjudicateMaliciousVoteEvidence
}

func (h *checkpointEvidenceHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	switch sa.Action {
	case sysaction.ActionCheckpointSubmitMaliciousVoteEvidence:
		return h.handleSubmit(ctx, sa)
	case sysaction.ActionCheckpointAdjudicateMaliciousVoteEvidence:
		return h.handleAdjudicate(ctx, sa)
	}
	return nil
}

func (h *checkpointEvidenceHandler) handleSubmit(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var evidence types.MaliciousVoteEvidence
	if err := sysaction.DecodePayload(sa, &evidence); err != nil {
		return fmt.Errorf("dpos: invalid malicious vote evidence payload: %w", err)
	}
	if ctx == nil || ctx.StateDB == nil || ctx.ChainConfig == nil || ctx.ChainConfig.ChainID == nil {
		return fmt.Errorf("dpos: missing execution context for malicious vote evidence")
	}
	if err := evidence.Validate(); err != nil {
		return err
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

func (h *checkpointEvidenceHandler) handleAdjudicate(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var payload AdjudicateMaliciousVoteEvidencePayload
	if err := sysaction.DecodePayload(sa, &payload); err != nil {
		return fmt.Errorf("dpos: invalid malicious vote adjudication payload: %w", err)
	}
	if payload.EvidenceHash == (common.Hash{}) {
		return fmt.Errorf("dpos: evidence hash must not be zero")
	}
	if ctx == nil || ctx.StateDB == nil || ctx.ChainConfig == nil || ctx.ChainConfig.DPoS == nil {
		return fmt.Errorf("dpos: missing execution context for malicious vote adjudication")
	}
	rec, ok := ReadMaliciousVoteEvidenceRecord(ctx.StateDB, payload.EvidenceHash)
	if !ok {
		return fmt.Errorf("dpos: malicious vote evidence not found: %s", payload.EvidenceHash.Hex())
	}
	if rec.Status == MaliciousVoteEvidenceAdjudicated {
		return fmt.Errorf("dpos: malicious vote evidence already adjudicated: %s", payload.EvidenceHash.Hex())
	}
	slashBips := ctx.ChainConfig.DPoS.MaliciousVoteSlashBipsEffective()
	selfStake := validator.ReadSelfStake(ctx.StateDB, rec.Signer)
	slashAmount := new(big.Int)
	if selfStake.Sign() > 0 && slashBips > 0 {
		slashAmount.Mul(selfStake, new(big.Int).SetUint64(slashBips))
		slashAmount.Div(slashAmount, big.NewInt(10_000))
	}
	appliedSlash, err := validator.ApplySlash(ctx.StateDB, rec.Signer, slashAmount, params.ValidatorPenaltyVaultAddress)
	if err != nil {
		return err
	}
	blockNumber := uint64(0)
	if ctx.BlockNumber != nil {
		blockNumber = ctx.BlockNumber.Uint64()
	}
	adjudicateMaliciousVoteEvidenceRecord(ctx.StateDB, payload.EvidenceHash, ctx.From, blockNumber, appliedSlash)
	return nil
}
