package reputation

import (
	"encoding/json"
	"math/big"

	"github.com/tos-network/gtos/capability"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&reputationHandler{})
}

// registrarBit is the well-known bit index for the "Registrar" capability.
const registrarBit uint8 = 0

type reputationHandler struct{}

func (h *reputationHandler) Actions() []sysaction.ActionKind {
	return []sysaction.ActionKind{
		sysaction.ActionReputationAuthorizeScorer,
		sysaction.ActionReputationRecordScore,
	}
}

func (h *reputationHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	switch sa.Action {
	case sysaction.ActionReputationAuthorizeScorer:
		return h.handleAuthorizeScorer(ctx, sa)
	case sysaction.ActionReputationRecordScore:
		return h.handleRecordScore(ctx, sa)
	}
	return nil
}

type authorizeScorerPayload struct {
	Scorer  string `json:"scorer"`  // hex address
	Enabled bool   `json:"enabled"` // true = authorize, false = revoke
}

func (h *reputationHandler) handleAuthorizeScorer(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	if !capability.HasCapability(ctx.StateDB, ctx.From, registrarBit) {
		return ErrRegistrarRequired
	}
	var p authorizeScorerPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	scorer := common.HexToAddress(p.Scorer)
	AuthorizeScorer(ctx.StateDB, scorer, p.Enabled)
	return nil
}

type recordScorePayload struct {
	Who    string `json:"who"`    // hex address of agent being scored
	Delta  string `json:"delta"`  // signed decimal string (may be negative)
	Reason string `json:"reason"` // human-readable reason (not stored on-chain)
	RefID  string `json:"ref_id"` // external reference ID (not stored on-chain)
}

func (h *reputationHandler) handleRecordScore(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	if !IsAuthorizedScorer(ctx.StateDB, ctx.From) {
		return ErrNotAuthorizedScorer
	}
	var p recordScorePayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}

	delta, ok := new(big.Int).SetString(p.Delta, 10)
	if !ok {
		return ErrInvalidDelta
	}

	who := common.HexToAddress(p.Who)
	RecordScore(ctx.StateDB, who, delta)
	return nil
}
