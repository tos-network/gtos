package referral

import (
	"encoding/json"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&referralHandler{})
}

type referralHandler struct{}

func (h *referralHandler) CanHandle(kind sysaction.ActionKind) bool {
	return kind == sysaction.ActionReferralBind
}

func (h *referralHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	return h.handleBind(ctx, sa)
}

type bindPayload struct {
	Referrer string `json:"referrer"` // hex address
}

func (h *referralHandler) handleBind(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p bindPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	referrer := common.HexToAddress(p.Referrer)

	// 1. No self-referral.
	if referrer == ctx.From {
		return ErrReferralSelf
	}
	// 2. Not already bound.
	if HasReferrer(ctx.StateDB, ctx.From) {
		return ErrReferralAlreadyBound
	}
	// 3. Circular reference check: ctx.From must not already be above referrer.
	if IsDownline(ctx.StateDB, ctx.From, referrer, params.MaxReferralDepth) {
		return ErrReferralCircular
	}

	// 4. Write referrer and bound block.
	writeReferrer(ctx.StateDB, ctx.From, referrer)
	writeBoundBlock(ctx.StateDB, ctx.From, ctx.BlockNumber.Uint64())

	// 5. Increment direct_count for referrer.
	incrementDirectCount(ctx.StateDB, referrer)

	// 6. Walk uplines and increment team_size for each ancestor.
	cur := referrer
	for i := uint8(0); i < params.MaxReferralDepth; i++ {
		incrementTeamSize(ctx.StateDB, cur)
		up := ReadReferrer(ctx.StateDB, cur)
		if up == (common.Address{}) {
			break
		}
		cur = up
	}

	return nil
}
