package lease

import (
	"encoding/json"
	"math/big"

	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&handler{})
}

type handler struct{}

func (h *handler) CanHandle(kind sysaction.ActionKind) bool {
	switch kind {
	case sysaction.ActionLeaseRenew, sysaction.ActionLeaseClose:
		return true
	}
	return false
}

func (h *handler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	switch sa.Action {
	case sysaction.ActionLeaseRenew:
		return h.handleRenew(ctx, sa)
	case sysaction.ActionLeaseClose:
		return h.handleClose(ctx, sa)
	default:
		return nil
	}
}

func (h *handler) handleRenew(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	if ctx.Value != nil && ctx.Value.Sign() != 0 {
		return ErrLeaseValueNotAllowed
	}
	var p RenewAction
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	meta, ok := ReadMeta(ctx.StateDB, p.ContractAddr)
	if !ok {
		return ErrLeaseNotFound
	}
	if err := RejectTombstoned(ctx.StateDB, p.ContractAddr); err != nil {
		return err
	}
	if ctx.From != meta.LeaseOwner {
		return ErrLeaseOwnerOnly
	}
	currentBlock := uint64(0)
	if ctx.BlockNumber != nil {
		currentBlock = ctx.BlockNumber.Uint64()
	}
	switch EffectiveStatus(meta, currentBlock) {
	case StatusActive, StatusFrozen:
	default:
		return ErrLeaseExpired
	}
	deposit, err := DepositFor(meta.CodeBytes, p.DeltaBlocks)
	if err != nil {
		return err
	}
	if ctx.StateDB.GetBalance(ctx.From).Cmp(deposit) < 0 {
		return ErrLeaseInsufficientDeposit
	}
	ctx.StateDB.SubBalance(ctx.From, deposit)
	ctx.StateDB.AddBalance(params.LeaseRegistryAddress, deposit)

	meta, err = RenewMeta(meta, currentBlock, p.DeltaBlocks, ctx.ChainConfig)
	if err != nil {
		return err
	}
	meta.DepositWei = new(big.Int).Add(meta.DepositWei, deposit)
	ScheduleMeta(ctx.StateDB, p.ContractAddr, &meta, ctx.ChainConfig)
	WriteMeta(ctx.StateDB, p.ContractAddr, meta)
	return nil
}

func (h *handler) handleClose(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	if ctx.Value != nil && ctx.Value.Sign() != 0 {
		return ErrLeaseValueNotAllowed
	}
	var p CloseAction
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	meta, ok := ReadMeta(ctx.StateDB, p.ContractAddr)
	if !ok {
		return ErrLeaseNotFound
	}
	if err := RejectTombstoned(ctx.StateDB, p.ContractAddr); err != nil {
		return err
	}
	if ctx.From != meta.LeaseOwner {
		return ErrLeaseOwnerOnly
	}
	refund := RefundFor(meta.DepositWei)
	if ctx.StateDB.GetBalance(params.LeaseRegistryAddress).Cmp(refund) < 0 {
		return ErrLeaseRegistryInvariant
	}
	if refund.Sign() > 0 {
		ctx.StateDB.SubBalance(params.LeaseRegistryAddress, refund)
		ctx.StateDB.AddBalance(ctx.From, refund)
	}
	currentBlock := uint64(0)
	if ctx.BlockNumber != nil {
		currentBlock = ctx.BlockNumber.Uint64()
	}
	meta = CloseMeta(meta, currentBlock)
	ScheduleMeta(ctx.StateDB, p.ContractAddr, &meta, ctx.ChainConfig)
	WriteMeta(ctx.StateDB, p.ContractAddr, meta)
	return nil
}
