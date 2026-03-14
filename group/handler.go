package group

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&groupHandler{})
}

// Sentinel errors returned by group system action handlers.
var (
	ErrGroupAlreadyRegistered = errors.New("group: group is already registered")
	ErrGroupNotRegistered     = errors.New("group: group is not registered")
	ErrGroupIDRequired        = errors.New("group: group_id is required")
	ErrNotGroupCreator        = errors.New("group: only the creator can perform this action")
)

type groupHandler struct{}

func (h *groupHandler) CanHandle(kind sysaction.ActionKind) bool {
	switch kind {
	case sysaction.ActionGroupRegister,
		sysaction.ActionGroupStateCommit:
		return true
	}
	return false
}

func (h *groupHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	switch sa.Action {
	case sysaction.ActionGroupRegister:
		return h.handleRegister(ctx, sa)
	case sysaction.ActionGroupStateCommit:
		return h.handleStateCommit(ctx, sa)
	default:
		return fmt.Errorf("group: unknown action %s", sa.Action)
	}
}

// --- GROUP_REGISTER ---

type registerPayload struct {
	GroupID         string `json:"group_id"`
	ManifestHash    string `json:"manifest_hash"`
	TreasuryAddress string `json:"treasury_address"`
	CreatorAddress  string `json:"creator_address"`
	MembersRoot     string `json:"members_root"`
}

func (h *groupHandler) handleRegister(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p registerPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return fmt.Errorf("group register: invalid payload: %w", err)
	}
	if p.GroupID == "" {
		return ErrGroupIDRequired
	}
	if IsGroupRegistered(ctx.StateDB, p.GroupID) {
		return ErrGroupAlreadyRegistered
	}

	SetGroupRegistered(ctx.StateDB, p.GroupID, true)
	SetGroupManifestHash(ctx.StateDB, p.GroupID, common.HexToHash(p.ManifestHash))
	SetGroupTreasuryAddress(ctx.StateDB, p.GroupID, common.HexToAddress(p.TreasuryAddress))
	if p.CreatorAddress != "" {
		SetGroupCreatorAddress(ctx.StateDB, p.GroupID, common.HexToAddress(p.CreatorAddress))
	} else {
		SetGroupCreatorAddress(ctx.StateDB, p.GroupID, ctx.From)
	}
	SetGroupMembersRoot(ctx.StateDB, p.GroupID, common.HexToHash(p.MembersRoot))
	SetGroupEpoch(ctx.StateDB, p.GroupID, 1)
	SetGroupCommitCount(ctx.StateDB, p.GroupID, 0)

	return nil
}

// --- GROUP_STATE_COMMIT ---

type stateCommitPayload struct {
	GroupID            string `json:"group_id"`
	Epoch              uint64 `json:"epoch"`
	MembersRoot        string `json:"members_root"`
	EventsMerkleRoot   string `json:"events_merkle_root"`
	TreasuryBalanceWei string `json:"treasury_balance_wei"`
}

func (h *groupHandler) handleStateCommit(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p stateCommitPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return fmt.Errorf("group state commit: invalid payload: %w", err)
	}
	if p.GroupID == "" {
		return ErrGroupIDRequired
	}
	if !IsGroupRegistered(ctx.StateDB, p.GroupID) {
		return ErrGroupNotRegistered
	}

	// Only the creator can commit state.
	creator := GetGroupCreatorAddress(ctx.StateDB, p.GroupID)
	if ctx.From != creator {
		return ErrNotGroupCreator
	}

	SetGroupMembersRoot(ctx.StateDB, p.GroupID, common.HexToHash(p.MembersRoot))
	SetGroupEventsRoot(ctx.StateDB, p.GroupID, common.HexToHash(p.EventsMerkleRoot))
	SetGroupEpoch(ctx.StateDB, p.GroupID, p.Epoch)

	if p.TreasuryBalanceWei != "" {
		bal, ok := new(big.Int).SetString(p.TreasuryBalanceWei, 10)
		if ok {
			SetGroupTreasuryBalance(ctx.StateDB, p.GroupID, bal)
		}
	}

	// Increment commit count.
	count := GetGroupCommitCount(ctx.StateDB, p.GroupID)
	SetGroupCommitCount(ctx.StateDB, p.GroupID, count+1)

	return nil
}
