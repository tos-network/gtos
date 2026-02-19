package agent

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&agentHandler{})
}

// agentHandler implements sysaction.Handler for agent lifecycle actions.
// It writes minimal on-chain state to params.AgentRegistryAddress so that
// ownership and manifest hash are verifiable without the in-memory index.
type agentHandler struct{}

func (h *agentHandler) CanHandle(kind sysaction.ActionKind) bool {
	switch kind {
	case sysaction.ActionAgentRegister, sysaction.ActionAgentUpdate, sysaction.ActionAgentHeartbeat:
		return true
	}
	return false
}

func (h *agentHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	switch sa.Action {
	case sysaction.ActionAgentRegister, sysaction.ActionAgentUpdate:
		return h.handleRegister(ctx, sa)
	case sysaction.ActionAgentHeartbeat:
		return h.handleHeartbeat(ctx, sa)
	}
	return fmt.Errorf("agent handler: unsupported action %q", sa.Action)
}

func (h *agentHandler) handleRegister(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p sysaction.AgentRegisterPayload
	if err := sysaction.DecodePayload(sa, &p); err != nil {
		return fmt.Errorf("agent register: %w", err)
	}
	if p.AgentID == "" {
		return fmt.Errorf("agent register: missing agent_id")
	}

	// Write owner slot.
	ownerSlot := agentSlot(p.AgentID, "owner")
	var ownerHash common.Hash
	copy(ownerHash[12:], ctx.From.Bytes())
	ctx.StateDB.SetState(params.AgentRegistryAddress, ownerSlot, ownerHash)

	// Write manifest hash if provided.
	if len(p.Manifest) > 0 {
		var m ToolManifest
		if err := json.Unmarshal(p.Manifest, &m); err == nil {
			m.Sig = ""
			m.SigAlg = ""
			b, _ := json.Marshal(m)
			h := sha256.Sum256(b)
			var hashSlotVal common.Hash
			copy(hashSlotVal[:], h[:])
			mhSlot := agentSlot(p.AgentID, "manifest_hash")
			ctx.StateDB.SetState(params.AgentRegistryAddress, mhSlot, hashSlotVal)
		}
	}

	// Mark active (status = 1).
	statusSlot := agentSlot(p.AgentID, "status")
	var statusHash common.Hash
	statusHash[31] = 1
	ctx.StateDB.SetState(params.AgentRegistryAddress, statusSlot, statusHash)
	return nil
}

func (h *agentHandler) handleHeartbeat(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p sysaction.AgentHeartbeatPayload
	if err := sysaction.DecodePayload(sa, &p); err != nil {
		return fmt.Errorf("agent heartbeat: %w", err)
	}
	if p.AgentID == "" {
		return fmt.Errorf("agent heartbeat: missing agent_id")
	}
	// Verify sender is owner.
	ownerSlot := agentSlot(p.AgentID, "owner")
	stored := ctx.StateDB.GetState(params.AgentRegistryAddress, ownerSlot)
	var fromHash common.Hash
	copy(fromHash[12:], ctx.From.Bytes())
	if stored != fromHash {
		return fmt.Errorf("agent heartbeat: sender is not owner of agent %s", p.AgentID)
	}
	return nil
}

func agentSlot(agentID, field string) common.Hash {
	key := []byte(agentID + "\x00" + field)
	return common.BytesToHash(crypto.Keccak256(key))
}
