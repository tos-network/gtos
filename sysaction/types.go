// Package sysaction implements the GTOS system action protocol.
//
// System actions are special transactions sent to params.SystemActionAddress.
// Their tx.Data field is a JSON-encoded SysAction message. The EVM is never
// invoked; instead the state processor calls sysaction.Execute() which
// dispatches to the appropriate handler (agent or staking).
package sysaction

import "encoding/json"

// ActionKind identifies the type of system action.
type ActionKind string

const (
	// Agent lifecycle
	ActionAgentRegister  ActionKind = "AGENT_REGISTER"
	ActionAgentUpdate    ActionKind = "AGENT_UPDATE"
	ActionAgentHeartbeat ActionKind = "AGENT_HEARTBEAT"

	// Node staking
	ActionNodeStake   ActionKind = "NODE_STAKE"
	ActionNodeUnstake ActionKind = "NODE_UNSTAKE"

	// Delegation
	ActionDelegate   ActionKind = "DELEGATE"
	ActionUndelegate ActionKind = "UNDELEGATE"

	// Reward
	ActionClaimReward ActionKind = "CLAIM_REWARD"

	// Node metadata
	ActionNodeRegister ActionKind = "NODE_REGISTER"
	ActionNodeUpdate   ActionKind = "NODE_UPDATE"
)

// SysAction is the top-level envelope stored in tx.Data for system action txs.
type SysAction struct {
	Action  ActionKind      `json:"action"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// AgentRegisterPayload is the payload for AGENT_REGISTER / AGENT_UPDATE.
type AgentRegisterPayload struct {
	AgentID     string          `json:"agent_id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Category    string          `json:"category"`
	Tags        []string        `json:"tags"`
	Manifest    json.RawMessage `json:"manifest"` // ToolManifest JSON
}

// AgentHeartbeatPayload is the payload for AGENT_HEARTBEAT.
type AgentHeartbeatPayload struct {
	AgentID string `json:"agent_id"`
}

// NodeRegisterPayload is the payload for NODE_REGISTER / NODE_UPDATE.
type NodeRegisterPayload struct {
	// Endpoint is the public RPC/P2P endpoint of the node (optional, informational).
	Endpoint string `json:"endpoint,omitempty"`
	// CommissionBPS is the commission in basis points (0–5000).
	CommissionBPS uint16 `json:"commission_bps"`
}

// DelegatePayload is the payload for DELEGATE.
type DelegatePayload struct {
	// NodeAddress is the operator address of the node to delegate to.
	NodeAddress string `json:"node_address"`
}

// UndelegatePayload is the payload for UNDELEGATE.
type UndelegatePayload struct {
	NodeAddress string `json:"node_address"`
	// Shares is the number of delegation shares to withdraw (0 = all).
	Shares string `json:"shares,omitempty"`
}
