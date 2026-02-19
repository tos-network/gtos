// Package sysaction implements the GTOS system action protocol.
//
// System actions are special transactions sent to params.SystemActionAddress.
// Their tx.Data field is a JSON-encoded SysAction message. The EVM is never
// invoked; instead the state processor calls sysaction.Execute() which
// dispatches to the appropriate handler (e.g. agent).
package sysaction

import "encoding/json"

// ActionKind identifies the type of system action.
type ActionKind string

const (
	// Agent lifecycle
	ActionAgentRegister  ActionKind = "AGENT_REGISTER"
	ActionAgentUpdate    ActionKind = "AGENT_UPDATE"
	ActionAgentHeartbeat ActionKind = "AGENT_HEARTBEAT"

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

