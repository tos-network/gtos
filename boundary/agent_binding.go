package boundary

import "github.com/tos-network/gtos/common"

// AgentAccountBinding links an agent to an account with a specific role and policy.
type AgentAccountBinding struct {
	AgentID      common.Address `json:"agent_id"`
	AccountID    common.Address `json:"account_id"`
	Role         AgentRole      `json:"role"`
	PolicyHash   common.Hash    `json:"policy_hash,omitempty"`
	Capabilities []string       `json:"capabilities,omitempty"`
	GrantedAt    uint64         `json:"granted_at"`
	ExpiresAt    uint64         `json:"expires_at,omitempty"`
	Revoked      bool           `json:"revoked"`
}
