package boundary

import (
	"math/big"

	"github.com/tos-network/gtos/common"
)

// ApprovalRecord represents a signed approval for a plan execution.
type ApprovalRecord struct {
	ApprovalID       string         `json:"approval_id"`
	IntentID         string         `json:"intent_id"`
	PlanID           string         `json:"plan_id"`
	SchemaVersion    string         `json:"schema_version"`
	Approver         common.Address `json:"approver"`
	ApproverRole     AgentRole      `json:"approver_role"`
	AccountID        common.Address `json:"account_id"`
	TerminalClass    TerminalClass  `json:"terminal_class"`
	TrustTier        TrustTier      `json:"trust_tier"`
	PolicyHash       common.Hash    `json:"policy_hash"`
	ApprovalProofRef string         `json:"approval_proof_ref,omitempty"`
	Scope            *ApprovalScope `json:"scope,omitempty"`
	CreatedAt        uint64         `json:"created_at"`
	ExpiresAt        uint64         `json:"expires_at"`
	Status           ApprovalStatus `json:"status"`
}

// ApprovalScope defines the boundaries of what an approval permits.
type ApprovalScope struct {
	MaxValue        *big.Int        `json:"max_value,omitempty"`
	AllowedActions  []string        `json:"allowed_actions,omitempty"`
	AllowedTargets  []common.Address `json:"allowed_targets,omitempty"`
	TerminalClasses []TerminalClass `json:"terminal_classes,omitempty"`
	MinTrustTier    TrustTier       `json:"min_trust_tier,omitempty"`
}

// ApprovalStatus represents the lifecycle state of an approval.
type ApprovalStatus string

const (
	ApprovalPending ApprovalStatus = "pending"
	ApprovalGranted ApprovalStatus = "granted"
	ApprovalDenied  ApprovalStatus = "denied"
	ApprovalRevoked ApprovalStatus = "revoked"
	ApprovalExpired ApprovalStatus = "expired"
)
