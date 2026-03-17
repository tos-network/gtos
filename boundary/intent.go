package boundary

import (
	"math/big"

	"github.com/tos-network/gtos/common"
)

// IntentEnvelope represents a user or agent intent.
type IntentEnvelope struct {
	IntentID      string             `json:"intent_id"`
	SchemaVersion string             `json:"schema_version"`
	Action        string             `json:"action"`
	Requester     common.Address     `json:"requester"`
	ActorAgentID  common.Address     `json:"actor_agent_id"`
	TerminalClass TerminalClass      `json:"terminal_class"`
	TrustTier     TrustTier          `json:"terminal_trust_tier"`
	Params        map[string]any     `json:"params"`
	Constraints   *IntentConstraints `json:"constraints,omitempty"`
	CreatedAt     uint64             `json:"created_at"`
	ExpiresAt     uint64             `json:"expires_at"`
	Status        IntentStatus       `json:"status"`
}

// IntentConstraints defines limits on how an intent may be fulfilled.
type IntentConstraints struct {
	MaxValue          *big.Int         `json:"max_value,omitempty"`
	AllowedRecipients []common.Address `json:"allowed_recipients,omitempty"`
	RequiredTrustTier TrustTier        `json:"required_trust_tier,omitempty"`
	MaxGas            uint64           `json:"max_gas,omitempty"`
	Deadline          uint64           `json:"deadline,omitempty"`
}

// IntentStatus represents the lifecycle state of an intent.
type IntentStatus string

const (
	IntentPending   IntentStatus = "pending"
	IntentPlanning  IntentStatus = "planning"
	IntentApproved  IntentStatus = "approved"
	IntentExecuting IntentStatus = "executing"
	IntentSettled   IntentStatus = "settled"
	IntentFailed    IntentStatus = "failed"
	IntentExpired   IntentStatus = "expired"
	IntentCancelled IntentStatus = "cancelled"
)

// PlanRecord represents an execution plan for an intent.
type PlanRecord struct {
	PlanID            string         `json:"plan_id"`
	IntentID          string         `json:"intent_id"`
	SchemaVersion     string         `json:"schema_version"`
	Provider          common.Address `json:"provider"`
	Sponsor           common.Address `json:"sponsor,omitempty"`
	ArtifactRef       string         `json:"artifact_ref,omitempty"`
	ABIRef            string         `json:"abi_ref,omitempty"`
	PolicyHash        common.Hash    `json:"policy_hash"`
	SponsorPolicyHash common.Hash    `json:"sponsor_policy_hash,omitempty"`
	EffectsHash       common.Hash    `json:"effects_hash,omitempty"`
	EstimatedGas      uint64         `json:"estimated_gas"`
	EstimatedValue    *big.Int       `json:"estimated_value"`
	Route             []RouteStep    `json:"route,omitempty"`
	FallbackPlanID    string         `json:"fallback_plan_id,omitempty"`
	CreatedAt         uint64         `json:"created_at"`
	ExpiresAt         uint64         `json:"expires_at"`
	Status            PlanStatus     `json:"status"`
}

// RouteStep represents a single step in a plan's execution route.
type RouteStep struct {
	Target      common.Address `json:"target"`
	Action      string         `json:"action"`
	Value       *big.Int       `json:"value,omitempty"`
	ArtifactRef string         `json:"artifact_ref,omitempty"`
}

// PlanStatus represents the lifecycle state of an execution plan.
type PlanStatus string

const (
	PlanDraft     PlanStatus = "draft"
	PlanReady     PlanStatus = "ready"
	PlanApproved  PlanStatus = "approved"
	PlanExecuting PlanStatus = "executing"
	PlanCompleted PlanStatus = "completed"
	PlanFailed    PlanStatus = "failed"
	PlanExpired   PlanStatus = "expired"
)
