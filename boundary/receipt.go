package boundary

import (
	"math/big"

	"github.com/tos-network/gtos/common"
)

// ExecutionReceipt records the on-chain result of an executed plan.
type ExecutionReceipt struct {
	ReceiptID         string         `json:"receipt_id"`
	IntentID          string         `json:"intent_id"`
	PlanID            string         `json:"plan_id"`
	ApprovalID        string         `json:"approval_id"`
	SchemaVersion     string         `json:"schema_version"`
	TxHash            common.Hash    `json:"tx_hash"`
	BlockNumber       uint64         `json:"block_number"`
	BlockHash         common.Hash    `json:"block_hash"`
	From              common.Address `json:"from"`
	To                common.Address `json:"to"`
	Sponsor           common.Address `json:"sponsor,omitempty"`
	ActorAgentID      common.Address `json:"actor_agent_id"`
	TerminalClass     TerminalClass  `json:"terminal_class"`
	TrustTier         TrustTier      `json:"trust_tier"`
	PolicyHash        common.Hash    `json:"policy_hash"`
	SponsorPolicyHash common.Hash    `json:"sponsor_policy_hash,omitempty"`
	ArtifactRef       string         `json:"artifact_ref,omitempty"`
	EffectsHash       common.Hash    `json:"effects_hash,omitempty"`
	GasUsed           uint64         `json:"gas_used"`
	Value             *big.Int       `json:"value"`
	Status            ReceiptStatus  `json:"receipt_status"`
	ProofRef          string         `json:"proof_ref,omitempty"`
	ReceiptRef        string         `json:"receipt_ref,omitempty"`
	SettledAt         uint64         `json:"settled_at"`
}

// ReceiptStatus represents the outcome of an execution.
type ReceiptStatus string

const (
	ReceiptSuccess  ReceiptStatus = "success"
	ReceiptFailed   ReceiptStatus = "failed"
	ReceiptReverted ReceiptStatus = "reverted"
)
