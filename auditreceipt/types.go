// Package auditreceipt provides verifiable audit receipts that extend chain
// receipts with 2046 boundary fields for intent-to-receipt traceability and
// proof references.
package auditreceipt

import (
	"math/big"

	"github.com/tos-network/gtos/common"
)

// AuditReceipt extends the chain receipt with 2046 boundary fields
// for intent-to-receipt traceability and proof references.
type AuditReceipt struct {
	// Chain receipt fields
	TxHash      common.Hash `json:"tx_hash"`
	BlockNumber uint64      `json:"block_number"`
	BlockHash   common.Hash `json:"block_hash"`
	Status      uint64      `json:"status"` // 0=failed, 1=success
	GasUsed     uint64      `json:"gas_used"`

	// 2046 boundary fields
	IntentID   string `json:"intent_id,omitempty"`
	PlanID     string `json:"plan_id,omitempty"`
	ApprovalID string `json:"approval_id,omitempty"`

	// Actor attribution
	From         common.Address `json:"from"`
	To           common.Address `json:"to"`
	Sponsor      common.Address `json:"sponsor,omitempty"`
	ActorAgentID common.Address `json:"actor_agent_id,omitempty"`
	SignerType   string         `json:"signer_type,omitempty"`

	// Policy and authority
	PolicyHash        common.Hash `json:"policy_hash,omitempty"`
	SponsorPolicyHash common.Hash `json:"sponsor_policy_hash,omitempty"`
	TerminalClass     string      `json:"terminal_class,omitempty"`
	TrustTier         uint8       `json:"trust_tier,omitempty"`

	// Artifact references
	ArtifactRef string      `json:"artifact_ref,omitempty"`
	EffectsHash common.Hash `json:"effects_hash,omitempty"`

	// Proof references
	ProofRef    string      `json:"proof_ref,omitempty"`
	ReceiptHash common.Hash `json:"receipt_hash"`

	// Value
	Value     *big.Int `json:"value"`
	SettledAt uint64   `json:"settled_at"`
}

// ProofReference is a pointer to verifiable evidence.
type ProofReference struct {
	Type        string      `json:"type"` // "tx_receipt", "policy_decision", "sponsor_auth", "settlement_anchor"
	Hash        common.Hash `json:"hash"`
	BlockNumber uint64      `json:"block_number,omitempty"`
	Index       uint64      `json:"index,omitempty"`
	URI         string      `json:"uri,omitempty"` // for off-chain references
}

// PolicyDecisionRecord captures why a policy accepted or rejected an action.
type PolicyDecisionRecord struct {
	AccountAddress  common.Address `json:"account_address"`
	TxHash          common.Hash    `json:"tx_hash"`
	PolicyHash      common.Hash    `json:"policy_hash"`
	Decision        string         `json:"decision"` // "allow", "deny", "escalate"
	Reason          string         `json:"reason,omitempty"`
	SpendCapUsed    *big.Int       `json:"spend_cap_used,omitempty"`
	SpendCapRemain  *big.Int       `json:"spend_cap_remaining,omitempty"`
	TerminalClass   string         `json:"terminal_class,omitempty"`
	TrustTier       uint8          `json:"trust_tier,omitempty"`
	DelegateAddress common.Address `json:"delegate_address,omitempty"`
	Timestamp       uint64         `json:"timestamp"`
}

// SponsorAttributionRecord captures sponsor details for audit.
type SponsorAttributionRecord struct {
	TxHash            common.Hash    `json:"tx_hash"`
	SponsorAddress    common.Address `json:"sponsor_address"`
	SponsorSignerType string         `json:"sponsor_signer_type"`
	SponsorNonce      uint64         `json:"sponsor_nonce"`
	SponsorExpiry     uint64         `json:"sponsor_expiry"`
	PolicyHash        common.Hash    `json:"policy_hash"`
	GasSponsored      uint64         `json:"gas_sponsored"`
	Timestamp         uint64         `json:"timestamp"`
}

// SettlementTrace links a transaction to its settlement outcome.
type SettlementTrace struct {
	TxHash       common.Hash    `json:"tx_hash"`
	IntentID     string         `json:"intent_id,omitempty"`
	From         common.Address `json:"from"`
	To           common.Address `json:"to"`
	Value        *big.Int       `json:"value"`
	Success      bool           `json:"success"`
	ContractAddr common.Address `json:"contract_address,omitempty"`
	ArtifactRef  string         `json:"artifact_ref,omitempty"`
	LogCount     uint           `json:"log_count"`
	BlockNumber  uint64         `json:"block_number"`
	Timestamp    uint64         `json:"timestamp"`
}
