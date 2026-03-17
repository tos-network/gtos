package auditreceipt

import (
	"github.com/tos-network/gtos/boundary"
	"github.com/tos-network/gtos/common"
)

// AuditMetaResult is the JSON-friendly result for GetAuditMeta.
type AuditMetaResult struct {
	IntentIDHash       string `json:"intent_id_hash"`
	PlanIDHash         string `json:"plan_id_hash"`
	TerminalClassHash  string `json:"terminal_class_hash"`
	TrustTier          uint8  `json:"trust_tier"`
}

// SessionProofResult is the JSON-friendly result for GetSessionProof.
type SessionProofResult struct {
	TxHash      common.Hash    `json:"tx_hash"`
	AccountAddr common.Address `json:"account_address"`
	TrustTier   uint8          `json:"trust_tier"`
	CreatedAt   uint64         `json:"created_at"`
	ExpiresAt   uint64         `json:"expires_at"`
	ProofHash   common.Hash    `json:"proof_hash"`
}

// PublicAuditReceiptAPI provides RPC methods for querying audit receipt state.
type PublicAuditReceiptAPI struct {
	stateReader func() stateDB
}

// NewPublicAuditReceiptAPI creates a new audit receipt API instance.
func NewPublicAuditReceiptAPI(stateReader func() stateDB) *PublicAuditReceiptAPI {
	return &PublicAuditReceiptAPI{stateReader: stateReader}
}

// GetAuditMeta returns audit metadata for a transaction.
func (api *PublicAuditReceiptAPI) GetAuditMeta(txHash common.Hash) (*AuditMetaResult, error) {
	db := api.stateReader()
	intentIDHash, planIDHash, terminalClassHash, trustTier := ReadAuditMeta(db, txHash)
	return &AuditMetaResult{
		IntentIDHash:      intentIDHash,
		PlanIDHash:        planIDHash,
		TerminalClassHash: terminalClassHash,
		TrustTier:         trustTier,
	}, nil
}

// GetSessionProof returns session proof for a transaction.
func (api *PublicAuditReceiptAPI) GetSessionProof(txHash common.Hash) (*SessionProofResult, error) {
	db := api.stateReader()
	proof := ReadSessionProof(db, txHash)
	if proof == nil {
		return nil, nil
	}
	return &SessionProofResult{
		TxHash:      proof.TxHash,
		AccountAddr: proof.AccountAddr,
		TrustTier:   proof.TrustTier,
		CreatedAt:   proof.CreatedAt,
		ExpiresAt:   proof.ExpiresAt,
		ProofHash:   proof.ProofHash,
	}, nil
}

// GetBoundaryVersion returns the boundary schema version used by this node.
func (api *PublicAuditReceiptAPI) GetBoundaryVersion() string {
	return boundary.SchemaVersion
}

// GetSchemaVersion returns the boundary schema version and negotiation info.
func (api *PublicAuditReceiptAPI) GetSchemaVersion() map[string]interface{} {
	return map[string]interface{}{
		"schema_version": boundary.SchemaVersion,
		"namespace":      "auditReceipt",
	}
}
