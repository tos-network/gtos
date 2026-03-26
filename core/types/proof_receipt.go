package types

import (
	"github.com/tos-network/gtos/common"
)

// ProofCoverageClass classifies a transaction's proof eligibility.
type ProofCoverageClass uint8

const (
	// ProofCoverageNone means the tx is not covered by any batch proof.
	ProofCoverageNone ProofCoverageClass = iota
	// ProofCoverageTransfer means the tx is covered by a native-transfer-batch proof.
	ProofCoverageTransfer
	// ProofCoverageRestrictedContract means the tx is covered by a restricted-contract proof (Phase 3+).
	ProofCoverageRestrictedContract
	// ProofCoverageHotPath means the tx is covered by a hot-path proof (Phase 4+).
	ProofCoverageHotPath
)

// ProofReceiptMeta holds proof-related metadata for a single receipt.
// These are implementation-layer fields, not consensus fields in Phase 1.
type ProofReceiptMeta struct {
	ProofCovered   bool               `json:"proofCovered"`
	CoverageClass  ProofCoverageClass `json:"coverageClass"`
	BatchIndex     uint32             `json:"batchIndex"`
	TraceDigest    common.Hash        `json:"traceDigest"`
	ProofType      string             `json:"proofType"`
}

// BatchReceiptRef links a receipt to its position within a proof batch.
type BatchReceiptRef struct {
	TxHash     common.Hash `json:"txHash"`
	BatchIndex uint32      `json:"batchIndex"`
	ProofType  string      `json:"proofType"`
}
