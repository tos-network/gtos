package types

import (
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/rlp"
)

// BatchProofSidecar carries proof metadata for a proof-backed block.
// It is stored out-of-band, keyed by canonical block hash — not in the
// Header struct and not in Header.Extra.
//
// Phase 1 uses this for shadow proving (observability only).
// Phase 2+ uses this for consensus validation.
type BatchProofSidecar struct {
	// Block binding
	BlockHash common.Hash `json:"blockHash"`

	// Proof identity
	ProofType    string `json:"proofType"`
	ProofVersion uint32 `json:"proofVersion"`
	CircuitVersion string `json:"circuitVersion"`

	// State commitments
	PreStateRoot        common.Hash `json:"preStateRoot"`
	PostStateRoot       common.Hash `json:"postStateRoot"`
	BatchTxCommitment   common.Hash `json:"batchTxCommitment"`
	WitnessCommitment   common.Hash `json:"witnessCommitment"`
	ReceiptCommitment   common.Hash `json:"receiptCommitment"`
	PublicInputsHash    common.Hash `json:"publicInputsHash"`

	// Proof artifact
	ProofArtifactHash common.Hash `json:"proofArtifactHash"`
	ProofBytes        []byte      `json:"proofBytes"`
	PublicInputs      []byte      `json:"publicInputs"`

	// Coverage
	ProofCoveredTxs []ProofCoveredTxRef `json:"proofCoveredTxs"`
	CoverageMode    string              `json:"coverageMode"`

	// Execution results (for Phase 2+ state materialization)
	UsedGas uint64 `json:"usedGas"`

	// Provenance
	ProverID      string `json:"proverId"`
	ProvingTimeMs uint64 `json:"provingTimeMs"`
}

// Digest returns a deterministic hash of the sidecar.
func (s *BatchProofSidecar) Digest() common.Hash {
	return rlpHash(s)
}

// CoversAllTxs returns true if the sidecar covers exactly the given
// transaction set (same count, same hashes, same order).
func (s *BatchProofSidecar) CoversAllTxs(txs Transactions) bool {
	if len(s.ProofCoveredTxs) != len(txs) {
		return false
	}
	for i, ref := range s.ProofCoveredTxs {
		if ref.TxHash != txs[i].Hash() || ref.Index != uint32(i) || ref.TxType != txs[i].Type() {
			return false
		}
	}
	return true
}

// BatchProofLocator is a lightweight reference to a proof sidecar,
// used for indexing and lookup without loading the full sidecar.
type BatchProofLocator struct {
	BlockHash         common.Hash `json:"blockHash"`
	ProofType         string      `json:"proofType"`
	ProofArtifactHash common.Hash `json:"proofArtifactHash"`
}

// EncodeBatchProofSidecar serializes a sidecar to RLP bytes.
func EncodeBatchProofSidecar(s *BatchProofSidecar) ([]byte, error) {
	return rlp.EncodeToBytes(s)
}

// DecodeBatchProofSidecar deserializes a sidecar from RLP bytes.
func DecodeBatchProofSidecar(data []byte) (*BatchProofSidecar, error) {
	var s BatchProofSidecar
	if err := rlp.DecodeBytes(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
