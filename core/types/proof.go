package types

import (
	"encoding/binary"
	"math/big"
	"sort"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/rlp"
)

// Proof type identifiers for batch proving.
const (
	ProofTypeTransferBatch       = "native-transfer-batch-v1"
	ProofTypeRestrictedContract  = "restricted-contract-batch-v1"
	ProofTypeHotPath             = "hotpath-batch-v1"
)

// CircuitVersion identifies a specific proving circuit revision.
type CircuitVersion struct {
	Major uint32
	Minor uint32
	Patch uint32
	Tag   string // e.g. "gtos-transfer-v1"
}

// String returns a human-readable circuit version string.
func (cv CircuitVersion) String() string {
	s := string(rune('0'+cv.Major)) + "." + string(rune('0'+cv.Minor)) + "." + string(rune('0'+cv.Patch))
	if cv.Tag != "" {
		s += "-" + cv.Tag
	}
	return s
}

// ProofPublicInputs contains the public inputs committed to by the proof.
// These are the values that the verifier checks against the proof.
type ProofPublicInputs struct {
	ChainID         *big.Int    `json:"chainId"`
	PreStateRoot    common.Hash `json:"preStateRoot"`
	PostStateRoot   common.Hash `json:"postStateRoot"`
	TxCommitment    common.Hash `json:"txCommitment"`
	ReceiptCommitment common.Hash `json:"receiptCommitment"`
	WitnessCommitment common.Hash `json:"witnessCommitment"`
	BlockHash       common.Hash `json:"blockHash"`
	BlockNumber     uint64      `json:"blockNumber"`
}

// Hash returns a deterministic hash of the public inputs.
func (pi *ProofPublicInputs) Hash() common.Hash {
	return rlpHash(pi)
}

// ProofProvenance records metadata about how and when a proof was generated.
type ProofProvenance struct {
	ProverID     string `json:"proverId"`
	ProvingTimeMs uint64 `json:"provingTimeMs"`
	Timestamp    uint64 `json:"timestamp"`
}

// ProofArtifact is the canonical proof object shared across builder, prover,
// validator, and RPC layers. It contains everything needed to verify a batch
// state transition proof.
type ProofArtifact struct {
	// Identity
	ProofType    string         `json:"proofType"`
	ProofVersion uint32         `json:"proofVersion"`
	Circuit      CircuitVersion `json:"circuit"`

	// Commitments
	PreStateRoot      common.Hash `json:"preStateRoot"`
	PostStateRoot     common.Hash `json:"postStateRoot"`
	TxCommitment      common.Hash `json:"txCommitment"`
	WitnessCommitment common.Hash `json:"witnessCommitment"`
	ReceiptCommitment common.Hash `json:"receiptCommitment"`

	// Proof data
	PublicInputs []byte `json:"publicInputs"`
	ProofBytes   []byte `json:"proofBytes"`

	// Provenance
	Provenance ProofProvenance `json:"provenance"`
}

// Digest returns a deterministic hash of the proof artifact, suitable for
// content-addressing and deduplication.
func (a *ProofArtifact) Digest() common.Hash {
	return rlpHash(a)
}

// PublicInputsHash returns a deterministic hash of only the public inputs
// portion of the artifact.
func (a *ProofArtifact) PublicInputsHash() common.Hash {
	return crypto.Keccak256Hash(a.PublicInputs)
}

// ProofCoveredTxRef identifies a single transaction covered by a batch proof.
type ProofCoveredTxRef struct {
	TxHash common.Hash `json:"txHash"`
	Index  uint32      `json:"index"`
	TxType uint8       `json:"txType"`
}

// DeriveBatchTxCommitment computes a deterministic commitment over the exact
// transaction sequence in a block. The commitment binds the proof to the
// precise tx ordering, count, and content.
func DeriveBatchTxCommitment(txs Transactions) common.Hash {
	// Encode each tx as (index, type, hash) in block body order.
	// Privacy tx order must remain serial and canonical — no reordering.
	buf := make([]byte, 0, len(txs)*37) // 4 + 1 + 32 per tx
	indexBuf := make([]byte, 4)
	for i, tx := range txs {
		binary.BigEndian.PutUint32(indexBuf, uint32(i))
		buf = append(buf, indexBuf...)
		buf = append(buf, tx.Type())
		buf = append(buf, tx.Hash().Bytes()...)
	}
	return crypto.Keccak256Hash(buf)
}

// DeriveBatchTxCommitmentFromRefs computes the same commitment from
// ProofCoveredTxRef entries. The refs must already be in block body order.
func DeriveBatchTxCommitmentFromRefs(refs []ProofCoveredTxRef) common.Hash {
	// Sort by index to ensure canonical order.
	sorted := make([]ProofCoveredTxRef, len(refs))
	copy(sorted, refs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Index < sorted[j].Index })

	buf := make([]byte, 0, len(sorted)*37)
	indexBuf := make([]byte, 4)
	for _, ref := range sorted {
		binary.BigEndian.PutUint32(indexBuf, ref.Index)
		buf = append(buf, indexBuf...)
		buf = append(buf, ref.TxType)
		buf = append(buf, ref.TxHash.Bytes()...)
	}
	return crypto.Keccak256Hash(buf)
}

// EncodeProofArtifact serializes a ProofArtifact to RLP bytes.
func EncodeProofArtifact(a *ProofArtifact) ([]byte, error) {
	return rlp.EncodeToBytes(a)
}

// DecodeProofArtifact deserializes a ProofArtifact from RLP bytes.
func DecodeProofArtifact(data []byte) (*ProofArtifact, error) {
	var a ProofArtifact
	if err := rlp.DecodeBytes(data, &a); err != nil {
		return nil, err
	}
	return &a, nil
}
