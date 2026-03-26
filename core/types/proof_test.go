package types

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
)

func TestProofArtifactRoundTrip(t *testing.T) {
	artifact := &ProofArtifact{
		ProofType:    ProofTypeTransferBatch,
		ProofVersion: 1,
		Circuit: CircuitVersion{
			Major: 0, Minor: 1, Patch: 0,
			Tag: "gtos-transfer-v1",
		},
		PreStateRoot:      common.HexToHash("0x1111"),
		PostStateRoot:     common.HexToHash("0x2222"),
		TxCommitment:      common.HexToHash("0x3333"),
		WitnessCommitment: common.HexToHash("0x4444"),
		ReceiptCommitment: common.HexToHash("0x5555"),
		PublicInputs:      []byte{0x01, 0x02, 0x03},
		ProofBytes:        []byte{0xde, 0xad, 0xbe, 0xef},
		Provenance: ProofProvenance{
			ProverID:      "test-prover-1",
			ProvingTimeMs: 1500,
			Timestamp:     1700000000,
		},
	}

	// Encode
	data, err := EncodeProofArtifact(artifact)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	// Decode
	decoded, err := DecodeProofArtifact(data)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	// Verify fields
	if decoded.ProofType != artifact.ProofType {
		t.Errorf("ProofType mismatch: got %s, want %s", decoded.ProofType, artifact.ProofType)
	}
	if decoded.PreStateRoot != artifact.PreStateRoot {
		t.Errorf("PreStateRoot mismatch")
	}
	if decoded.PostStateRoot != artifact.PostStateRoot {
		t.Errorf("PostStateRoot mismatch")
	}
	if decoded.Circuit.Tag != artifact.Circuit.Tag {
		t.Errorf("Circuit.Tag mismatch")
	}
	if string(decoded.ProofBytes) != string(artifact.ProofBytes) {
		t.Errorf("ProofBytes mismatch")
	}
	if decoded.Provenance.ProverID != artifact.Provenance.ProverID {
		t.Errorf("Provenance.ProverID mismatch")
	}
}

func TestProofArtifactDigestDeterminism(t *testing.T) {
	artifact := &ProofArtifact{
		ProofType:     ProofTypeTransferBatch,
		ProofVersion:  1,
		PreStateRoot:  common.HexToHash("0xaaaa"),
		PostStateRoot: common.HexToHash("0xbbbb"),
		ProofBytes:    []byte{0x01, 0x02},
	}

	// Compute digest 100 times and verify stability
	first := artifact.Digest()
	for i := 0; i < 100; i++ {
		if got := artifact.Digest(); got != first {
			t.Fatalf("digest not deterministic: run %d got %x, want %x", i, got, first)
		}
	}
}

func TestDeriveBatchTxCommitment(t *testing.T) {
	// Create a set of test transactions
	txs := Transactions{
		NewTx(&SignerTx{
			ChainID: big.NewInt(1666),
			Nonce:   0,
			To:      addrPtr(common.HexToAddress("0x1234")),
			Value:   big.NewInt(1000),
		}),
		NewTx(&SignerTx{
			ChainID: big.NewInt(1666),
			Nonce:   1,
			To:      addrPtr(common.HexToAddress("0x5678")),
			Value:   big.NewInt(2000),
		}),
	}

	// Commitment must be deterministic
	c1 := DeriveBatchTxCommitment(txs)
	c2 := DeriveBatchTxCommitment(txs)
	if c1 != c2 {
		t.Fatalf("tx commitment not deterministic: %x vs %x", c1, c2)
	}

	// Commitment from refs must match
	refs := make([]ProofCoveredTxRef, len(txs))
	for i, tx := range txs {
		refs[i] = ProofCoveredTxRef{
			TxHash: tx.Hash(),
			Index:  uint32(i),
			TxType: tx.Type(),
		}
	}
	c3 := DeriveBatchTxCommitmentFromRefs(refs)
	if c1 != c3 {
		t.Fatalf("tx commitment from refs mismatch: %x vs %x", c1, c3)
	}

	// Different tx order must produce different commitment
	reversed := Transactions{txs[1], txs[0]}
	c4 := DeriveBatchTxCommitment(reversed)
	if c1 == c4 {
		t.Fatal("different tx order produced same commitment")
	}
}

func TestProofPublicInputsHash(t *testing.T) {
	pi := &ProofPublicInputs{
		ChainID:       big.NewInt(1666),
		PreStateRoot:  common.HexToHash("0xaa"),
		PostStateRoot: common.HexToHash("0xbb"),
	}

	h1 := pi.Hash()
	h2 := pi.Hash()
	if h1 != h2 {
		t.Fatalf("public inputs hash not deterministic")
	}
	if h1 == (common.Hash{}) {
		t.Fatal("public inputs hash is zero")
	}
}

func addrPtr(a common.Address) *common.Address { return &a }
