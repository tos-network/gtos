package rawdb

import (
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
)

func TestProofSidecarRoundTrip(t *testing.T) {
	db := NewMemoryDatabase()
	blockHash := common.HexToHash("0xaabbccdd")

	// Initially no sidecar
	if HasProofSidecar(db, blockHash) {
		t.Fatal("should not have sidecar before write")
	}
	if s := ReadProofSidecar(db, blockHash); s != nil {
		t.Fatal("should return nil before write")
	}

	// Write sidecar
	sidecar := &types.BatchProofSidecar{
		BlockHash:         blockHash,
		ProofType:         types.ProofTypeTransferBatch,
		ProofVersion:      1,
		PreStateRoot:      common.HexToHash("0x1111"),
		PostStateRoot:     common.HexToHash("0x2222"),
		BatchTxCommitment: common.HexToHash("0x3333"),
		ProofBytes:        []byte{0xde, 0xad, 0xbe, 0xef},
		UsedGas:           21000,
		ProverID:          "test",
		ProofCoveredTxs: []types.ProofCoveredTxRef{
			{TxHash: common.HexToHash("0xaa"), Index: 0, TxType: 0},
		},
	}
	WriteProofSidecar(db, blockHash, sidecar)

	// Has sidecar
	if !HasProofSidecar(db, blockHash) {
		t.Fatal("should have sidecar after write")
	}

	// Read sidecar
	got := ReadProofSidecar(db, blockHash)
	if got == nil {
		t.Fatal("read returned nil after write")
	}
	if got.BlockHash != blockHash {
		t.Errorf("BlockHash mismatch: got %x, want %x", got.BlockHash, blockHash)
	}
	if got.ProofType != types.ProofTypeTransferBatch {
		t.Errorf("ProofType mismatch")
	}
	if got.UsedGas != 21000 {
		t.Errorf("UsedGas mismatch: got %d, want 21000", got.UsedGas)
	}
	if len(got.ProofCoveredTxs) != 1 {
		t.Fatalf("ProofCoveredTxs count: got %d, want 1", len(got.ProofCoveredTxs))
	}

	// Delete sidecar
	DeleteProofSidecar(db, blockHash)
	if HasProofSidecar(db, blockHash) {
		t.Fatal("should not have sidecar after delete")
	}
	if s := ReadProofSidecar(db, blockHash); s != nil {
		t.Fatal("should return nil after delete")
	}
}

func TestProvedHeadRoundTrip(t *testing.T) {
	db := NewMemoryDatabase()

	// Initially zero
	if h := ReadProvedHead(db); h != (common.Hash{}) {
		t.Fatalf("proved head should be zero initially, got %x", h)
	}

	// Write
	hash := common.HexToHash("0xdeadbeef")
	WriteProvedHead(db, hash)

	// Read
	if got := ReadProvedHead(db); got != hash {
		t.Fatalf("proved head mismatch: got %x, want %x", got, hash)
	}

	// Overwrite
	hash2 := common.HexToHash("0xcafebabe")
	WriteProvedHead(db, hash2)
	if got := ReadProvedHead(db); got != hash2 {
		t.Fatalf("proved head not updated: got %x, want %x", got, hash2)
	}
}
