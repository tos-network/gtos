package types

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
)

func TestBatchProofSidecarRoundTrip(t *testing.T) {
	sidecar := &BatchProofSidecar{
		BlockHash:         common.HexToHash("0xaabb"),
		ProofType:         ProofTypeTransferBatch,
		ProofVersion:      1,
		CircuitVersion:    "0.1.0-gtos-transfer-v1",
		PreStateRoot:      common.HexToHash("0x1111"),
		PostStateRoot:     common.HexToHash("0x2222"),
		BatchTxCommitment: common.HexToHash("0x3333"),
		WitnessCommitment: common.HexToHash("0x4444"),
		ReceiptCommitment: common.HexToHash("0x5555"),
		PublicInputsHash:  common.HexToHash("0x6666"),
		ProofArtifactHash: common.HexToHash("0x7777"),
		ProofBytes:        []byte{0xde, 0xad},
		PublicInputs:      []byte{0xbe, 0xef},
		ProofCoveredTxs: []ProofCoveredTxRef{
			{TxHash: common.HexToHash("0xaa"), Index: 0, TxType: SignerTxType},
			{TxHash: common.HexToHash("0xbb"), Index: 1, TxType: ShieldTxType},
		},
		CoverageMode:  "full",
		UsedGas:       42000,
		ProverID:      "test-prover",
		ProvingTimeMs: 500,
	}

	data, err := EncodeBatchProofSidecar(sidecar)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	decoded, err := DecodeBatchProofSidecar(data)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.BlockHash != sidecar.BlockHash {
		t.Errorf("BlockHash mismatch")
	}
	if decoded.ProofType != sidecar.ProofType {
		t.Errorf("ProofType mismatch")
	}
	if decoded.PreStateRoot != sidecar.PreStateRoot {
		t.Errorf("PreStateRoot mismatch")
	}
	if decoded.UsedGas != sidecar.UsedGas {
		t.Errorf("UsedGas mismatch: got %d, want %d", decoded.UsedGas, sidecar.UsedGas)
	}
	if len(decoded.ProofCoveredTxs) != 2 {
		t.Fatalf("ProofCoveredTxs count mismatch: got %d, want 2", len(decoded.ProofCoveredTxs))
	}
	if decoded.ProofCoveredTxs[0].TxType != SignerTxType {
		t.Errorf("ProofCoveredTxs[0].TxType mismatch")
	}
	if decoded.ProofCoveredTxs[1].TxType != ShieldTxType {
		t.Errorf("ProofCoveredTxs[1].TxType mismatch")
	}
}

func TestBatchProofSidecarDigestDeterminism(t *testing.T) {
	sidecar := &BatchProofSidecar{
		BlockHash:    common.HexToHash("0xaabb"),
		ProofType:    ProofTypeTransferBatch,
		ProofVersion: 1,
		ProofBytes:   []byte{0x01, 0x02, 0x03},
	}

	first := sidecar.Digest()
	for i := 0; i < 100; i++ {
		if got := sidecar.Digest(); got != first {
			t.Fatalf("sidecar digest not deterministic: run %d", i)
		}
	}
}

func TestCoversAllTxs(t *testing.T) {
	tx1 := NewTx(&SignerTx{
		ChainID: big.NewInt(1666),
		Nonce:   0,
		To:      addrPtr(common.HexToAddress("0x1234")),
		Value:   big.NewInt(1000),
	})
	tx2 := NewTx(&SignerTx{
		ChainID: big.NewInt(1666),
		Nonce:   1,
		To:      addrPtr(common.HexToAddress("0x5678")),
		Value:   big.NewInt(2000),
	})
	txs := Transactions{tx1, tx2}

	// Matching sidecar
	sidecar := &BatchProofSidecar{
		ProofCoveredTxs: []ProofCoveredTxRef{
			{TxHash: tx1.Hash(), Index: 0, TxType: tx1.Type()},
			{TxHash: tx2.Hash(), Index: 1, TxType: tx2.Type()},
		},
	}
	if !sidecar.CoversAllTxs(txs) {
		t.Fatal("CoversAllTxs should return true for matching txs")
	}

	// Wrong order
	sidecarWrong := &BatchProofSidecar{
		ProofCoveredTxs: []ProofCoveredTxRef{
			{TxHash: tx2.Hash(), Index: 0, TxType: tx2.Type()},
			{TxHash: tx1.Hash(), Index: 1, TxType: tx1.Type()},
		},
	}
	if sidecarWrong.CoversAllTxs(txs) {
		t.Fatal("CoversAllTxs should return false for wrong order")
	}

	// Missing tx
	sidecarShort := &BatchProofSidecar{
		ProofCoveredTxs: []ProofCoveredTxRef{
			{TxHash: tx1.Hash(), Index: 0, TxType: tx1.Type()},
		},
	}
	if sidecarShort.CoversAllTxs(txs) {
		t.Fatal("CoversAllTxs should return false for missing tx")
	}
}
