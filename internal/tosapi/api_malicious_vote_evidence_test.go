package tosapi

import (
	"context"
	"crypto/ed25519"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

func testMaliciousVoteEvidence(t *testing.T) *types.MaliciousVoteEvidence {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	signer := common.BytesToAddress(crypto.Keccak256(pub))
	first := &types.CheckpointVoteEnvelope{
		Vote:   types.CheckpointVote{ChainID: big.NewInt(42), Number: 64, Hash: common.HexToHash("0x1111"), ValidatorSetHash: common.HexToHash("0xabcd")},
		Signer: signer,
	}
	firstHash := first.Vote.SigningHash()
	copy(first.Signature[:], ed25519.Sign(priv, firstHash[:]))
	second := &types.CheckpointVoteEnvelope{
		Vote:   types.CheckpointVote{ChainID: big.NewInt(42), Number: 64, Hash: common.HexToHash("0x2222"), ValidatorSetHash: common.HexToHash("0xabcd")},
		Signer: signer,
	}
	secondHash := second.Vote.SigningHash()
	copy(second.Signature[:], ed25519.Sign(priv, secondHash[:]))
	evidence, err := types.NewMaliciousVoteEvidence(first, second, "ed25519", pub)
	if err != nil {
		t.Fatalf("NewMaliciousVoteEvidence: %v", err)
	}
	return evidence
}

func TestBuildSubmitMaliciousVoteEvidenceTxBuildsSlashIndicatorTx(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	evidence := testMaliciousVoteEvidence(t)
	from := common.HexToAddress("0xbeef")
	res, err := api.BuildSubmitMaliciousVoteEvidenceTx(context.Background(), RPCSubmitMaliciousVoteEvidenceArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: from},
		Evidence:        *evidence,
	})
	if err != nil {
		t.Fatalf("BuildSubmitMaliciousVoteEvidenceTx: %v", err)
	}
	if len(res.Raw) == 0 {
		t.Fatal("expected raw tx bytes")
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(res.Raw); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if tx.To() == nil || *tx.To() != params.CheckpointSlashIndicatorAddress {
		t.Fatalf("unexpected tx to: %v", tx.To())
	}
	decoded, err := dpos.DecodeSubmitFinalityViolationEvidence(tx.Data())
	if err != nil {
		t.Fatalf("DecodeSubmitFinalityViolationEvidence: %v", err)
	}
	if decoded.Hash() != evidence.Hash() {
		t.Fatalf("decoded evidence mismatch: have %s want %s", decoded.Hash(), evidence.Hash())
	}
}

func TestGetAndListMaliciousVoteEvidence(t *testing.T) {
	backend := newBackendMock()
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	st, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	backend.state = st
	api := NewTOSAPI(backend)
	evidence := testMaliciousVoteEvidence(t)
	input, err := dpos.PackSubmitFinalityViolationEvidence(evidence)
	if err != nil {
		t.Fatalf("PackSubmitFinalityViolationEvidence: %v", err)
	}
	to := params.CheckpointSlashIndicatorAddress
	msg := types.NewMessage(common.HexToAddress("0x200"), &to, 0, big.NewInt(0), 500000, params.TxPrice(), params.TxPrice(), params.TxPrice(), input, nil, true)
	if _, err := dpos.ExecuteSlashIndicator(msg, st, big.NewInt(77), backend.config); err != nil {
		t.Fatalf("ExecuteSlashIndicator: %v", err)
	}
	hash := evidence.Hash()
	rec, err := api.GetMaliciousVoteEvidence(context.Background(), hash, nil)
	if err != nil {
		t.Fatalf("GetMaliciousVoteEvidence: %v", err)
	}
	if rec == nil || rec.Number != 64 || rec.Signer != evidence.Signer || rec.SubmittedBy != msg.From() || rec.SubmittedAt != 77 || rec.Status != "submitted" {
		t.Fatalf("unexpected evidence record: %+v", rec)
	}
	if rec.OffenseKey != dpos.MaliciousVoteOffenseKey(evidence.Signer, evidence.Number) {
		t.Fatalf("unexpected offense key: %s", rec.OffenseKey.Hex())
	}
	list, err := api.ListMaliciousVoteEvidence(context.Background(), 10, nil)
	if err != nil {
		t.Fatalf("ListMaliciousVoteEvidence: %v", err)
	}
	if len(list) != 1 || list[0].EvidenceHash != hash || list[0].Status != "submitted" {
		t.Fatalf("unexpected evidence list: %+v", list)
	}
}
