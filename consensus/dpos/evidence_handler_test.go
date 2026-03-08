package dpos

import (
	"crypto/ed25519"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

func TestCheckpointEvidenceHandlerStoresSubmittedEvidence(t *testing.T) {
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	st, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	pub, priv, signer := testEd25519Key(0x61)
	first := &types.CheckpointVoteEnvelope{
		Vote: types.CheckpointVote{
			ChainID:          big.NewInt(42),
			Number:           64,
			Hash:             common.HexToHash("0x1111"),
			ValidatorSetHash: common.HexToHash("0xaaaa"),
		},
		Signer: signer,
	}
	h1 := first.Vote.SigningHash()
	copy(first.Signature[:], ed25519.Sign(priv, h1[:]))
	second := &types.CheckpointVoteEnvelope{
		Vote: types.CheckpointVote{
			ChainID:          big.NewInt(42),
			Number:           64,
			Hash:             common.HexToHash("0x2222"),
			ValidatorSetHash: common.HexToHash("0xaaaa"),
		},
		Signer: signer,
	}
	h2 := second.Vote.SigningHash()
	copy(second.Signature[:], ed25519.Sign(priv, h2[:]))
	evidence, err := types.NewMaliciousVoteEvidence(first, second, "ed25519", pub)
	if err != nil {
		t.Fatalf("NewMaliciousVoteEvidence: %v", err)
	}
	payload, err := sysaction.MakeSysAction(sysaction.ActionCheckpointSubmitMaliciousVoteEvidence, evidence)
	if err != nil {
		t.Fatalf("MakeSysAction: %v", err)
	}
	ctx := &sysaction.Context{
		From:        common.HexToAddress("0xbeef"),
		Value:       big.NewInt(0),
		BlockNumber: big.NewInt(77),
		StateDB:     st,
		ChainConfig: &params.ChainConfig{ChainID: big.NewInt(42)},
	}
	if err := sysaction.ExecuteWithContext(ctx, payload); err != nil {
		t.Fatalf("ExecuteWithContext: %v", err)
	}
	hash := evidence.Hash()
	rec, ok := ReadMaliciousVoteEvidenceRecord(st, hash)
	if !ok {
		t.Fatal("expected stored malicious vote evidence record")
	}
	if rec.Number != 64 || rec.Signer != signer || rec.SubmittedBy != ctx.From || rec.SubmittedAt != 77 {
		t.Fatalf("unexpected record: %+v", rec)
	}
	if got := ReadMaliciousVoteEvidenceCount(st); got != 1 {
		t.Fatalf("evidence count = %d, want 1", got)
	}
	hashes := ReadMaliciousVoteEvidenceHashes(st, 10)
	if len(hashes) != 1 || hashes[0] != hash {
		t.Fatalf("unexpected evidence hash list: %v", hashes)
	}
}
