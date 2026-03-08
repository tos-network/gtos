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
	"github.com/tos-network/gtos/validator"
)

func TestSlashIndicatorExecuteStoresSubmittedEvidence(t *testing.T) {
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	st, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	pub, priv, signer := testEd25519Key(0x61)
	first := &types.CheckpointVoteEnvelope{
		Vote:   types.CheckpointVote{ChainID: big.NewInt(42), Number: 64, Hash: common.HexToHash("0x1111"), ValidatorSetHash: common.HexToHash("0xaaaa")},
		Signer: signer,
	}
	h1 := first.Vote.SigningHash()
	copy(first.Signature[:], ed25519.Sign(priv, h1[:]))
	second := &types.CheckpointVoteEnvelope{
		Vote:   types.CheckpointVote{ChainID: big.NewInt(42), Number: 64, Hash: common.HexToHash("0x2222"), ValidatorSetHash: common.HexToHash("0xaaaa")},
		Signer: signer,
	}
	h2 := second.Vote.SigningHash()
	copy(second.Signature[:], ed25519.Sign(priv, h2[:]))
	evidence, err := types.NewMaliciousVoteEvidence(first, second, "ed25519", pub)
	if err != nil {
		t.Fatalf("NewMaliciousVoteEvidence: %v", err)
	}
	input, err := PackSubmitFinalityViolationEvidence(evidence)
	if err != nil {
		t.Fatalf("PackSubmitFinalityViolationEvidence: %v", err)
	}
	to := params.CheckpointSlashIndicatorAddress
	validator.WriteValidatorStatus(st, signer, validator.Active)
	msg := types.NewMessage(common.HexToAddress("0xbeef"), &to, 0, big.NewInt(0), 500000, params.TxPrice(), params.TxPrice(), params.TxPrice(), input, nil, true)
	if _, err := ExecuteSlashIndicator(msg, st, big.NewInt(77), &params.ChainConfig{ChainID: big.NewInt(42)}); err != nil {
		t.Fatalf("ExecuteSlashIndicator: %v", err)
	}
	hash := evidence.Hash()
	rec, ok := ReadMaliciousVoteEvidenceRecord(st, hash)
	if !ok {
		t.Fatal("expected stored malicious vote evidence record")
	}
	if rec.Number != 64 || rec.Signer != signer || rec.SubmittedBy != msg.From() || rec.SubmittedAt != 77 {
		t.Fatalf("unexpected record: %+v", rec)
	}
	if rec.OffenseKey != MaliciousVoteOffenseKey(signer, 64) {
		t.Fatalf("unexpected offense key: %s", rec.OffenseKey.Hex())
	}
	if got := ReadMaliciousVoteEvidenceCount(st); got != 1 {
		t.Fatalf("evidence count = %d, want 1", got)
	}
}

func TestSlashIndicatorRejectsDuplicateOffense(t *testing.T) {
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	st, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	pub, priv, signer := testEd25519Key(0x71)
	makeEnv := func(hash common.Hash) *types.CheckpointVoteEnvelope {
		env := &types.CheckpointVoteEnvelope{
			Vote:   types.CheckpointVote{ChainID: big.NewInt(42), Number: 64, Hash: hash, ValidatorSetHash: common.HexToHash("0xaaaa")},
			Signer: signer,
		}
		h := env.Vote.SigningHash()
		copy(env.Signature[:], ed25519.Sign(priv, h[:]))
		return env
	}
	firstEvidence, err := types.NewMaliciousVoteEvidence(makeEnv(common.HexToHash("0x1111")), makeEnv(common.HexToHash("0x2222")), "ed25519", pub)
	if err != nil {
		t.Fatalf("NewMaliciousVoteEvidence first: %v", err)
	}
	secondEvidence, err := types.NewMaliciousVoteEvidence(makeEnv(common.HexToHash("0x1111")), makeEnv(common.HexToHash("0x3333")), "ed25519", pub)
	if err != nil {
		t.Fatalf("NewMaliciousVoteEvidence second: %v", err)
	}
	cfg := &params.ChainConfig{ChainID: big.NewInt(42)}
	validator.WriteValidatorStatus(st, signer, validator.Active)
	to := params.CheckpointSlashIndicatorAddress
	firstInput, _ := PackSubmitFinalityViolationEvidence(firstEvidence)
	firstMsg := types.NewMessage(common.HexToAddress("0x100"), &to, 0, big.NewInt(0), 500000, params.TxPrice(), params.TxPrice(), params.TxPrice(), firstInput, nil, true)
	if _, err := ExecuteSlashIndicator(firstMsg, st, big.NewInt(77), cfg); err != nil {
		t.Fatalf("ExecuteSlashIndicator first: %v", err)
	}
	secondInput, _ := PackSubmitFinalityViolationEvidence(secondEvidence)
	secondMsg := types.NewMessage(common.HexToAddress("0x101"), &to, 0, big.NewInt(0), 500000, params.TxPrice(), params.TxPrice(), params.TxPrice(), secondInput, nil, true)
	if _, err := ExecuteSlashIndicator(secondMsg, st, big.NewInt(78), cfg); err == nil {
		t.Fatal("expected duplicate offense rejection")
	}
}
