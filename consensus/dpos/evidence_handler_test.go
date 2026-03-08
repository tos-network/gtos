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
	"github.com/tos-network/gtos/validator"
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

func TestCheckpointEvidenceAdjudicationSlashesValidator(t *testing.T) {
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	st, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	pub, priv, signer := testEd25519Key(0x71)
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
	validatorStake := new(big.Int).Set(params.DPoSMinValidatorStake)
	st.AddBalance(signer, validatorStake)
	cfg := &params.ChainConfig{ChainID: big.NewInt(42), DPoS: &params.DPoSConfig{MaliciousVoteSlashBips: 10_000}}
	registerPayload, err := sysaction.MakeSysAction(sysaction.ActionValidatorRegister, nil)
	if err != nil {
		t.Fatalf("MakeSysAction register: %v", err)
	}
	if err := sysaction.ExecuteWithContext(&sysaction.Context{
		From:        signer,
		Value:       validatorStake,
		BlockNumber: big.NewInt(70),
		StateDB:     st,
		ChainConfig: cfg,
	}, registerPayload); err != nil {
		t.Fatalf("register ExecuteWithContext: %v", err)
	}

	submitPayload, err := sysaction.MakeSysAction(sysaction.ActionCheckpointSubmitMaliciousVoteEvidence, evidence)
	if err != nil {
		t.Fatalf("MakeSysAction submit: %v", err)
	}
	if err := sysaction.ExecuteWithContext(&sysaction.Context{
		From:        common.HexToAddress("0xbeef"),
		Value:       big.NewInt(0),
		BlockNumber: big.NewInt(77),
		StateDB:     st,
		ChainConfig: cfg,
	}, submitPayload); err != nil {
		t.Fatalf("submit ExecuteWithContext: %v", err)
	}
	hash := evidence.Hash()
	adjPayload, err := sysaction.MakeSysAction(sysaction.ActionCheckpointAdjudicateMaliciousVoteEvidence, AdjudicateMaliciousVoteEvidencePayload{
		EvidenceHash: hash,
	})
	if err != nil {
		t.Fatalf("MakeSysAction adjudicate: %v", err)
	}
	adjudicator := common.HexToAddress("0xface")
	if err := sysaction.ExecuteWithContext(&sysaction.Context{
		From:        adjudicator,
		Value:       big.NewInt(0),
		BlockNumber: big.NewInt(99),
		StateDB:     st,
		ChainConfig: cfg,
	}, adjPayload); err != nil {
		t.Fatalf("adjudicate ExecuteWithContext: %v", err)
	}
	rec, ok := ReadMaliciousVoteEvidenceRecord(st, hash)
	if !ok {
		t.Fatal("expected adjudicated record")
	}
	if rec.Status != MaliciousVoteEvidenceAdjudicated || rec.AdjudicatedBy != adjudicator || rec.AdjudicatedAt != 99 {
		t.Fatalf("unexpected adjudication record: %+v", rec)
	}
	if rec.SlashAmount == nil || rec.SlashAmount.Cmp(validatorStake) != 0 {
		t.Fatalf("unexpected slash amount: %v", rec.SlashAmount)
	}
	if got := validator.ReadValidatorStatus(st, signer); got != validator.Inactive {
		t.Fatalf("validator status = %d, want inactive", got)
	}
	if got := validator.ReadSelfStake(st, signer); got.Sign() != 0 {
		t.Fatalf("validator selfStake = %v, want 0", got)
	}
	if got := st.GetBalance(params.ValidatorPenaltyVaultAddress); got.Cmp(validatorStake) != 0 {
		t.Fatalf("penalty vault balance = %v, want %v", got, validatorStake)
	}
}
