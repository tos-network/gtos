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
	"github.com/tos-network/gtos/sysaction"
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
		Vote: types.CheckpointVote{
			ChainID:          big.NewInt(42),
			Number:           64,
			Hash:             common.HexToHash("0x1111"),
			ValidatorSetHash: common.HexToHash("0xabcd"),
		},
		Signer: signer,
	}
	firstHash := first.Vote.SigningHash()
	copy(first.Signature[:], ed25519.Sign(priv, firstHash[:]))
	second := &types.CheckpointVoteEnvelope{
		Vote: types.CheckpointVote{
			ChainID:          big.NewInt(42),
			Number:           64,
			Hash:             common.HexToHash("0x2222"),
			ValidatorSetHash: common.HexToHash("0xabcd"),
		},
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

func TestBuildSubmitMaliciousVoteEvidenceTxBuildsSystemActionTx(t *testing.T) {
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
	if tx.To() == nil || *tx.To() != params.SystemActionAddress {
		t.Fatalf("unexpected tx to: %v", tx.To())
	}
}

func TestBuildAdjudicateMaliciousVoteEvidenceTxBuildsSystemActionTx(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	from := common.HexToAddress("0xbeef")
	res, err := api.BuildAdjudicateMaliciousVoteEvidenceTx(context.Background(), RPCAdjudicateMaliciousVoteEvidenceArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: from},
		EvidenceHash:    common.HexToHash("0x1234"),
	})
	if err != nil {
		t.Fatalf("BuildAdjudicateMaliciousVoteEvidenceTx: %v", err)
	}
	if len(res.Raw) == 0 {
		t.Fatal("expected raw tx bytes")
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(res.Raw); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if tx.To() == nil || *tx.To() != params.SystemActionAddress {
		t.Fatalf("unexpected tx to: %v", tx.To())
	}
}

func TestGetAndListMaliciousVoteEvidence(t *testing.T) {
	backend := newBackendMock()
	backend.config.DPoS = &params.DPoSConfig{MaliciousVoteSlashBips: 10_000}
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	st, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	backend.state = st
	api := NewTOSAPI(backend)
	evidence := testMaliciousVoteEvidence(t)
	payload, err := sysaction.MakeSysAction(sysaction.ActionCheckpointSubmitMaliciousVoteEvidence, evidence)
	if err != nil {
		t.Fatalf("MakeSysAction: %v", err)
	}
	submitter := common.HexToAddress("0x200")
	if err := sysaction.ExecuteWithContext(&sysaction.Context{
		From:        submitter,
		Value:       big.NewInt(0),
		BlockNumber: big.NewInt(77),
		StateDB:     st,
		ChainConfig: backend.config,
	}, payload); err != nil {
		t.Fatalf("ExecuteWithContext: %v", err)
	}
	hash := evidence.Hash()

	rec, err := api.GetMaliciousVoteEvidence(context.Background(), hash, nil)
	if err != nil {
		t.Fatalf("GetMaliciousVoteEvidence: %v", err)
	}
	if rec == nil || rec.Number != 64 || rec.Signer != evidence.Signer || rec.SubmittedBy != submitter || rec.SubmittedAt != 77 {
		t.Fatalf("unexpected evidence record: %+v", rec)
	}
	list, err := api.ListMaliciousVoteEvidence(context.Background(), 10, nil)
	if err != nil {
		t.Fatalf("ListMaliciousVoteEvidence: %v", err)
	}
	if len(list) != 1 || list[0].EvidenceHash != hash {
		t.Fatalf("unexpected evidence list: %+v", list)
	}
}

func TestGetMaliciousVoteEvidenceShowsAdjudicationFields(t *testing.T) {
	backend := newBackendMock()
	backend.config.DPoS = &params.DPoSConfig{MaliciousVoteSlashBips: 10_000}
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	st, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	backend.state = st
	api := NewTOSAPI(backend)
	evidence := testMaliciousVoteEvidence(t)
	submitPayload, err := sysaction.MakeSysAction(sysaction.ActionCheckpointSubmitMaliciousVoteEvidence, evidence)
	if err != nil {
		t.Fatalf("MakeSysAction submit: %v", err)
	}
	if err := sysaction.ExecuteWithContext(&sysaction.Context{
		From:        common.HexToAddress("0x200"),
		Value:       big.NewInt(0),
		BlockNumber: big.NewInt(77),
		StateDB:     st,
		ChainConfig: backend.config,
	}, submitPayload); err != nil {
		t.Fatalf("submit ExecuteWithContext: %v", err)
	}
	st.AddBalance(evidence.Signer, params.DPoSMinValidatorStake)
	registerPayload, err := sysaction.MakeSysAction(sysaction.ActionValidatorRegister, nil)
	if err != nil {
		t.Fatalf("MakeSysAction register: %v", err)
	}
	if err := sysaction.ExecuteWithContext(&sysaction.Context{
		From:        evidence.Signer,
		Value:       new(big.Int).Set(params.DPoSMinValidatorStake),
		BlockNumber: big.NewInt(78),
		StateDB:     st,
		ChainConfig: backend.config,
	}, registerPayload); err != nil {
		t.Fatalf("register ExecuteWithContext: %v", err)
	}
	adjPayload, err := sysaction.MakeSysAction(sysaction.ActionCheckpointAdjudicateMaliciousVoteEvidence, dpos.AdjudicateMaliciousVoteEvidencePayload{
		EvidenceHash: evidence.Hash(),
	})
	if err != nil {
		t.Fatalf("MakeSysAction adjudicate: %v", err)
	}
	if err := sysaction.ExecuteWithContext(&sysaction.Context{
		From:        common.HexToAddress("0x201"),
		Value:       big.NewInt(0),
		BlockNumber: big.NewInt(88),
		StateDB:     st,
		ChainConfig: backend.config,
	}, adjPayload); err != nil {
		t.Fatalf("adjudicate ExecuteWithContext: %v", err)
	}
	rec, err := api.GetMaliciousVoteEvidence(context.Background(), evidence.Hash(), nil)
	if err != nil {
		t.Fatalf("GetMaliciousVoteEvidence: %v", err)
	}
	if rec == nil || rec.Status != "adjudicated" || rec.AdjudicatedAt != 88 || rec.SlashAmount == nil || (*big.Int)(rec.SlashAmount).Sign() == 0 {
		t.Fatalf("unexpected adjudicated record: %+v", rec)
	}
}
