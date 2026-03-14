package group

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

func newTestState() *state.StateDB {
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	s, _ := state.New(common.Hash{}, db, nil)
	return s
}

func newCtx(st *state.StateDB, from common.Address) *sysaction.Context {
	return &sysaction.Context{
		From:        from,
		Value:       big.NewInt(0),
		BlockNumber: big.NewInt(1),
		StateDB:     st,
		ChainConfig: &params.ChainConfig{},
	}
}

func tAddr(b byte) common.Address { return common.Address{b} }

var h = &groupHandler{}

func TestRegisterGroup(t *testing.T) {
	st := newTestState()
	creator := tAddr(0x01)

	payload, _ := json.Marshal(registerPayload{
		GroupID:         "test-group-1",
		ManifestHash:    "0xabcdef",
		TreasuryAddress: tAddr(0x02).Hex(),
		MembersRoot:     "0x112233",
	})
	sa := &sysaction.SysAction{Action: sysaction.ActionGroupRegister, Payload: payload}
	if err := h.Handle(newCtx(st, creator), sa); err != nil {
		t.Fatalf("register group: %v", err)
	}

	if !IsGroupRegistered(st, "test-group-1") {
		t.Error("expected group to be registered")
	}
	if got := GetGroupCreatorAddress(st, "test-group-1"); got != creator {
		t.Errorf("creator: want %s, got %s", creator.Hex(), got.Hex())
	}
	if got := GetGroupTreasuryAddress(st, "test-group-1"); got != tAddr(0x02) {
		t.Errorf("treasury: want %s, got %s", tAddr(0x02).Hex(), got.Hex())
	}
	if got := GetGroupEpoch(st, "test-group-1"); got != 1 {
		t.Errorf("epoch: want 1, got %d", got)
	}
	if got := GetGroupCommitCount(st, "test-group-1"); got != 0 {
		t.Errorf("commit_count: want 0, got %d", got)
	}
}

func TestRegisterDuplicateGroup(t *testing.T) {
	st := newTestState()
	creator := tAddr(0x01)

	payload, _ := json.Marshal(registerPayload{
		GroupID:    "dup-group",
		MembersRoot: "0x01",
	})
	sa := &sysaction.SysAction{Action: sysaction.ActionGroupRegister, Payload: payload}

	if err := h.Handle(newCtx(st, creator), sa); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := h.Handle(newCtx(st, creator), sa); err != ErrGroupAlreadyRegistered {
		t.Errorf("want ErrGroupAlreadyRegistered, got %v", err)
	}
}

func TestRegisterGroupEmptyID(t *testing.T) {
	st := newTestState()
	creator := tAddr(0x01)

	payload, _ := json.Marshal(registerPayload{GroupID: ""})
	sa := &sysaction.SysAction{Action: sysaction.ActionGroupRegister, Payload: payload}

	if err := h.Handle(newCtx(st, creator), sa); err != ErrGroupIDRequired {
		t.Errorf("want ErrGroupIDRequired, got %v", err)
	}
}

func TestStateCommitSuccess(t *testing.T) {
	st := newTestState()
	creator := tAddr(0x10)

	// Register first.
	regPayload, _ := json.Marshal(registerPayload{
		GroupID:    "commit-group",
		MembersRoot: "0x01",
	})
	regSa := &sysaction.SysAction{Action: sysaction.ActionGroupRegister, Payload: regPayload}
	if err := h.Handle(newCtx(st, creator), regSa); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Commit state.
	commitPayload, _ := json.Marshal(stateCommitPayload{
		GroupID:            "commit-group",
		Epoch:              2,
		MembersRoot:        "0xaabb",
		EventsMerkleRoot:   "0xccdd",
		TreasuryBalanceWei: "1000000000000000000",
	})
	commitSa := &sysaction.SysAction{Action: sysaction.ActionGroupStateCommit, Payload: commitPayload}
	if err := h.Handle(newCtx(st, creator), commitSa); err != nil {
		t.Fatalf("state commit: %v", err)
	}

	if got := GetGroupEpoch(st, "commit-group"); got != 2 {
		t.Errorf("epoch: want 2, got %d", got)
	}
	if got := GetGroupCommitCount(st, "commit-group"); got != 1 {
		t.Errorf("commit_count: want 1, got %d", got)
	}
	expectedBal := new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18))
	if got := GetGroupTreasuryBalance(st, "commit-group"); got.Cmp(expectedBal) != 0 {
		t.Errorf("treasury_balance: want %s, got %s", expectedBal, got)
	}
}

func TestStateCommitUnregisteredGroup(t *testing.T) {
	st := newTestState()
	sender := tAddr(0x20)

	payload, _ := json.Marshal(stateCommitPayload{
		GroupID: "nonexistent",
		Epoch:   1,
	})
	sa := &sysaction.SysAction{Action: sysaction.ActionGroupStateCommit, Payload: payload}
	if err := h.Handle(newCtx(st, sender), sa); err != ErrGroupNotRegistered {
		t.Errorf("want ErrGroupNotRegistered, got %v", err)
	}
}

func TestStateCommitNonCreator(t *testing.T) {
	st := newTestState()
	creator := tAddr(0x30)
	other := tAddr(0x31)

	// Register as creator.
	regPayload, _ := json.Marshal(registerPayload{
		GroupID:    "auth-group",
		MembersRoot: "0x01",
	})
	regSa := &sysaction.SysAction{Action: sysaction.ActionGroupRegister, Payload: regPayload}
	if err := h.Handle(newCtx(st, creator), regSa); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Try to commit as non-creator.
	commitPayload, _ := json.Marshal(stateCommitPayload{
		GroupID: "auth-group",
		Epoch:   2,
	})
	commitSa := &sysaction.SysAction{Action: sysaction.ActionGroupStateCommit, Payload: commitPayload}
	if err := h.Handle(newCtx(st, other), commitSa); err != ErrNotGroupCreator {
		t.Errorf("want ErrNotGroupCreator, got %v", err)
	}
}
