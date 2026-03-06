package reputation

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/capability"
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

var h = &reputationHandler{}

// TestAuthorizeScorer verifies a Registrar can authorize a scorer.
func TestAuthorizeScorer(t *testing.T) {
	st := newTestState()
	registrar := tAddr(0x01)
	scorer := tAddr(0x02)
	capability.GrantCapability(st, registrar, registrarBit)

	payload, _ := json.Marshal(authorizeScorerPayload{Scorer: scorer.Hex(), Enabled: true})
	sa := &sysaction.SysAction{Action: sysaction.ActionReputationAuthorizeScorer, Payload: payload}
	if err := h.Handle(newCtx(st, registrar), sa); err != nil {
		t.Fatalf("authorize scorer: %v", err)
	}
	if !IsAuthorizedScorer(st, scorer) {
		t.Error("expected scorer to be authorized")
	}
}

// TestAuthorizeScorerRequiresRegistrar verifies non-Registrar cannot authorize.
func TestAuthorizeScorerRequiresRegistrar(t *testing.T) {
	st := newTestState()
	nonRegistrar := tAddr(0x03)
	scorer := tAddr(0x04)

	payload, _ := json.Marshal(authorizeScorerPayload{Scorer: scorer.Hex(), Enabled: true})
	sa := &sysaction.SysAction{Action: sysaction.ActionReputationAuthorizeScorer, Payload: payload}
	if err := h.Handle(newCtx(st, nonRegistrar), sa); err != ErrRegistrarRequired {
		t.Errorf("want ErrRegistrarRequired, got %v", err)
	}
}

// TestRevokeScorer verifies a scorer can be de-authorized.
func TestRevokeScorer(t *testing.T) {
	st := newTestState()
	registrar := tAddr(0x05)
	scorer := tAddr(0x06)
	capability.GrantCapability(st, registrar, registrarBit)
	AuthorizeScorer(st, scorer, true)

	payload, _ := json.Marshal(authorizeScorerPayload{Scorer: scorer.Hex(), Enabled: false})
	sa := &sysaction.SysAction{Action: sysaction.ActionReputationAuthorizeScorer, Payload: payload}
	if err := h.Handle(newCtx(st, registrar), sa); err != nil {
		t.Fatalf("revoke scorer: %v", err)
	}
	if IsAuthorizedScorer(st, scorer) {
		t.Error("expected scorer to be de-authorized")
	}
}

// TestRecordScoreHappyPath verifies an authorized scorer can record a positive score.
func TestRecordScoreHappyPath(t *testing.T) {
	st := newTestState()
	scorer := tAddr(0x07)
	who := tAddr(0x08)
	AuthorizeScorer(st, scorer, true)

	payload, _ := json.Marshal(recordScorePayload{Who: who.Hex(), Delta: "10", Reason: "good job", RefID: "tx-1"})
	sa := &sysaction.SysAction{Action: sysaction.ActionReputationRecordScore, Payload: payload}
	if err := h.Handle(newCtx(st, scorer), sa); err != nil {
		t.Fatalf("record score: %v", err)
	}

	score := TotalScoreOf(st, who)
	if score.Cmp(big.NewInt(10)) != 0 {
		t.Errorf("score: want 10, got %v", score)
	}
	if RatingCountOf(st, who).Cmp(big.NewInt(1)) != 0 {
		t.Error("rating count must be 1")
	}
}

// TestRecordScoreNegativeDelta verifies negative scores work correctly.
func TestRecordScoreNegativeDelta(t *testing.T) {
	st := newTestState()
	scorer := tAddr(0x09)
	who := tAddr(0x0A)
	AuthorizeScorer(st, scorer, true)

	// Record +5 then -3 → net +2.
	for _, delta := range []string{"5", "-3"} {
		payload, _ := json.Marshal(recordScorePayload{Who: who.Hex(), Delta: delta})
		sa := &sysaction.SysAction{Action: sysaction.ActionReputationRecordScore, Payload: payload}
		if err := h.Handle(newCtx(st, scorer), sa); err != nil {
			t.Fatalf("record score (%s): %v", delta, err)
		}
	}

	score := TotalScoreOf(st, who)
	if score.Cmp(big.NewInt(2)) != 0 {
		t.Errorf("net score: want 2, got %v", score)
	}
	if RatingCountOf(st, who).Cmp(big.NewInt(2)) != 0 {
		t.Error("rating count must be 2")
	}
}

// TestRecordScoreUnauthorized verifies non-scorer cannot record.
func TestRecordScoreUnauthorized(t *testing.T) {
	st := newTestState()
	nonScorer := tAddr(0x0B)
	who := tAddr(0x0C)

	payload, _ := json.Marshal(recordScorePayload{Who: who.Hex(), Delta: "1"})
	sa := &sysaction.SysAction{Action: sysaction.ActionReputationRecordScore, Payload: payload}
	if err := h.Handle(newCtx(st, nonScorer), sa); err != ErrNotAuthorizedScorer {
		t.Errorf("want ErrNotAuthorizedScorer, got %v", err)
	}
}

// TestRecordScoreCrossInvariant verifies that RecordScore (direct call) accumulates correctly.
func TestRecordScoreCrossInvariant(t *testing.T) {
	st := newTestState()
	who := tAddr(0x0D)

	// Accumulate 100 positive ratings and 10 negative ones.
	for i := 0; i < 100; i++ {
		RecordScore(st, who, big.NewInt(1))
	}
	for i := 0; i < 10; i++ {
		RecordScore(st, who, big.NewInt(-1))
	}

	score := TotalScoreOf(st, who)
	if score.Cmp(big.NewInt(90)) != 0 {
		t.Errorf("net score: want 90, got %v", score)
	}
	if RatingCountOf(st, who).Cmp(big.NewInt(110)) != 0 {
		t.Errorf("rating count: want 110, got %v", RatingCountOf(st, who))
	}
}
