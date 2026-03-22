package verifyregistry

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
		BlockNumber: big.NewInt(7),
		StateDB:     st,
		ChainConfig: &params.ChainConfig{},
	}
}

func makeSysAction(t *testing.T, action sysaction.ActionKind, payload any) *sysaction.SysAction {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return &sysaction.SysAction{Action: action, Payload: raw}
}

func TestRegisterVerifierAndAttestSubject(t *testing.T) {
	st := newTestState()
	h := &handler{}
	verifier := common.HexToAddress("0x1234000000000000000000000000000000000000")

	register := makeSysAction(t, sysaction.ActionRegistryRegisterVerifier, registerVerifierPayload{
		Name:         "state_proof",
		VerifierType: 1,
		VerifierAddr: verifier.Hex(),
		Version:      1,
	})
	if err := h.Handle(newCtx(st, verifier), register); err != nil {
		t.Fatalf("register verifier: %v", err)
	}
	rec := ReadVerifier(st, "state_proof")
	if rec.Name != "state_proof" || rec.Status != VerifierActive {
		t.Fatalf("unexpected verifier record %+v", rec)
	}

	subject := common.HexToAddress("0xabcd")
	attest := makeSysAction(t, sysaction.ActionRegistryAttestVerification, subjectVerificationPayload{
		Subject:   subject.Hex(),
		ProofType: "state_proof",
		ExpiryMS:  2_000_000_000_000,
	})
	if err := h.Handle(newCtx(st, verifier), attest); err != nil {
		t.Fatalf("attest verification: %v", err)
	}
	claim := ReadSubjectVerification(st, subject, "state_proof")
	if claim.Subject != subject || claim.Status != VerificationActive || claim.VerifiedAt != 7 {
		t.Fatalf("unexpected subject verification %+v", claim)
	}
}

func TestInactiveVerifierBlocksVerificationWrites(t *testing.T) {
	st := newTestState()
	h := &handler{}
	verifier := common.HexToAddress("0x1234000000000000000000000000000000000000")
	subject := common.HexToAddress("0xabcd")

	register := makeSysAction(t, sysaction.ActionRegistryRegisterVerifier, registerVerifierPayload{
		Name:         "state_proof",
		VerifierType: 1,
		VerifierAddr: verifier.Hex(),
		Version:      1,
	})
	if err := h.Handle(newCtx(st, verifier), register); err != nil {
		t.Fatalf("register verifier: %v", err)
	}
	if err := h.Handle(newCtx(st, verifier), makeSysAction(t, sysaction.ActionRegistryDeactivateVerifier, verifierNamePayload{Name: "state_proof"})); err != nil {
		t.Fatalf("deactivate verifier: %v", err)
	}

	attest := makeSysAction(t, sysaction.ActionRegistryAttestVerification, subjectVerificationPayload{
		Subject:   subject.Hex(),
		ProofType: "state_proof",
		ExpiryMS:  2_000_000_000_000,
	})
	if err := h.Handle(newCtx(st, verifier), attest); err != ErrVerifierInactive {
		t.Fatalf("expected verifier inactive error, got %v", err)
	}
	if err := h.Handle(newCtx(st, verifier), makeSysAction(t, sysaction.ActionRegistryDeactivateVerifier, verifierNamePayload{Name: "state_proof"})); err != ErrVerifierAlreadyRevoked {
		t.Fatalf("expected already revoked error, got %v", err)
	}
}

func TestRevokeVerificationRequiresExistingClaim(t *testing.T) {
	st := newTestState()
	h := &handler{}
	verifier := common.HexToAddress("0x1234000000000000000000000000000000000000")
	subject := common.HexToAddress("0xabcd")

	register := makeSysAction(t, sysaction.ActionRegistryRegisterVerifier, registerVerifierPayload{
		Name:         "state_proof",
		VerifierType: 1,
		VerifierAddr: verifier.Hex(),
		Version:      1,
	})
	if err := h.Handle(newCtx(st, verifier), register); err != nil {
		t.Fatalf("register verifier: %v", err)
	}
	revoke := makeSysAction(t, sysaction.ActionRegistryRevokeVerification, subjectVerificationPayload{
		Subject:   subject.Hex(),
		ProofType: "state_proof",
	})
	if err := h.Handle(newCtx(st, verifier), revoke); err != ErrVerificationNotFound {
		t.Fatalf("expected verification not found error, got %v", err)
	}
}

func TestRevokeVerificationTwiceRejected(t *testing.T) {
	st := newTestState()
	h := &handler{}
	verifier := common.HexToAddress("0x1234000000000000000000000000000000000000")
	subject := common.HexToAddress("0xabcd")

	register := makeSysAction(t, sysaction.ActionRegistryRegisterVerifier, registerVerifierPayload{
		Name:         "state_proof",
		VerifierType: 1,
		VerifierAddr: verifier.Hex(),
		Version:      1,
	})
	if err := h.Handle(newCtx(st, verifier), register); err != nil {
		t.Fatalf("register verifier: %v", err)
	}
	attest := makeSysAction(t, sysaction.ActionRegistryAttestVerification, subjectVerificationPayload{
		Subject:   subject.Hex(),
		ProofType: "state_proof",
		ExpiryMS:  2_000_000_000_000,
	})
	if err := h.Handle(newCtx(st, verifier), attest); err != nil {
		t.Fatalf("attest verification: %v", err)
	}
	revoke := makeSysAction(t, sysaction.ActionRegistryRevokeVerification, subjectVerificationPayload{
		Subject:   subject.Hex(),
		ProofType: "state_proof",
	})
	if err := h.Handle(newCtx(st, verifier), revoke); err != nil {
		t.Fatalf("revoke verification: %v", err)
	}
	if err := h.Handle(newCtx(st, verifier), revoke); err != ErrVerificationAlreadyRevoked {
		t.Fatalf("expected already revoked error, got %v", err)
	}
}
