package verifyregistry

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/capability"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/registry"
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

func grantGovernor(t *testing.T, st *state.StateDB, addr common.Address) {
	t.Helper()
	capability.GrantCapability(st, addr, registry.GovernorCapabilityBit)
}

func TestRegisterVerifierAndAttestSubject(t *testing.T) {
	st := newTestState()
	h := &handler{}
	verifier := common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")

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
	if rec.Name != "state_proof" || rec.Status != VerifierActive || rec.Controller != verifier || rec.CreatedAt != 7 || rec.UpdatedAt != 7 {
		t.Fatalf("unexpected verifier record %+v", rec)
	}

	subject := common.HexToAddress("0x473302ca547d5f9877e272cffe58d4def43198b66ba35cff4b2e584be19efa05")
	attest := makeSysAction(t, sysaction.ActionRegistryAttestVerification, subjectVerificationPayload{
		Subject:   subject.Hex(),
		ProofType: "state_proof",
		ExpiryMS:  2_000_000_000_000,
	})
	if err := h.Handle(newCtx(st, verifier), attest); err != nil {
		t.Fatalf("attest verification: %v", err)
	}
	claim := ReadSubjectVerification(st, subject, "state_proof")
	if claim.Subject != subject || claim.Status != VerificationActive || claim.VerifiedAt != 7 || claim.UpdatedAt != 7 {
		t.Fatalf("unexpected subject verification %+v", claim)
	}
}

func TestInactiveVerifierBlocksVerificationWrites(t *testing.T) {
	st := newTestState()
	h := &handler{}
	verifier := common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")
	subject := common.HexToAddress("0x473302ca547d5f9877e272cffe58d4def43198b66ba35cff4b2e584be19efa05")

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

func TestGovernorCanDeactivateVerifierAndRevokeClaim(t *testing.T) {
	st := newTestState()
	h := &handler{}
	verifier := common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")
	governor := common.HexToAddress("0xf4897a85e6ac20f6b7b22e2c3a8fac52fb6c36430b80655354e5aa4f5e1a3533")
	subject := common.HexToAddress("0x473302ca547d5f9877e272cffe58d4def43198b66ba35cff4b2e584be19efa05")
	grantGovernor(t, st, governor)

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
	if err := h.Handle(newCtx(st, governor), makeSysAction(t, sysaction.ActionRegistryDeactivateVerifier, verifierNamePayload{Name: "state_proof"})); err != nil {
		t.Fatalf("governor deactivate verifier: %v", err)
	}
	revoke := makeSysAction(t, sysaction.ActionRegistryRevokeVerification, subjectVerificationPayload{
		Subject:   subject.Hex(),
		ProofType: "state_proof",
	})
	if err := h.Handle(newCtx(st, governor), revoke); err != nil {
		t.Fatalf("governor revoke verification: %v", err)
	}
	claim := ReadSubjectVerification(st, subject, "state_proof")
	if claim.Status != VerificationRevoked || claim.UpdatedAt != 7 {
		t.Fatalf("unexpected revoked claim %+v", claim)
	}
}

func TestRevokeVerificationRequiresExistingClaim(t *testing.T) {
	st := newTestState()
	h := &handler{}
	verifier := common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")
	subject := common.HexToAddress("0x473302ca547d5f9877e272cffe58d4def43198b66ba35cff4b2e584be19efa05")

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
	verifier := common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")
	subject := common.HexToAddress("0x473302ca547d5f9877e272cffe58d4def43198b66ba35cff4b2e584be19efa05")

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
