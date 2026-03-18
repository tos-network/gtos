package sysaction

import (
	"errors"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
)

func TestValidateProofHookBuiltInHashModes(t *testing.T) {
	resetProofVerifierRegistry()

	proofData := []byte("receipt-proof")
	expectedRoot := crypto.Keccak256Hash(proofData)

	ok, err := ValidateProofHook(&ProofVerificationHook{
		ProofType:    "receipt",
		ProofData:    proofData,
		ExpectedRoot: expectedRoot,
	})
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if !ok {
		t.Fatal("expected proof to validate")
	}

	ok, err = ValidateProofHook(&ProofVerificationHook{
		ProofType:    "merkle",
		ProofData:    proofData,
		ExpectedRoot: crypto.Keccak256Hash([]byte("different-proof")),
	})
	if !errors.Is(err, ErrProofRootMismatch) {
		t.Fatalf("expected ErrProofRootMismatch, got ok=%v err=%v", ok, err)
	}
}

func TestValidateProofHookZKRequiresRegisteredVerifier(t *testing.T) {
	resetProofVerifierRegistry()

	ok, err := ValidateProofHook(&ProofVerificationHook{
		ProofType: "zk",
		ProofData: []byte("zk-proof"),
	})
	if !errors.Is(err, ErrProofVerifierMissing) {
		t.Fatalf("expected ErrProofVerifierMissing, got ok=%v err=%v", ok, err)
	}
}

func TestValidateProofHookDispatchesRegisteredVerifierByType(t *testing.T) {
	resetProofVerifierRegistry()
	RegisterProofVerifier("zk", func(hook *ProofVerificationHook) (bool, error) {
		return string(hook.ProofData) == "valid-zk-proof", nil
	})

	ok, err := ValidateProofHook(&ProofVerificationHook{
		ProofType: "zk",
		ProofData: []byte("valid-zk-proof"),
	})
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if !ok {
		t.Fatal("expected registered verifier to accept proof")
	}

	ok, err = ValidateProofHook(&ProofVerificationHook{
		ProofType: "zk",
		ProofData: []byte("invalid-zk-proof"),
	})
	if !errors.Is(err, ErrProofVerifierReject) {
		t.Fatalf("expected ErrProofVerifierReject, got ok=%v err=%v", ok, err)
	}
}

func TestValidateProofHookDispatchesRegisteredVerifierByAddress(t *testing.T) {
	resetProofVerifierRegistry()

	verifierAddr := common.HexToAddress("0x1234000000000000000000000000000000000000")
	RegisterProofVerifierAddress(verifierAddr, func(hook *ProofVerificationHook) (bool, error) {
		return hook.ExpectedRoot == crypto.Keccak256Hash(hook.ProofData), nil
	})

	ok, err := ValidateProofHook(&ProofVerificationHook{
		ProofType:    "zk",
		ProofData:    []byte("addr-proof"),
		ExpectedRoot: crypto.Keccak256Hash([]byte("addr-proof")),
		VerifierAddr: verifierAddr,
	})
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if !ok {
		t.Fatal("expected address-based verifier to accept proof")
	}
}
