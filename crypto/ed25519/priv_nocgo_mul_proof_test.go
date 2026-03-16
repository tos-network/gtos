//go:build !cgo || !ed25519c

package ed25519

import (
	"testing"
)

func TestMulProofRoundTrip(t *testing.T) {
	// a=3, b=7, c=21
	a := uint64(3)
	b := uint64(7)
	c := a * b

	rA, err := randomScalar()
	if err != nil {
		t.Fatal(err)
	}
	rB, err := randomScalar()
	if err != nil {
		t.Fatal(err)
	}
	rC, err := randomScalar()
	if err != nil {
		t.Fatal(err)
	}

	comA := pedersenCommit(a, rA)
	comB := pedersenCommit(b, rB)
	comC := pedersenCommit(c, rC)

	aScalar := u64ToLEScalar(a)

	proof, err := provePrivMulProof(
		comA.Bytes(), comB.Bytes(), comC.Bytes(),
		aScalar.Bytes(), rA.Bytes(), rB.Bytes(), rC.Bytes(),
	)
	if err != nil {
		t.Fatalf("provePrivMulProof: %v", err)
	}

	if len(proof) != mulProofSize {
		t.Fatalf("proof size: got %d, want %d", len(proof), mulProofSize)
	}

	if err := verifyPrivMulProof(proof, comA.Bytes(), comB.Bytes(), comC.Bytes()); err != nil {
		t.Fatalf("verifyPrivMulProof: %v", err)
	}
}

func TestMulProofWrongProduct(t *testing.T) {
	a := uint64(3)
	b := uint64(7)
	wrongC := uint64(22) // should be 21

	rA, _ := randomScalar()
	rB, _ := randomScalar()
	rC, _ := randomScalar()

	comA := pedersenCommit(a, rA)
	comB := pedersenCommit(b, rB)
	comC := pedersenCommit(wrongC, rC) // wrong product

	aScalar := u64ToLEScalar(a)

	proof, err := provePrivMulProof(
		comA.Bytes(), comB.Bytes(), comC.Bytes(),
		aScalar.Bytes(), rA.Bytes(), rB.Bytes(), rC.Bytes(),
	)
	if err != nil {
		t.Fatalf("provePrivMulProof: %v", err)
	}

	// Verification should fail because c != a*b.
	if err := verifyPrivMulProof(proof, comA.Bytes(), comB.Bytes(), comC.Bytes()); err == nil {
		t.Fatal("expected verification to fail for wrong product")
	}
}

func TestMulProofTamperedProof(t *testing.T) {
	a := uint64(5)
	b := uint64(4)
	c := a * b

	rA, _ := randomScalar()
	rB, _ := randomScalar()
	rC, _ := randomScalar()

	comA := pedersenCommit(a, rA)
	comB := pedersenCommit(b, rB)
	comC := pedersenCommit(c, rC)

	aScalar := u64ToLEScalar(a)

	proof, err := provePrivMulProof(
		comA.Bytes(), comB.Bytes(), comC.Bytes(),
		aScalar.Bytes(), rA.Bytes(), rB.Bytes(), rC.Bytes(),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the proof.
	proof[10] ^= 0xFF

	if err := verifyPrivMulProof(proof, comA.Bytes(), comB.Bytes(), comC.Bytes()); err == nil {
		t.Fatal("expected verification to fail for tampered proof")
	}
}

func TestMulProofLargeValues(t *testing.T) {
	a := uint64(1000000)
	b := uint64(999999)
	c := a * b

	rA, _ := randomScalar()
	rB, _ := randomScalar()
	rC, _ := randomScalar()

	comA := pedersenCommit(a, rA)
	comB := pedersenCommit(b, rB)
	comC := pedersenCommit(c, rC)

	aScalar := u64ToLEScalar(a)

	proof, err := provePrivMulProof(
		comA.Bytes(), comB.Bytes(), comC.Bytes(),
		aScalar.Bytes(), rA.Bytes(), rB.Bytes(), rC.Bytes(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := verifyPrivMulProof(proof, comA.Bytes(), comB.Bytes(), comC.Bytes()); err != nil {
		t.Fatalf("verifyPrivMulProof: %v", err)
	}
}

func TestMulProofZeroMultiplier(t *testing.T) {
	a := uint64(0)
	b := uint64(42)
	c := a * b // 0

	rA, _ := randomScalar()
	rB, _ := randomScalar()
	rC, _ := randomScalar()

	comA := pedersenCommit(a, rA)
	comB := pedersenCommit(b, rB)
	comC := pedersenCommit(c, rC)

	aScalar := u64ToLEScalar(a)

	proof, err := provePrivMulProof(
		comA.Bytes(), comB.Bytes(), comC.Bytes(),
		aScalar.Bytes(), rA.Bytes(), rB.Bytes(), rC.Bytes(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := verifyPrivMulProof(proof, comA.Bytes(), comB.Bytes(), comC.Bytes()); err != nil {
		t.Fatalf("verifyPrivMulProof: %v", err)
	}
}

func TestMulProofExportedAPI(t *testing.T) {
	a := uint64(6)
	b := uint64(9)
	c := a * b

	rA, _ := randomScalar()
	rB, _ := randomScalar()
	rC, _ := randomScalar()

	comA := pedersenCommit(a, rA)
	comB := pedersenCommit(b, rB)
	comC := pedersenCommit(c, rC)

	aScalar := u64ToLEScalar(a)

	proof, err := ProvePrivMulProof(
		comA.Bytes(), comB.Bytes(), comC.Bytes(),
		aScalar.Bytes(), rA.Bytes(), rB.Bytes(), rC.Bytes(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyPrivMulProof(proof, comA.Bytes(), comB.Bytes(), comC.Bytes()); err != nil {
		t.Fatalf("VerifyPrivMulProof: %v", err)
	}
}
