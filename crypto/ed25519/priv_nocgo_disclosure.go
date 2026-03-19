//go:build !cgo || !ed25519c

package ed25519

import (
	"encoding/binary"

	"github.com/tos-network/gtos/crypto/ristretto255"
)

// DisclosureProofSize is the size of a DLEQ disclosure proof: R₁[32] + R₂[32] + z[32] = 96 bytes.
const DisclosureProofSize = 96

// ProvePrivDisclosureExact generates a DLEQ proof that the prover knows sk such that:
//   - sk·D = C - amount·G  (correct decryption)
//   - sk·PK = H            (key ownership, where H is the Pedersen blinding base)
//
// The proof is bound to the provided context bytes via a Merlin transcript.
//
// Parameters:
//   - privkey32: prover's 32-byte ElGamal private key (sk)
//   - pubkey32: prover's 32-byte ElGamal public key (PK = sk⁻¹·H)
//   - ct64: 64-byte ciphertext (commitment[32] || handle[32])
//   - amount: claimed plaintext balance
//   - ctx: chain-binding context bytes (may be nil)
//
// Returns a 96-byte proof: R₁[32] || R₂[32] || z[32].
func ProvePrivDisclosureExact(privkey32, pubkey32, ct64 []byte, amount uint64, ctx []byte) ([]byte, error) {
	if len(privkey32) != 32 || len(pubkey32) != 32 || len(ct64) != 64 {
		return nil, ErrPrivInvalidInput
	}

	sk, err := decodeScalar(privkey32)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}
	if isScalarZero(sk) {
		return nil, ErrPrivInvalidInput
	}

	PK, err := decodePoint(pubkey32)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}
	C, err := decodePoint(ct64[:32])
	if err != nil {
		return nil, ErrPrivInvalidInput
	}
	D, err := decodePoint(ct64[32:64])
	if err != nil {
		return nil, ErrPrivInvalidInput
	}

	G := getBasepointG()
	H := getPedersenH()

	// target = C - amount·G (should equal sk·D)
	amountScalar := u64ToLEScalar(amount)
	aG := ristretto255.NewIdentityElement().ScalarMult(amountScalar, G)
	target := ristretto255.NewIdentityElement().Subtract(C, aG)

	// Verify prover actually knows the correct amount: sk·D must equal target.
	skD := ristretto255.NewIdentityElement().ScalarMult(sk, D)
	if skD.Equal(target) != 1 {
		return nil, ErrPrivInvalidInput
	}

	// Also verify key ownership: sk·PK must equal H.
	skPK := ristretto255.NewIdentityElement().ScalarMult(sk, PK)
	if skPK.Equal(H) != 1 {
		return nil, ErrPrivInvalidInput
	}

	// Random nonce k.
	k, err := randomScalar()
	if err != nil {
		return nil, ErrPrivOperationFailed
	}

	R1 := ristretto255.NewIdentityElement().ScalarMult(k, D)
	R2 := ristretto255.NewIdentityElement().ScalarMult(k, PK)

	// Build Merlin transcript.
	t := newMerlinTranscript("disclosure-exact")
	if len(ctx) > 0 {
		t.appendMessage("chain-ctx", ctx)
	}
	t.appendMessage("pubkey", pubkey32)
	t.appendMessage("commitment", ct64[:32])
	t.appendMessage("handle", ct64[32:64])
	var amountLE [8]byte
	binary.LittleEndian.PutUint64(amountLE[:], amount)
	t.appendMessage("amount", amountLE[:])
	t.appendMessage("R1", R1.Bytes())
	t.appendMessage("R2", R2.Bytes())

	c := t.challengeScalar("c")

	// z = k + c·sk
	z := scalarMulAdd(c, sk, k)

	proof := make([]byte, 96)
	copy(proof[0:32], R1.Bytes())
	copy(proof[32:64], R2.Bytes())
	copy(proof[64:96], z.Bytes())
	return proof, nil
}

// AuditorHandleDLEQProofSize is the size of an auditor handle DLEQ proof: R₁[32] + R₂[32] + z[32] = 96 bytes.
const AuditorHandleDLEQProofSize = 96

// ProveAuditorHandleDLEQ generates a DLEQ proof that the same randomness r was
// used to create both the receiver handle (D_receiver = r·PK_receiver) and the
// auditor handle (D_audit = r·PK_audit).
//
// This proves: log_{PK_audit}(D_audit) == log_{PK_receiver}(D_receiver)
func ProveAuditorHandleDLEQ(opening32, pkAudit32, pkReceiver32, dAudit32, dReceiver32 []byte, ctx []byte) ([]byte, error) {
	if len(opening32) != 32 || len(pkAudit32) != 32 || len(pkReceiver32) != 32 || len(dAudit32) != 32 || len(dReceiver32) != 32 {
		return nil, ErrPrivInvalidInput
	}

	r, err := decodeScalar(opening32)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}
	if isScalarZero(r) {
		return nil, ErrPrivInvalidInput
	}

	PKaudit, err := decodePoint(pkAudit32)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}
	PKreceiver, err := decodePoint(pkReceiver32)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}

	// Verify consistency: r·PK_audit == D_audit and r·PK_receiver == D_receiver
	expectedDAudit := ristretto255.NewIdentityElement().ScalarMult(r, PKaudit)
	Daudit, err := decodePoint(dAudit32)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}
	if expectedDAudit.Equal(Daudit) != 1 {
		return nil, ErrPrivInvalidInput
	}

	expectedDReceiver := ristretto255.NewIdentityElement().ScalarMult(r, PKreceiver)
	Dreceiver, err := decodePoint(dReceiver32)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}
	if expectedDReceiver.Equal(Dreceiver) != 1 {
		return nil, ErrPrivInvalidInput
	}

	// Random nonce k
	k, err := randomScalar()
	if err != nil {
		return nil, ErrPrivOperationFailed
	}

	R1 := ristretto255.NewIdentityElement().ScalarMult(k, PKaudit)
	R2 := ristretto255.NewIdentityElement().ScalarMult(k, PKreceiver)

	// Build Merlin transcript
	t := newMerlinTranscript("auditor-handle-dleq")
	if len(ctx) > 0 {
		t.appendMessage("chain-ctx", ctx)
	}
	t.appendMessage("pk-audit", pkAudit32)
	t.appendMessage("pk-receiver", pkReceiver32)
	t.appendMessage("d-audit", dAudit32)
	t.appendMessage("d-receiver", dReceiver32)
	t.appendMessage("R1", R1.Bytes())
	t.appendMessage("R2", R2.Bytes())

	c := t.challengeScalar("c")

	// z = k + c·r
	z := scalarMulAdd(c, r, k)

	proof := make([]byte, 96)
	copy(proof[0:32], R1.Bytes())
	copy(proof[32:64], R2.Bytes())
	copy(proof[64:96], z.Bytes())
	return proof, nil
}

// VerifyAuditorHandleDLEQ verifies a DLEQ proof that the same randomness
// was used to create both handle points.
//
// Checks:
//   - z·PK_audit    == R₁ + c·D_audit
//   - z·PK_receiver == R₂ + c·D_receiver
func VerifyAuditorHandleDLEQ(proof96, pkAudit32, pkReceiver32, dAudit32, dReceiver32 []byte, ctx []byte) error {
	if len(proof96) != 96 || len(pkAudit32) != 32 || len(pkReceiver32) != 32 || len(dAudit32) != 32 || len(dReceiver32) != 32 {
		return ErrPrivInvalidInput
	}

	R1, err := decodePoint(proof96[0:32])
	if err != nil {
		return ErrPrivInvalidProof
	}
	R2, err := decodePoint(proof96[32:64])
	if err != nil {
		return ErrPrivInvalidProof
	}
	z, err := decodeScalar(proof96[64:96])
	if err != nil {
		return ErrPrivInvalidProof
	}

	PKaudit, err := decodePoint(pkAudit32)
	if err != nil {
		return ErrPrivInvalidProof
	}
	PKreceiver, err := decodePoint(pkReceiver32)
	if err != nil {
		return ErrPrivInvalidProof
	}
	Daudit, err := decodePoint(dAudit32)
	if err != nil {
		return ErrPrivInvalidProof
	}
	Dreceiver, err := decodePoint(dReceiver32)
	if err != nil {
		return ErrPrivInvalidProof
	}

	// Rebuild transcript
	t := newMerlinTranscript("auditor-handle-dleq")
	if len(ctx) > 0 {
		t.appendMessage("chain-ctx", ctx)
	}
	t.appendMessage("pk-audit", pkAudit32)
	t.appendMessage("pk-receiver", pkReceiver32)
	t.appendMessage("d-audit", dAudit32)
	t.appendMessage("d-receiver", dReceiver32)
	t.appendMessage("R1", proof96[0:32])
	t.appendMessage("R2", proof96[32:64])

	c := t.challengeScalar("c")

	// Check 1: z·PK_audit == R₁ + c·D_audit
	lhs1 := ristretto255.NewIdentityElement().ScalarMult(z, PKaudit)
	cDaudit := ristretto255.NewIdentityElement().ScalarMult(c, Daudit)
	rhs1 := ristretto255.NewIdentityElement().Add(R1, cDaudit)
	if lhs1.Equal(rhs1) != 1 {
		return ErrPrivInvalidProof
	}

	// Check 2: z·PK_receiver == R₂ + c·D_receiver
	lhs2 := ristretto255.NewIdentityElement().ScalarMult(z, PKreceiver)
	cDreceiver := ristretto255.NewIdentityElement().ScalarMult(c, Dreceiver)
	rhs2 := ristretto255.NewIdentityElement().Add(R2, cDreceiver)
	if lhs2.Equal(rhs2) != 1 {
		return ErrPrivInvalidProof
	}

	return nil
}

// VerifyPrivDisclosureExact verifies a DLEQ disclosure proof that the holder
// of pubkey32 has exactly `amount` in the given ciphertext.
//
// Verification checks (both must hold for the same scalar sk):
//   - z·D  == R₁ + c·target   where target = C - amount·G
//   - z·PK == R₂ + c·H        where H is the Pedersen blinding base
func VerifyPrivDisclosureExact(pubkey32, ct64 []byte, amount uint64, proof96, ctx []byte) error {
	if len(pubkey32) != 32 || len(ct64) != 64 || len(proof96) != 96 {
		return ErrPrivInvalidInput
	}

	PK, err := decodePoint(pubkey32)
	if err != nil {
		return ErrPrivInvalidProof
	}
	C, err := decodePoint(ct64[:32])
	if err != nil {
		return ErrPrivInvalidProof
	}
	D, err := decodePoint(ct64[32:64])
	if err != nil {
		return ErrPrivInvalidProof
	}

	R1, err := decodePoint(proof96[0:32])
	if err != nil {
		return ErrPrivInvalidProof
	}
	R2, err := decodePoint(proof96[32:64])
	if err != nil {
		return ErrPrivInvalidProof
	}
	z, err := decodeScalar(proof96[64:96])
	if err != nil {
		return ErrPrivInvalidProof
	}

	G := getBasepointG()
	H := getPedersenH()

	// Rebuild transcript.
	t := newMerlinTranscript("disclosure-exact")
	if len(ctx) > 0 {
		t.appendMessage("chain-ctx", ctx)
	}
	t.appendMessage("pubkey", pubkey32)
	t.appendMessage("commitment", ct64[:32])
	t.appendMessage("handle", ct64[32:64])
	var amountLE [8]byte
	binary.LittleEndian.PutUint64(amountLE[:], amount)
	t.appendMessage("amount", amountLE[:])
	t.appendMessage("R1", proof96[0:32])
	t.appendMessage("R2", proof96[32:64])

	c := t.challengeScalar("c")

	// target = C - amount·G
	amountScalar := u64ToLEScalar(amount)
	aG := ristretto255.NewIdentityElement().ScalarMult(amountScalar, G)
	target := ristretto255.NewIdentityElement().Subtract(C, aG)

	// Check 1: z·D == R₁ + c·target
	lhs1 := ristretto255.NewIdentityElement().ScalarMult(z, D)
	cTarget := ristretto255.NewIdentityElement().ScalarMult(c, target)
	rhs1 := ristretto255.NewIdentityElement().Add(R1, cTarget)
	if lhs1.Equal(rhs1) != 1 {
		return ErrPrivInvalidProof
	}

	// Check 2: z·PK == R₂ + c·H
	lhs2 := ristretto255.NewIdentityElement().ScalarMult(z, PK)
	cH := ristretto255.NewIdentityElement().ScalarMult(c, H)
	rhs2 := ristretto255.NewIdentityElement().Add(R2, cH)
	if lhs2.Equal(rhs2) != 1 {
		return ErrPrivInvalidProof
	}

	return nil
}
