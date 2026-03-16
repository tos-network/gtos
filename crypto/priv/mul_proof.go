package priv

import (
	"encoding/binary"

	"github.com/tos-network/gtos/crypto/ed25519"
)

// ProveMulProof generates a 160-byte multiplication Sigma proof proving that
// the value committed in comC equals the product of the values committed in
// comA and comB. The prover must supply the plaintext value aVal (of comA)
// and all three blinding factors.
func ProveMulProof(comA, comB, comC []byte, aVal uint64, rA, rB, rC []byte) ([]byte, error) {
	var aScalar [32]byte
	binary.LittleEndian.PutUint64(aScalar[:8], aVal)
	proof, err := ed25519.ProvePrivMulProof(comA, comB, comC, aScalar[:], rA, rB, rC)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return proof, nil
}

// VerifyMulProof verifies a 160-byte multiplication Sigma proof against three
// 32-byte Pedersen commitments.
func VerifyMulProof(proof, comA, comB, comC []byte) error {
	return mapBackendError(ed25519.VerifyPrivMulProof(proof, comA, comB, comC))
}
