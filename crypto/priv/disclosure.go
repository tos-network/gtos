package priv

import "github.com/tos-network/gtos/crypto/ed25519"

// ProveDisclosureExact generates a 96-byte DLEQ proof that privkey's account
// holds exactly amount in the given 64-byte ciphertext, bound to ctx.
func ProveDisclosureExact(privkey, pubkey []byte, ct64 []byte, amount uint64, ctx []byte) ([]byte, error) {
	proof, err := ed25519.ProvePrivDisclosureExact(privkey, pubkey, ct64, amount, ctx)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return proof, nil
}

// VerifyDisclosureExact verifies a 96-byte DLEQ disclosure proof.
func VerifyDisclosureExact(pubkey []byte, ct64 []byte, amount uint64, proof96, ctx []byte) error {
	return mapBackendError(ed25519.VerifyPrivDisclosureExact(pubkey, ct64, amount, proof96, ctx))
}

// ProveAuditorHandleDLEQ generates a 96-byte DLEQ proof for same-randomness.
func ProveAuditorHandleDLEQ(opening, pkAudit, pkReceiver, dAudit, dReceiver []byte, ctx []byte) ([]byte, error) {
	proof, err := ed25519.ProveAuditorHandleDLEQ(opening, pkAudit, pkReceiver, dAudit, dReceiver, ctx)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return proof, nil
}

// VerifyAuditorHandleDLEQ verifies a 96-byte auditor handle DLEQ proof.
func VerifyAuditorHandleDLEQ(proof96, pkAudit, pkReceiver, dAudit, dReceiver []byte, ctx []byte) error {
	return mapBackendError(ed25519.VerifyAuditorHandleDLEQ(proof96, pkAudit, pkReceiver, dAudit, dReceiver, ctx))
}
