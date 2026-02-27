package uno

import "github.com/tos-network/gtos/crypto/ed25519"

func ProveShieldProofWithContext(receiverPubkey []byte, amount uint64, opening32 []byte, ctx []byte) (proof96 []byte, commitment32 []byte, receiverHandle32 []byte, err error) {
	proof96, commitment32, receiverHandle32, err = ed25519.ProveUNOShieldProofWithContext(receiverPubkey, amount, opening32, ctx)
	if err != nil {
		return nil, nil, nil, mapBackendError(err)
	}
	return proof96, commitment32, receiverHandle32, nil
}

func ProveShieldProof(receiverPubkey []byte, amount uint64, opening32 []byte) (proof96 []byte, commitment32 []byte, receiverHandle32 []byte, err error) {
	proof96, commitment32, receiverHandle32, err = ed25519.ProveUNOShieldProof(receiverPubkey, amount, opening32)
	if err != nil {
		return nil, nil, nil, mapBackendError(err)
	}
	return proof96, commitment32, receiverHandle32, nil
}

func ProveCTValidityProofWithContext(senderPubkey, receiverPubkey []byte, amount uint64, opening32 []byte, txVersionT1 bool, ctx []byte) (proof []byte, commitment32 []byte, senderHandle32 []byte, receiverHandle32 []byte, err error) {
	proof, commitment32, senderHandle32, receiverHandle32, err = ed25519.ProveUNOCTValidityProofWithContext(senderPubkey, receiverPubkey, amount, opening32, txVersionT1, ctx)
	if err != nil {
		return nil, nil, nil, nil, mapBackendError(err)
	}
	return proof, commitment32, senderHandle32, receiverHandle32, nil
}

func ProveCTValidityProof(senderPubkey, receiverPubkey []byte, amount uint64, opening32 []byte, txVersionT1 bool) (proof []byte, commitment32 []byte, senderHandle32 []byte, receiverHandle32 []byte, err error) {
	proof, commitment32, senderHandle32, receiverHandle32, err = ed25519.ProveUNOCTValidityProof(senderPubkey, receiverPubkey, amount, opening32, txVersionT1)
	if err != nil {
		return nil, nil, nil, nil, mapBackendError(err)
	}
	return proof, commitment32, senderHandle32, receiverHandle32, nil
}

func ProveBalanceProofWithContext(sourcePrivkey32, sourceCiphertext64 []byte, amount uint64, ctx []byte) ([]byte, error) {
	proof, err := ed25519.ProveUNOBalanceProofWithContext(sourcePrivkey32, sourceCiphertext64, amount, ctx)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return proof, nil
}

func ProveBalanceProof(sourcePrivkey32, sourceCiphertext64 []byte, amount uint64) ([]byte, error) {
	proof, err := ed25519.ProveUNOBalanceProof(sourcePrivkey32, sourceCiphertext64, amount)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return proof, nil
}
