package priv

import "github.com/tos-network/gtos/crypto/ed25519"

type BatchVerifier struct {
	inner *ed25519.PrivBatchVerifier
}

func NewBatchVerifier() *BatchVerifier {
	return &BatchVerifier{inner: ed25519.NewPrivBatchVerifier()}
}

func (b *BatchVerifier) AddShieldProofWithContext(proof96, commitment, receiverHandle, receiverPubkey []byte, amount uint64, ctx []byte) error {
	return mapBackendError(b.inner.AddPrivShieldProofWithContext(proof96, commitment, receiverHandle, receiverPubkey, amount, ctx))
}

func (b *BatchVerifier) AddCTValidityProofWithContext(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey []byte, txVersionT1 bool, ctx []byte) error {
	return mapBackendError(b.inner.AddPrivCTValidityProofWithContext(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey, txVersionT1, ctx))
}

func (b *BatchVerifier) AddCommitmentEqProofWithContext(proof192, sourcePubkey, sourceCiphertext64, destinationCommitment []byte, ctx []byte) error {
	return mapBackendError(b.inner.AddPrivCommitmentEqProofWithContext(proof192, sourcePubkey, sourceCiphertext64, destinationCommitment, ctx))
}

func (b *BatchVerifier) AddRangeProof(proof []byte, commitments []byte, bitLengths []byte, batchLen uint8) error {
	return mapBackendError(b.inner.AddPrivRangeProof(proof, commitments, bitLengths, batchLen))
}

func (b *BatchVerifier) Verify() error {
	return mapBackendError(b.inner.Verify())
}
