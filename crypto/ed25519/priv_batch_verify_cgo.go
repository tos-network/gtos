//go:build cgo && ed25519c

package ed25519

type PrivBatchVerifier struct{}

func NewPrivBatchVerifier() *PrivBatchVerifier {
	return &PrivBatchVerifier{}
}

func (b *PrivBatchVerifier) AddPrivShieldProofWithContext(proof96, commitment, receiverHandle, receiverPubkey []byte, amount uint64, ctx []byte) error {
	_ = b
	_ = proof96
	_ = commitment
	_ = receiverHandle
	_ = receiverPubkey
	_ = amount
	_ = ctx
	return ErrPrivBackendUnavailable
}

func (b *PrivBatchVerifier) AddPrivCTValidityProofWithContext(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey []byte, txVersionT1 bool, ctx []byte) error {
	_ = b
	_ = proof
	_ = commitment
	_ = senderHandle
	_ = receiverHandle
	_ = senderPubkey
	_ = receiverPubkey
	_ = txVersionT1
	_ = ctx
	return ErrPrivBackendUnavailable
}

func (b *PrivBatchVerifier) AddPrivCommitmentEqProofWithContext(proof192, sourcePubkey, sourceCiphertext64, destinationCommitment []byte, ctx []byte) error {
	_ = b
	_ = proof192
	_ = sourcePubkey
	_ = sourceCiphertext64
	_ = destinationCommitment
	_ = ctx
	return ErrPrivBackendUnavailable
}

func (b *PrivBatchVerifier) AddPrivRangeProof(proof []byte, commitments []byte, bitLengths []byte, batchLen uint8) error {
	_ = b
	_ = proof
	_ = commitments
	_ = bitLengths
	_ = batchLen
	return ErrPrivBackendUnavailable
}

func (b *PrivBatchVerifier) Verify() error {
	_ = b
	return ErrPrivBackendUnavailable
}
