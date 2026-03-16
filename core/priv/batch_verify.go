package priv

import cryptopriv "github.com/tos-network/gtos/crypto/priv"

type BatchVerifier struct {
	inner *cryptopriv.BatchVerifier
}

func NewBatchVerifier() *BatchVerifier {
	return &BatchVerifier{inner: cryptopriv.NewBatchVerifier()}
}

func (b *BatchVerifier) AddCiphertextValidityProofWithContext(commitment, senderHandle, receiverHandle [32]byte, senderPub, receiverPub [32]byte, proof []byte, ctx []byte) error {
	decoded, err := decodeCTValidityProof(proof)
	if err != nil {
		return err
	}
	return mapCryptoVerifyError(b.inner.AddCTValidityProofWithContext(
		decoded,
		commitment[:],
		senderHandle[:],
		receiverHandle[:],
		senderPub[:],
		receiverPub[:],
		true,
		ctx,
	))
}

func (b *BatchVerifier) AddCommitmentEqProofWithContext(pubkey [32]byte, ciphertext Ciphertext, sourceCommitment [32]byte, proof []byte, ctx []byte) error {
	decoded, err := decodeCommitmentEqProof(proof)
	if err != nil {
		return err
	}
	ct64 := make([]byte, 64)
	copy(ct64[:32], ciphertext.Commitment[:])
	copy(ct64[32:], ciphertext.Handle[:])
	return mapCryptoVerifyError(b.inner.AddCommitmentEqProofWithContext(
		decoded,
		pubkey[:],
		ct64,
		sourceCommitment[:],
		ctx,
	))
}

func (b *BatchVerifier) AddShieldProofWithContext(commitment, handle [32]byte, pubkey [32]byte, amount uint64, proof []byte, ctx []byte) error {
	decoded, err := decodeShieldProof(proof)
	if err != nil {
		return err
	}
	return mapCryptoVerifyError(b.inner.AddShieldProofWithContext(
		decoded,
		commitment[:],
		handle[:],
		pubkey[:],
		amount,
		ctx,
	))
}

func (b *BatchVerifier) AddRangeProof(sourceCommitment, transferCommitment [32]byte, proof []byte) error {
	decoded, err := decodeTransferRangeProofs(proof)
	if err != nil {
		return err
	}
	if err := mapCryptoVerifyError(b.inner.AddRangeProof(decoded[0], sourceCommitment[:], []byte{64}, 1)); err != nil {
		return err
	}
	return mapCryptoVerifyError(b.inner.AddRangeProof(decoded[1], transferCommitment[:], []byte{64}, 1))
}

func (b *BatchVerifier) AddSingleRangeProof(commitment [32]byte, proof []byte) error {
	decoded, err := decodeSingleRangeProof(proof)
	if err != nil {
		return err
	}
	return mapCryptoVerifyError(b.inner.AddRangeProof(decoded, commitment[:], []byte{64}, 1))
}

func (b *BatchVerifier) Verify() error {
	return mapCryptoVerifyError(b.inner.Verify())
}
