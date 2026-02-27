//go:build !cgo || !ed25519c

package ed25519

func VerifyUNOShieldProof(proof96, commitment, receiverHandle, receiverPubkey []byte, amount uint64) error {
	_ = proof96
	_ = commitment
	_ = receiverHandle
	_ = receiverPubkey
	_ = amount
	return ErrUNOBackendUnavailable
}

func VerifyUNOShieldProofWithContext(proof96, commitment, receiverHandle, receiverPubkey []byte, amount uint64, ctx []byte) error {
	_ = proof96
	_ = commitment
	_ = receiverHandle
	_ = receiverPubkey
	_ = amount
	_ = ctx
	return ErrUNOBackendUnavailable
}

func VerifyUNOCTValidityProof(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey []byte, txVersionT1 bool) error {
	_ = proof
	_ = commitment
	_ = senderHandle
	_ = receiverHandle
	_ = senderPubkey
	_ = receiverPubkey
	_ = txVersionT1
	return ErrUNOBackendUnavailable
}

func VerifyUNOCTValidityProofWithContext(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey []byte, txVersionT1 bool, ctx []byte) error {
	_ = proof
	_ = commitment
	_ = senderHandle
	_ = receiverHandle
	_ = senderPubkey
	_ = receiverPubkey
	_ = txVersionT1
	_ = ctx
	return ErrUNOBackendUnavailable
}

func ElgamalCTAddCompressed(a64, b64 []byte) ([]byte, error) {
	_ = a64
	_ = b64
	return nil, ErrUNOBackendUnavailable
}

func ElgamalCTSubCompressed(a64, b64 []byte) ([]byte, error) {
	_ = a64
	_ = b64
	return nil, ErrUNOBackendUnavailable
}

func ElgamalCTAddAmountCompressed(in64 []byte, amount uint64) ([]byte, error) {
	_ = in64
	_ = amount
	return nil, ErrUNOBackendUnavailable
}

func ElgamalCTSubAmountCompressed(in64 []byte, amount uint64) ([]byte, error) {
	_ = in64
	_ = amount
	return nil, ErrUNOBackendUnavailable
}

func ElgamalCTNormalizeCompressed(in64 []byte) ([]byte, error) {
	_ = in64
	return nil, ErrUNOBackendUnavailable
}

func ElgamalCTZeroCompressed() ([]byte, error) {
	return nil, ErrUNOBackendUnavailable
}

func ElgamalCTAddScalarCompressed(in64, scalar32 []byte) ([]byte, error) {
	_ = in64
	_ = scalar32
	return nil, ErrUNOBackendUnavailable
}

func ElgamalCTSubScalarCompressed(in64, scalar32 []byte) ([]byte, error) {
	_ = in64
	_ = scalar32
	return nil, ErrUNOBackendUnavailable
}

func ElgamalCTMulScalarCompressed(in64, scalar32 []byte) ([]byte, error) {
	_ = in64
	_ = scalar32
	return nil, ErrUNOBackendUnavailable
}

func VerifyUNOCommitmentEqProof(proof192, sourcePubkey, sourceCiphertext64, destinationCommitment []byte) error {
	_ = proof192
	_ = sourcePubkey
	_ = sourceCiphertext64
	_ = destinationCommitment
	return ErrUNOBackendUnavailable
}

func VerifyUNOBalanceProof(proof, publicKey, sourceCiphertext64 []byte) error {
	_ = proof
	_ = publicKey
	_ = sourceCiphertext64
	return ErrUNOBackendUnavailable
}

func VerifyUNOBalanceProofWithContext(proof, publicKey, sourceCiphertext64 []byte, ctx []byte) error {
	_ = proof
	_ = publicKey
	_ = sourceCiphertext64
	_ = ctx
	return ErrUNOBackendUnavailable
}

func VerifyUNORangeProof(proof []byte, commitments []byte, bitLengths []byte, batchLen uint8) error {
	_ = proof
	_ = commitments
	_ = bitLengths
	_ = batchLen
	return ErrUNOBackendUnavailable
}

func ElgamalPublicKeyFromPrivate(priv32 []byte) ([]byte, error) {
	_ = priv32
	return nil, ErrUNOBackendUnavailable
}

func ElgamalEncrypt(pub32 []byte, amount uint64) ([]byte, error) {
	_ = pub32
	_ = amount
	return nil, ErrUNOBackendUnavailable
}

func PedersenOpeningGenerate() ([]byte, error) {
	return nil, ErrUNOBackendUnavailable
}

func PedersenCommitmentNew(amount uint64) (commitment32 []byte, opening32 []byte, err error) {
	_ = amount
	return nil, nil, ErrUNOBackendUnavailable
}

func PedersenCommitmentWithOpening(opening32 []byte, amount uint64) ([]byte, error) {
	_ = opening32
	_ = amount
	return nil, ErrUNOBackendUnavailable
}

func ElgamalDecryptHandleWithOpening(pub32, opening32 []byte) ([]byte, error) {
	_ = pub32
	_ = opening32
	return nil, ErrUNOBackendUnavailable
}

func ElgamalEncryptWithOpening(pub32 []byte, amount uint64, opening32 []byte) ([]byte, error) {
	_ = pub32
	_ = amount
	_ = opening32
	return nil, ErrUNOBackendUnavailable
}

func ElgamalEncryptWithGeneratedOpening(pub32 []byte, amount uint64) (ct64 []byte, opening32 []byte, err error) {
	_ = pub32
	_ = amount
	return nil, nil, ErrUNOBackendUnavailable
}

func ElgamalKeypairGenerate() (pub32 []byte, priv32 []byte, err error) {
	return nil, nil, ErrUNOBackendUnavailable
}

func ElgamalDecryptToPoint(priv32, ct64 []byte) ([]byte, error) {
	_ = priv32
	_ = ct64
	return nil, ErrUNOBackendUnavailable
}

func ElgamalPublicKeyToAddress(pub32 []byte, mainnet bool) (string, error) {
	_ = pub32
	_ = mainnet
	return "", ErrUNOBackendUnavailable
}
