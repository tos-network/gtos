package uno

import (
	"errors"

	"github.com/tos-network/gtos/crypto/ed25519"
)

func AddCompressedCiphertexts(a64, b64 []byte) ([]byte, error) {
	out, err := ed25519.ElgamalCTAddCompressed(a64, b64)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return out, nil
}

func SubCompressedCiphertexts(a64, b64 []byte) ([]byte, error) {
	out, err := ed25519.ElgamalCTSubCompressed(a64, b64)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return out, nil
}

func AddAmountCompressed(in64 []byte, amount uint64) ([]byte, error) {
	out, err := ed25519.ElgamalCTAddAmountCompressed(in64, amount)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return out, nil
}

func SubAmountCompressed(in64 []byte, amount uint64) ([]byte, error) {
	out, err := ed25519.ElgamalCTSubAmountCompressed(in64, amount)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return out, nil
}

func NormalizeCompressed(in64 []byte) ([]byte, error) {
	out, err := ed25519.ElgamalCTNormalizeCompressed(in64)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return out, nil
}

func ZeroCiphertextCompressed() ([]byte, error) {
	out, err := ed25519.ElgamalCTZeroCompressed()
	if err != nil {
		return nil, mapBackendError(err)
	}
	return out, nil
}

func AddScalarCompressed(in64, scalar32 []byte) ([]byte, error) {
	out, err := ed25519.ElgamalCTAddScalarCompressed(in64, scalar32)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return out, nil
}

func SubScalarCompressed(in64, scalar32 []byte) ([]byte, error) {
	out, err := ed25519.ElgamalCTSubScalarCompressed(in64, scalar32)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return out, nil
}

func MulScalarCompressed(in64, scalar32 []byte) ([]byte, error) {
	out, err := ed25519.ElgamalCTMulScalarCompressed(in64, scalar32)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return out, nil
}

func PublicKeyFromPrivate(priv32 []byte) ([]byte, error) {
	out, err := ed25519.ElgamalPublicKeyFromPrivate(priv32)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return out, nil
}

func Encrypt(pub32 []byte, amount uint64) ([]byte, error) {
	out, err := ed25519.ElgamalEncrypt(pub32, amount)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return out, nil
}

func GenerateOpening() ([]byte, error) {
	out, err := ed25519.PedersenOpeningGenerate()
	if err != nil {
		return nil, mapBackendError(err)
	}
	return out, nil
}

func CommitmentNew(amount uint64) (commitment32 []byte, opening32 []byte, err error) {
	commitment32, opening32, err = ed25519.PedersenCommitmentNew(amount)
	if err != nil {
		return nil, nil, mapBackendError(err)
	}
	return commitment32, opening32, nil
}

func DecryptToPoint(priv32, ct64 []byte) ([]byte, error) {
	out, err := ed25519.ElgamalDecryptToPoint(priv32, ct64)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return out, nil
}

func PublicKeyToAddress(pub32 []byte, mainnet bool) (string, error) {
	out, err := ed25519.ElgamalPublicKeyToAddress(pub32, mainnet)
	if err != nil {
		return "", mapBackendError(err)
	}
	return out, nil
}

func PedersenCommitmentWithOpening(opening32 []byte, amount uint64) ([]byte, error) {
	out, err := ed25519.PedersenCommitmentWithOpening(opening32, amount)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return out, nil
}

func DecryptHandleWithOpening(pub32, opening32 []byte) ([]byte, error) {
	out, err := ed25519.ElgamalDecryptHandleWithOpening(pub32, opening32)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return out, nil
}

func EncryptWithOpening(pub32 []byte, amount uint64, opening32 []byte) ([]byte, error) {
	out, err := ed25519.ElgamalEncryptWithOpening(pub32, amount, opening32)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return out, nil
}

func EncryptWithGeneratedOpening(pub32 []byte, amount uint64) (ct64 []byte, opening32 []byte, err error) {
	ct64, opening32, err = ed25519.ElgamalEncryptWithGeneratedOpening(pub32, amount)
	if err != nil {
		return nil, nil, mapBackendError(err)
	}
	return ct64, opening32, nil
}

func GenerateKeypair() (pub32 []byte, priv32 []byte, err error) {
	pub32, priv32, err = ed25519.ElgamalKeypairGenerate()
	if err != nil {
		return nil, nil, mapBackendError(err)
	}
	return pub32, priv32, nil
}

func mapBackendError(err error) error {
	switch {
	case errors.Is(err, ed25519.ErrUNOBackendUnavailable):
		return ErrBackendUnavailable
	case errors.Is(err, ed25519.ErrUNOInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, ed25519.ErrUNOInvalidProof):
		return ErrInvalidProof
	case errors.Is(err, ed25519.ErrUNOOperationFailed):
		return ErrOperationFailed
	default:
		return err
	}
}
