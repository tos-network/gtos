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

func DecryptToPoint(priv32, ct64 []byte) ([]byte, error) {
	out, err := ed25519.ElgamalDecryptToPoint(priv32, ct64)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return out, nil
}

func mapBackendError(err error) error {
	switch {
	case errors.Is(err, ed25519.ErrUNOBackendUnavailable):
		return ErrBackendUnavailable
	case errors.Is(err, ed25519.ErrUNOInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, ed25519.ErrUNOInvalidProof), errors.Is(err, ed25519.ErrUNOOperationFailed):
		return ErrInvalidProof
	default:
		return err
	}
}
