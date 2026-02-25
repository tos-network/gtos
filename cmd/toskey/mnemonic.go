package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/tos-network/gtos/accounts"
	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/crypto"
	ed25519 "github.com/tos-network/gtos/crypto/ed25519"
	"github.com/tos-network/gtos/crypto/ristretto255"
	"github.com/tyler-smith/go-bip39"
)

const (
	defaultMnemonicBits = 128
	defaultHDPath       = "m/44'/60'/0'/0/0"
	hdHardenedOffset    = uint32(0x80000000)
)

func generateMnemonic(bits int) (string, error) {
	if err := validateMnemonicBits(bits); err != nil {
		return "", err
	}
	entropy, err := bip39.NewEntropy(bits)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

func validateMnemonicBits(bits int) error {
	switch bits {
	case 128, 160, 192, 224, 256:
		return nil
	default:
		return fmt.Errorf("invalid mnemonic bits %d (allowed: 128,160,192,224,256)", bits)
	}
}

func deriveECDSAFromMnemonic(mnemonic string, passphrase string, derivationPath string) (*ecdsa.PrivateKey, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, passphrase)
	if err != nil {
		return nil, err
	}
	return deriveECDSAFromSeed(seed, derivationPath)
}

func deriveElgamalPrivateFromMnemonic(mnemonic string, passphrase string, derivationPath string) ([]byte, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, passphrase)
	if err != nil {
		return nil, err
	}
	return deriveElgamalPrivateFromSeed(seed, derivationPath)
}

func deriveEd25519PrivateFromMnemonic(mnemonic string, passphrase string, derivationPath string) (ed25519.PrivateKey, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, passphrase)
	if err != nil {
		return nil, err
	}
	return deriveEd25519PrivateFromSeed(seed, derivationPath)
}

func deriveBLS12381PrivateFromMnemonic(mnemonic string, passphrase string, derivationPath string) ([]byte, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, passphrase)
	if err != nil {
		return nil, err
	}
	return deriveBLS12381PrivateFromSeed(seed, derivationPath)
}

func deriveECDSAFromSeed(seed []byte, derivationPath string) (*ecdsa.PrivateKey, error) {
	path, err := accounts.ParseDerivationPath(derivationPath)
	if err != nil {
		return nil, fmt.Errorf("invalid hd path %q: %w", derivationPath, err)
	}
	key, chainCode, err := deriveBIP32Master(seed)
	if err != nil {
		return nil, err
	}
	for _, index := range path {
		key, chainCode, err = deriveBIP32Child(key, chainCode, index)
		if err != nil {
			return nil, err
		}
	}
	return crypto.ToECDSA(key)
}

func deriveEd25519PrivateFromSeed(seed []byte, derivationPath string) (ed25519.PrivateKey, error) {
	if _, err := accounts.ParseDerivationPath(derivationPath); err != nil {
		return nil, fmt.Errorf("invalid hd path %q: %w", derivationPath, err)
	}
	mac := hmac.New(sha512.New, []byte("GTOS_ED25519_DERIVE"))
	mac.Write(seed)
	mac.Write([]byte{0})
	mac.Write([]byte(derivationPath))
	digest := mac.Sum(nil)
	seed32 := make([]byte, ed25519.SeedSize)
	copy(seed32, digest[:ed25519.SeedSize])
	return ed25519.NewKeyFromSeed(seed32), nil
}

func deriveBLS12381PrivateFromSeed(seed []byte, derivationPath string) ([]byte, error) {
	if _, err := accounts.ParseDerivationPath(derivationPath); err != nil {
		return nil, fmt.Errorf("invalid hd path %q: %w", derivationPath, err)
	}
	for counter := uint32(0); counter < 1024; counter++ {
		mac := hmac.New(sha512.New, []byte("GTOS_BLS12381_DERIVE"))
		mac.Write(seed)
		mac.Write([]byte{0})
		mac.Write([]byte(derivationPath))
		var ctr [4]byte
		binary.BigEndian.PutUint32(ctr[:], counter)
		mac.Write(ctr[:])
		digest := mac.Sum(nil)

		ikm := make([]byte, 32)
		copy(ikm, digest[:32])
		priv, err := accountsigner.GenerateBLS12381PrivateKey(bytes.NewReader(ikm))
		if err != nil {
			continue
		}
		if _, err := accountsigner.PublicKeyFromBLS12381Private(priv); err == nil {
			return priv, nil
		}
	}
	return nil, fmt.Errorf("failed to derive valid bls12-381 private key")
}

func deriveElgamalPrivateFromSeed(seed []byte, derivationPath string) ([]byte, error) {
	if _, err := accounts.ParseDerivationPath(derivationPath); err != nil {
		return nil, fmt.Errorf("invalid hd path %q: %w", derivationPath, err)
	}
	zero := ristretto255.NewScalar()
	for counter := uint32(0); counter < 1024; counter++ {
		mac := hmac.New(sha512.New, []byte("GTOS_ELGAMAL_DERIVE"))
		mac.Write(seed)
		mac.Write([]byte{0})
		mac.Write([]byte(derivationPath))
		var ctr [4]byte
		binary.BigEndian.PutUint32(ctr[:], counter)
		mac.Write(ctr[:])
		digest := mac.Sum(nil)
		scalar := ristretto255.NewScalar()
		if _, err := scalar.SetUniformBytes(digest); err != nil {
			return nil, err
		}
		if scalar.Equal(zero) == 1 {
			continue
		}
		priv := scalar.Bytes()
		if _, err := accountsigner.PublicKeyFromElgamalPrivate(priv); err == nil {
			return priv, nil
		}
	}
	return nil, fmt.Errorf("failed to derive valid elgamal private key")
}

func deriveBIP32Master(seed []byte) ([]byte, []byte, error) {
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	if _, err := mac.Write(seed); err != nil {
		return nil, nil, err
	}
	sum := mac.Sum(nil)
	key := make([]byte, 32)
	chainCode := make([]byte, 32)
	copy(key, sum[:32])
	copy(chainCode, sum[32:])
	if err := validateBIP32Scalar(key); err != nil {
		return nil, nil, fmt.Errorf("invalid bip32 master key: %w", err)
	}
	return key, chainCode, nil
}

func deriveBIP32Child(parentKey []byte, parentChainCode []byte, index uint32) ([]byte, []byte, error) {
	if len(parentKey) != 32 || len(parentChainCode) != 32 {
		return nil, nil, fmt.Errorf("invalid bip32 parent key material")
	}

	data := make([]byte, 37)
	if index >= hdHardenedOffset {
		data[0] = 0x00
		copy(data[1:33], parentKey)
	} else {
		priv, _ := btcec.PrivKeyFromBytes(parentKey)
		copy(data[:33], priv.PubKey().SerializeCompressed())
	}
	binary.BigEndian.PutUint32(data[33:], index)

	mac := hmac.New(sha512.New, parentChainCode)
	if _, err := mac.Write(data); err != nil {
		return nil, nil, err
	}
	sum := mac.Sum(nil)
	il := sum[:32]
	ir := sum[32:]

	curveN := crypto.S256().Params().N
	ilInt := new(big.Int).SetBytes(il)
	if ilInt.Sign() == 0 || ilInt.Cmp(curveN) >= 0 {
		return nil, nil, fmt.Errorf("invalid bip32 child scalar")
	}
	parentInt := new(big.Int).SetBytes(parentKey)
	childInt := new(big.Int).Add(ilInt, parentInt)
	childInt.Mod(childInt, curveN)
	if childInt.Sign() == 0 {
		return nil, nil, fmt.Errorf("invalid bip32 child key: zero")
	}

	childKey := make([]byte, 32)
	childBytes := childInt.Bytes()
	copy(childKey[32-len(childBytes):], childBytes)
	childChainCode := make([]byte, 32)
	copy(childChainCode, ir)
	return childKey, childChainCode, nil
}

func validateBIP32Scalar(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("invalid scalar length %d", len(key))
	}
	curveN := crypto.S256().Params().N
	v := new(big.Int).SetBytes(key)
	if v.Sign() == 0 || v.Cmp(curveN) >= 0 {
		return fmt.Errorf("scalar out of range")
	}
	return nil
}
