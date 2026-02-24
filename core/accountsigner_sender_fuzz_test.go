package core

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
)

func FuzzResolveSenderSecp256k1Mutation(f *testing.F) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		panic(err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	to := common.HexToAddress("0x74c5f09f80cc62940a4f392f067a68b40696c06bf8e31f973efee01156caea5f")
	chainSigner := types.LatestSignerForChainID(big.NewInt(1))
	unsigned := newSignerUnsignedTx(0, from, to, accountsigner.SignerTypeSecp256k1)
	signed, err := types.SignTx(unsigned, chainSigner, key)
	if err != nil {
		panic(err)
	}
	baseV, baseR, baseS := signed.RawSignatureValues()
	baseCfgValue := hexutil.Encode(crypto.FromECDSAPub(&key.PublicKey))

	// kind: 0=none, 1=from, 2=R, 3=S, 4=signerType, 5=chainID mismatch
	f.Add(uint8(0), uint8(0), uint8(1), "secp256k1")
	f.Add(uint8(1), uint8(3), uint8(1), "secp256k1")
	f.Add(uint8(2), uint8(8), uint8(1), "secp256k1")
	f.Add(uint8(3), uint8(11), uint8(1), "secp256k1")
	f.Add(uint8(4), uint8(0), uint8(0), "ethereum_secp256k1")
	f.Add(uint8(4), uint8(0), uint8(0), "unknown")
	f.Add(uint8(5), uint8(0), uint8(0), "secp256k1")

	f.Fuzz(func(t *testing.T, kind, pos, mask uint8, txSignerType string) {
		if len(txSignerType) > 96 {
			return
		}

		st := newSenderTestState(t)
		accountsigner.Set(st, from, accountsigner.SignerTypeSecp256k1, baseCfgValue)

		useFrom := from
		useType := accountsigner.SignerTypeSecp256k1
		useChainID := new(big.Int).Set(chainSigner.ChainID())

		rBytes := make([]byte, 32)
		sBytes := make([]byte, 32)
		copy(rBytes[32-len(baseR.Bytes()):], baseR.Bytes())
		copy(sBytes[32-len(baseS.Bytes()):], baseS.Bytes())

		switch kind % 6 {
		case 1:
			useFrom[pos%20] ^= mask
		case 2:
			rBytes[pos%32] ^= mask
		case 3:
			sBytes[pos%32] ^= mask
		case 4:
			useType = txSignerType
		case 5:
			useChainID = big.NewInt(2)
		}

		tx := types.NewTx(&types.SignerTx{
			ChainID:    useChainID,
			Nonce:      unsigned.Nonce(),
			To:         unsigned.To(),
			Value:      unsigned.Value(),
			Gas:        unsigned.Gas(),
			Data:       unsigned.Data(),
			From:       useFrom,
			SignerType: useType,
			V:          new(big.Int).Set(baseV),
			R:          new(big.Int).SetBytes(rBytes),
			S:          new(big.Int).SetBytes(sBytes),
		})

		got, err := ResolveSender(tx, chainSigner, st)
		switch kind % 6 {
		case 0:
			if err != nil {
				t.Fatalf("unmutated resolve failed: %v", err)
			}
			if got != from {
				t.Fatalf("unexpected sender: have=%s want=%s", got.Hex(), from.Hex())
			}
		case 1:
			if useFrom != from && err == nil {
				t.Fatalf("expected error when from is mutated")
			}
		case 4:
			// Current secp256k1 sender recovery path requires canonical tx signerType.
			if useType == accountsigner.SignerTypeSecp256k1 {
				if err != nil {
					t.Fatalf("expected canonical secp256k1 signerType to pass, got %v", err)
				}
				if got != from {
					t.Fatalf("unexpected sender: have=%s want=%s", got.Hex(), from.Hex())
				}
			} else if err == nil {
				t.Fatalf("expected non-canonical signerType to fail")
			}
		case 5:
			if !errors.Is(err, types.ErrInvalidChainId) {
				t.Fatalf("expected chain id mismatch, got %v", err)
			}
		}
	})
}

func FuzzResolveSenderSecp256r1Mutation(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	pub := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	_, normalizedPub, normalizedValue, err := accountsigner.NormalizeSigner(accountsigner.SignerTypeSecp256r1, hexutil.Encode(pub))
	if err != nil {
		panic(err)
	}
	from, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeSecp256r1, normalizedPub)
	if err != nil {
		panic(err)
	}
	to := common.HexToAddress("0xd885744b9cb252077d755ad317c5185167401ed00cf5f5b2fc97d9bbfdb7d025")
	chainSigner := types.LatestSignerForChainID(big.NewInt(1))
	unsigned := newSignerUnsignedTx(0, from, to, accountsigner.SignerTypeSecp256r1)
	hash := chainSigner.Hash(unsigned)
	baseR, baseS, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		panic(err)
	}

	// kind: 0=none, 1=from, 2=R, 3=S, 4=signerType, 5=chainID mismatch
	f.Add(uint8(0), uint8(0), uint8(1), "secp256r1")
	f.Add(uint8(1), uint8(3), uint8(1), "secp256r1")
	f.Add(uint8(2), uint8(8), uint8(1), "secp256r1")
	f.Add(uint8(3), uint8(11), uint8(1), "secp256r1")
	f.Add(uint8(4), uint8(0), uint8(0), "SECP256R1")
	f.Add(uint8(4), uint8(0), uint8(0), "unknown")
	f.Add(uint8(5), uint8(0), uint8(0), "secp256r1")

	f.Fuzz(func(t *testing.T, kind, pos, mask uint8, txSignerType string) {
		if len(txSignerType) > 96 {
			return
		}

		st := newSenderTestState(t)
		accountsigner.Set(st, from, accountsigner.SignerTypeSecp256r1, normalizedValue)

		useFrom := from
		useType := accountsigner.SignerTypeSecp256r1
		useChainID := new(big.Int).Set(chainSigner.ChainID())

		rBytes := make([]byte, 32)
		sBytes := make([]byte, 32)
		copy(rBytes[32-len(baseR.Bytes()):], baseR.Bytes())
		copy(sBytes[32-len(baseS.Bytes()):], baseS.Bytes())

		switch kind % 6 {
		case 1:
			useFrom[pos%20] ^= mask
		case 2:
			rBytes[pos%32] ^= mask
		case 3:
			sBytes[pos%32] ^= mask
		case 4:
			useType = txSignerType
		case 5:
			useChainID = big.NewInt(2)
		}

		tx := types.NewTx(&types.SignerTx{
			ChainID:    useChainID,
			Nonce:      unsigned.Nonce(),
			To:         unsigned.To(),
			Value:      unsigned.Value(),
			Gas:        unsigned.Gas(),
			Data:       unsigned.Data(),
			From:       useFrom,
			SignerType: useType,
			V:          big.NewInt(0),
			R:          new(big.Int).SetBytes(rBytes),
			S:          new(big.Int).SetBytes(sBytes),
		})

		got, err := ResolveSender(tx, chainSigner, st)
		switch kind % 6 {
		case 0:
			if err != nil {
				t.Fatalf("unmutated resolve failed: %v", err)
			}
			if got != from {
				t.Fatalf("unexpected sender: have=%s want=%s", got.Hex(), from.Hex())
			}
		case 1:
			if useFrom != from && err == nil {
				t.Fatalf("expected error when from is mutated")
			}
		case 4:
			// Signature hash includes signerType string; non-exact casing mutates hash.
			if useType == accountsigner.SignerTypeSecp256r1 {
				if err != nil {
					t.Fatalf("expected canonical secp256r1 signerType to pass, got %v", err)
				}
				if got != from {
					t.Fatalf("unexpected sender: have=%s want=%s", got.Hex(), from.Hex())
				}
			} else if err == nil {
				t.Fatalf("expected non-exact signerType to fail")
			}
		case 5:
			if !errors.Is(err, types.ErrInvalidChainId) {
				t.Fatalf("expected chain id mismatch, got %v", err)
			}
		}
	})
}

func FuzzResolveSenderEd25519Mutation(f *testing.F) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	_, normalizedPub, normalizedValue, err := accountsigner.NormalizeSigner(accountsigner.SignerTypeEd25519, hexutil.Encode(pub))
	if err != nil {
		panic(err)
	}
	from, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeEd25519, normalizedPub)
	if err != nil {
		panic(err)
	}
	to := common.HexToAddress("0xb8a0722ae6cb48cde0b4ae1f1a642f0e3c3af545e7acbd38b07251b3990914f1")
	chainSigner := types.LatestSignerForChainID(big.NewInt(1))
	unsigned := newSignerUnsignedTx(0, from, to, accountsigner.SignerTypeEd25519)
	hash := chainSigner.Hash(unsigned)
	baseSig := ed25519.Sign(priv, hash[:])
	baseR := new(big.Int).SetBytes(baseSig[:32])
	baseS := new(big.Int).SetBytes(baseSig[32:])

	// kind: 0=none, 1=from, 2=R, 3=S, 4=signerType, 5=chainID mismatch
	f.Add(uint8(0), uint8(0), uint8(1), "ed25519")
	f.Add(uint8(1), uint8(3), uint8(1), "ed25519")
	f.Add(uint8(2), uint8(8), uint8(1), "ed25519")
	f.Add(uint8(3), uint8(11), uint8(1), "ed25519")
	f.Add(uint8(4), uint8(0), uint8(0), "ED25519")
	f.Add(uint8(4), uint8(0), uint8(0), "unknown")
	f.Add(uint8(5), uint8(0), uint8(0), "ed25519")

	f.Fuzz(func(t *testing.T, kind, pos, mask uint8, txSignerType string) {
		if len(txSignerType) > 96 {
			return
		}

		st := newSenderTestState(t)
		accountsigner.Set(st, from, accountsigner.SignerTypeEd25519, normalizedValue)

		useFrom := from
		useType := accountsigner.SignerTypeEd25519
		useChainID := new(big.Int).Set(chainSigner.ChainID())

		rBytes := make([]byte, 32)
		sBytes := make([]byte, 32)
		copy(rBytes[32-len(baseR.Bytes()):], baseR.Bytes())
		copy(sBytes[32-len(baseS.Bytes()):], baseS.Bytes())

		switch kind % 6 {
		case 1:
			useFrom[pos%20] ^= mask
		case 2:
			rBytes[pos%32] ^= mask
		case 3:
			sBytes[pos%32] ^= mask
		case 4:
			useType = txSignerType
		case 5:
			useChainID = big.NewInt(2)
		}

		tx := types.NewTx(&types.SignerTx{
			ChainID:    useChainID,
			Nonce:      unsigned.Nonce(),
			To:         unsigned.To(),
			Value:      unsigned.Value(),
			Gas:        unsigned.Gas(),
			Data:       unsigned.Data(),
			From:       useFrom,
			SignerType: useType,
			V:          big.NewInt(0),
			R:          new(big.Int).SetBytes(rBytes),
			S:          new(big.Int).SetBytes(sBytes),
		})

		got, err := ResolveSender(tx, chainSigner, st)
		switch kind % 6 {
		case 0:
			if err != nil {
				t.Fatalf("unmutated resolve failed: %v", err)
			}
			if got != from {
				t.Fatalf("unexpected sender: have=%s want=%s", got.Hex(), from.Hex())
			}
		case 1:
			if useFrom != from && err == nil {
				t.Fatalf("expected error when from is mutated")
			}
		case 4:
			// Signature hash includes signerType string; non-exact casing mutates hash.
			if useType == accountsigner.SignerTypeEd25519 {
				if err != nil {
					t.Fatalf("expected canonical ed25519 signerType to pass, got %v", err)
				}
				if got != from {
					t.Fatalf("unexpected sender: have=%s want=%s", got.Hex(), from.Hex())
				}
			} else if err == nil {
				t.Fatalf("expected non-exact signerType to fail")
			}
		case 5:
			if !errors.Is(err, types.ErrInvalidChainId) {
				t.Fatalf("expected chain id mismatch, got %v", err)
			}
		}
	})
}
