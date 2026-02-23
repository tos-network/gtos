package core

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

func newSenderTestState(t *testing.T) *state.StateDB {
	t.Helper()
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}
	return st
}

func newSignerUnsignedTx(nonce uint64, from, to common.Address, signerType string) *types.Transaction {
	return types.NewTx(&types.SignerTx{
		ChainID:    big.NewInt(1),
		Nonce:      nonce,
		To:         &to,
		Value:      big.NewInt(0),
		Gas:        params.TxGas,
		GasPrice:   big.NewInt(1),
		From:       from,
		SignerType: signerType,
	})
}

func TestResolveSenderSecp256k1FromAccountSigner(t *testing.T) {
	st := newSenderTestState(t)
	chainSigner := types.LatestSignerForChainID(big.NewInt(1))
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	to := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	unsigned := newSignerUnsignedTx(0, from, to, accountsigner.SignerTypeSecp256k1)
	signed, err := types.SignTx(unsigned, chainSigner, key)
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}
	accountsigner.Set(st, from, accountsigner.SignerTypeSecp256k1, hexutil.Encode(crypto.FromECDSAPub(&key.PublicKey)))

	got, err := ResolveSender(signed, chainSigner, st)
	if err != nil {
		t.Fatalf("resolve sender failed: %v", err)
	}
	if got != from {
		t.Fatalf("unexpected sender have=%s want=%s", got.Hex(), from.Hex())
	}
}

func TestResolveSenderSecp256r1(t *testing.T) {
	st := newSenderTestState(t)
	chainSigner := types.LatestSignerForChainID(big.NewInt(1))
	to := common.HexToAddress("0x00000000000000000000000000000000000000ab")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate p256 key: %v", err)
	}
	pub := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	_, _, normalizedValue, err := accountsigner.NormalizeSigner(accountsigner.SignerTypeSecp256r1, hexutil.Encode(pub))
	if err != nil {
		t.Fatalf("normalize signer failed: %v", err)
	}
	from, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeSecp256r1, pub)
	if err != nil {
		t.Fatalf("derive address failed: %v", err)
	}
	accountsigner.Set(st, from, accountsigner.SignerTypeSecp256r1, normalizedValue)

	unsigned := newSignerUnsignedTx(0, from, to, accountsigner.SignerTypeSecp256r1)
	hash := chainSigner.Hash(unsigned)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("failed to sign hash: %v", err)
	}
	tx := types.NewTx(&types.SignerTx{
		ChainID:    unsigned.ChainId(),
		Nonce:      unsigned.Nonce(),
		To:         unsigned.To(),
		Value:      unsigned.Value(),
		Gas:        unsigned.Gas(),
		GasPrice:   unsigned.GasPrice(),
		Data:       unsigned.Data(),
		From:       from,
		SignerType: accountsigner.SignerTypeSecp256r1,
		V:          big.NewInt(0),
		R:          r,
		S:          s,
	})

	got, err := ResolveSender(tx, chainSigner, st)
	if err != nil {
		t.Fatalf("resolve sender failed: %v", err)
	}
	if got != from {
		t.Fatalf("unexpected sender have=%s want=%s", got.Hex(), from.Hex())
	}
}

func TestResolveSenderEd25519(t *testing.T) {
	st := newSenderTestState(t)
	chainSigner := types.LatestSignerForChainID(big.NewInt(1))
	to := common.HexToAddress("0x00000000000000000000000000000000000000ac")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	_, normalizedPub, normalizedValue, err := accountsigner.NormalizeSigner(accountsigner.SignerTypeEd25519, hexutil.Encode(pub))
	if err != nil {
		t.Fatalf("normalize signer failed: %v", err)
	}
	from, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeEd25519, normalizedPub)
	if err != nil {
		t.Fatalf("derive address failed: %v", err)
	}
	accountsigner.Set(st, from, accountsigner.SignerTypeEd25519, normalizedValue)

	unsigned := newSignerUnsignedTx(0, from, to, accountsigner.SignerTypeEd25519)
	hash := chainSigner.Hash(unsigned)
	sig := ed25519.Sign(priv, hash[:])
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	tx := types.NewTx(&types.SignerTx{
		ChainID:    unsigned.ChainId(),
		Nonce:      unsigned.Nonce(),
		To:         unsigned.To(),
		Value:      unsigned.Value(),
		Gas:        unsigned.Gas(),
		GasPrice:   unsigned.GasPrice(),
		Data:       unsigned.Data(),
		From:       from,
		SignerType: accountsigner.SignerTypeEd25519,
		V:          big.NewInt(0),
		R:          r,
		S:          s,
	})

	got, err := ResolveSender(tx, chainSigner, st)
	if err != nil {
		t.Fatalf("resolve sender failed: %v", err)
	}
	if got != from {
		t.Fatalf("unexpected sender have=%s want=%s", got.Hex(), from.Hex())
	}
}

func TestResolveSenderRejectsMetaMismatch(t *testing.T) {
	st := newSenderTestState(t)
	chainSigner := types.LatestSignerForChainID(big.NewInt(1))
	to := common.HexToAddress("0x00000000000000000000000000000000000000ad")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	_, normalizedPub, _, err := accountsigner.NormalizeSigner(accountsigner.SignerTypeEd25519, hexutil.Encode(pub))
	if err != nil {
		t.Fatalf("normalize signer failed: %v", err)
	}
	from, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeEd25519, normalizedPub)
	if err != nil {
		t.Fatalf("derive address failed: %v", err)
	}
	accountsigner.Set(st, from, accountsigner.SignerTypeEd25519, "0x"+strings.Repeat("11", 32))

	unsigned := newSignerUnsignedTx(0, from, to, accountsigner.SignerTypeEd25519)
	hash := chainSigner.Hash(unsigned)
	sig := ed25519.Sign(priv, hash[:])
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	tx := types.NewTx(&types.SignerTx{
		ChainID:    unsigned.ChainId(),
		Nonce:      unsigned.Nonce(),
		To:         unsigned.To(),
		Value:      unsigned.Value(),
		Gas:        unsigned.Gas(),
		GasPrice:   unsigned.GasPrice(),
		Data:       unsigned.Data(),
		From:       from,
		SignerType: accountsigner.SignerTypeEd25519,
		V:          big.NewInt(0),
		R:          r,
		S:          s,
	})
	_, err = ResolveSender(tx, chainSigner, st)
	if !errors.Is(err, ErrInvalidAccountSignerSignature) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveSenderRejectsUnsupportedSignerType(t *testing.T) {
	st := newSenderTestState(t)
	chainSigner := types.LatestSignerForChainID(big.NewInt(1))
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	to := common.HexToAddress("0x00000000000000000000000000000000000000ae")
	unsigned := newSignerUnsignedTx(0, from, to, accountsigner.SignerTypeSecp256k1)
	signed, err := types.SignTx(unsigned, chainSigner, key)
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}
	// BLS key material is accepted as signer metadata, but current tx signature format does not support BLS verification.
	accountsigner.Set(st, from, accountsigner.SignerTypeBLS12381, "0x"+strings.Repeat("44", 48))

	// Build tx using explicit unsupported signerType.
	v, r, s := signed.RawSignatureValues()
	unsupported := types.NewTx(&types.SignerTx{
		ChainID:    signed.ChainId(),
		Nonce:      signed.Nonce(),
		To:         signed.To(),
		Value:      signed.Value(),
		Gas:        signed.Gas(),
		GasPrice:   signed.GasPrice(),
		Data:       signed.Data(),
		From:       from,
		SignerType: accountsigner.SignerTypeBLS12381,
		V:          new(big.Int).Set(v),
		R:          new(big.Int).Set(r),
		S:          new(big.Int).Set(s),
	})

	_, err = ResolveSender(unsupported, chainSigner, st)
	if !errors.Is(err, ErrUnsupportedAccountSignerType) {
		t.Fatalf("unexpected error: %v", err)
	}
}
