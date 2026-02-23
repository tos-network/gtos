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

func newLegacyUnsignedTx(nonce uint64, to common.Address) *types.Transaction {
	return types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &to,
		Value:    big.NewInt(0),
		Gas:      params.TxGas,
		GasPrice: big.NewInt(1),
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
	unsigned := newLegacyUnsignedTx(0, to)
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
	unsigned := newLegacyUnsignedTx(0, to)
	hash := chainSigner.Hash(unsigned)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate p256 key: %v", err)
	}
	pub := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	_, normalizedPub, normalizedValue, err := accountsigner.NormalizeSigner(accountsigner.SignerTypeSecp256r1, hexutil.Encode(pub))
	if err != nil {
		t.Fatalf("normalize signer failed: %v", err)
	}
	from, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeSecp256r1, normalizedPub)
	if err != nil {
		t.Fatalf("derive address failed: %v", err)
	}
	accountsigner.Set(st, from, accountsigner.SignerTypeSecp256r1, normalizedValue)

	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("failed to sign hash: %v", err)
	}
	v, err := accountsigner.EncodeSignatureMeta(accountsigner.SignerTypeSecp256r1, normalizedPub)
	if err != nil {
		t.Fatalf("failed to encode signature meta: %v", err)
	}
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    unsigned.Nonce(),
		To:       unsigned.To(),
		Value:    unsigned.Value(),
		Gas:      unsigned.Gas(),
		GasPrice: unsigned.GasPrice(),
		Data:     unsigned.Data(),
		V:        v,
		R:        r,
		S:        s,
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
	unsigned := newLegacyUnsignedTx(0, to)
	hash := chainSigner.Hash(unsigned)

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

	sig := ed25519.Sign(priv, hash[:])
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	v, err := accountsigner.EncodeSignatureMeta(accountsigner.SignerTypeEd25519, normalizedPub)
	if err != nil {
		t.Fatalf("failed to encode signature meta: %v", err)
	}
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    unsigned.Nonce(),
		To:       unsigned.To(),
		Value:    unsigned.Value(),
		Gas:      unsigned.Gas(),
		GasPrice: unsigned.GasPrice(),
		Data:     unsigned.Data(),
		V:        v,
		R:        r,
		S:        s,
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
	unsigned := newLegacyUnsignedTx(0, to)
	hash := chainSigner.Hash(unsigned)

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
	// Configure a different signer in state.
	accountsigner.Set(st, from, accountsigner.SignerTypeEd25519, "0x"+strings.Repeat("11", 32))

	sig := ed25519.Sign(priv, hash[:])
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	v, err := accountsigner.EncodeSignatureMeta(accountsigner.SignerTypeEd25519, normalizedPub)
	if err != nil {
		t.Fatalf("failed to encode signature meta: %v", err)
	}
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    unsigned.Nonce(),
		To:       unsigned.To(),
		Value:    unsigned.Value(),
		Gas:      unsigned.Gas(),
		GasPrice: unsigned.GasPrice(),
		Data:     unsigned.Data(),
		V:        v,
		R:        r,
		S:        s,
	})
	_, err = ResolveSender(tx, chainSigner, st)
	if !errors.Is(err, ErrAccountSignerMismatch) {
		t.Fatalf("unexpected error: %v", err)
	}
}
