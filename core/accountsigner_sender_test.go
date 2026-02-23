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

func TestResolveSenderElgamal(t *testing.T) {
	st := newSenderTestState(t)
	chainSigner := types.LatestSignerForChainID(big.NewInt(1))
	to := common.HexToAddress("0x00000000000000000000000000000000000000ba")

	priv, err := accountsigner.GenerateElgamalPrivateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate elgamal key: %v", err)
	}
	pub, err := accountsigner.PublicKeyFromElgamalPrivate(priv)
	if err != nil {
		t.Fatalf("failed to derive elgamal pubkey: %v", err)
	}
	_, normalizedPub, normalizedValue, err := accountsigner.NormalizeSigner(accountsigner.SignerTypeElgamal, hexutil.Encode(pub))
	if err != nil {
		t.Fatalf("normalize signer failed: %v", err)
	}
	from, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeElgamal, normalizedPub)
	if err != nil {
		t.Fatalf("derive address failed: %v", err)
	}
	accountsigner.Set(st, from, accountsigner.SignerTypeElgamal, normalizedValue)

	unsigned := newSignerUnsignedTx(0, from, to, accountsigner.SignerTypeElgamal)
	hash := chainSigner.Hash(unsigned)
	sig, err := accountsigner.SignElgamalHash(priv, hash)
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
		SignerType: accountsigner.SignerTypeElgamal,
		V:          big.NewInt(0),
		R:          new(big.Int).SetBytes(sig[:32]),
		S:          new(big.Int).SetBytes(sig[32:]),
	})

	got, err := ResolveSender(tx, chainSigner, st)
	if err != nil {
		t.Fatalf("resolve sender failed: %v", err)
	}
	if got != from {
		t.Fatalf("unexpected sender have=%s want=%s", got.Hex(), from.Hex())
	}
}

func TestResolveSenderBLS12381(t *testing.T) {
	st := newSenderTestState(t)
	chainSigner := types.LatestSignerForChainID(big.NewInt(1))
	to := common.HexToAddress("0x00000000000000000000000000000000000000be")

	priv, err := accountsigner.GenerateBLS12381PrivateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate bls private key: %v", err)
	}
	pub, err := accountsigner.PublicKeyFromBLS12381Private(priv)
	if err != nil {
		t.Fatalf("failed to derive bls public key: %v", err)
	}
	_, normalizedPub, normalizedValue, err := accountsigner.NormalizeSigner(accountsigner.SignerTypeBLS12381, hexutil.Encode(pub))
	if err != nil {
		t.Fatalf("normalize signer failed: %v", err)
	}
	from, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeBLS12381, normalizedPub)
	if err != nil {
		t.Fatalf("derive address failed: %v", err)
	}
	accountsigner.Set(st, from, accountsigner.SignerTypeBLS12381, normalizedValue)

	unsigned := newSignerUnsignedTx(0, from, to, accountsigner.SignerTypeBLS12381)
	hash := chainSigner.Hash(unsigned)
	sig, err := accountsigner.SignBLS12381Hash(priv, hash)
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
		SignerType: accountsigner.SignerTypeBLS12381,
		V:          big.NewInt(0),
		R:          new(big.Int).SetBytes(sig[:48]),
		S:          new(big.Int).SetBytes(sig[48:96]),
	})

	got, err := ResolveSender(tx, chainSigner, st)
	if err != nil {
		t.Fatalf("resolve sender failed: %v", err)
	}
	if got != from {
		t.Fatalf("unexpected sender have=%s want=%s", got.Hex(), from.Hex())
	}
}

func TestResolveSenderBLS12381FastAggregate(t *testing.T) {
	st := newSenderTestState(t)
	chainSigner := types.LatestSignerForChainID(big.NewInt(1))
	to := common.HexToAddress("0x00000000000000000000000000000000000000bf")

	var (
		pubs  [][]byte
		sigs  [][]byte
		privs [][]byte
	)
	for i := 0; i < 3; i++ {
		priv, err := accountsigner.GenerateBLS12381PrivateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate bls private key: %v", err)
		}
		pub, err := accountsigner.PublicKeyFromBLS12381Private(priv)
		if err != nil {
			t.Fatalf("failed to derive bls public key: %v", err)
		}
		privs = append(privs, priv)
		pubs = append(pubs, pub)
	}
	aggPub, err := accountsigner.AggregateBLS12381PublicKeys(pubs)
	if err != nil {
		t.Fatalf("failed to aggregate bls public keys: %v", err)
	}
	_, normalizedPub, normalizedValue, err := accountsigner.NormalizeSigner(accountsigner.SignerTypeBLS12381, hexutil.Encode(aggPub))
	if err != nil {
		t.Fatalf("normalize signer failed: %v", err)
	}
	from, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeBLS12381, normalizedPub)
	if err != nil {
		t.Fatalf("derive address failed: %v", err)
	}
	accountsigner.Set(st, from, accountsigner.SignerTypeBLS12381, normalizedValue)

	unsigned := newSignerUnsignedTx(0, from, to, accountsigner.SignerTypeBLS12381)
	hash := chainSigner.Hash(unsigned)
	for _, priv := range privs {
		sig, signErr := accountsigner.SignBLS12381Hash(priv, hash)
		if signErr != nil {
			t.Fatalf("failed to sign hash: %v", signErr)
		}
		sigs = append(sigs, sig)
	}
	aggSig, err := accountsigner.AggregateBLS12381Signatures(sigs)
	if err != nil {
		t.Fatalf("failed to aggregate signatures: %v", err)
	}
	r, s, err := accountsigner.SplitBLS12381Signature(aggSig)
	if err != nil {
		t.Fatalf("failed to split aggregate signature: %v", err)
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
		SignerType: accountsigner.SignerTypeBLS12381,
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

func TestResolveSenderRejectsUnknownSignerType(t *testing.T) {
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
	accountsigner.Set(st, from, accountsigner.SignerTypeSecp256k1, hexutil.Encode(crypto.FromECDSAPub(&key.PublicKey)))

	// Build tx using unknown signerType.
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
		SignerType: "frost",
		V:          new(big.Int).Set(v),
		R:          new(big.Int).Set(r),
		S:          new(big.Int).Set(s),
	})

	_, err = ResolveSender(unsupported, chainSigner, st)
	if !errors.Is(err, accountsigner.ErrUnknownSignerType) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveSenderRejectsChainIDMismatchSecp256k1(t *testing.T) {
	st := newSenderTestState(t)
	signerChain1 := types.LatestSignerForChainID(big.NewInt(1))
	signerChain2 := types.LatestSignerForChainID(big.NewInt(2))

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	to := common.HexToAddress("0x00000000000000000000000000000000000000b1")

	unsigned := newSignerUnsignedTx(0, from, to, accountsigner.SignerTypeSecp256k1)
	signed, err := types.SignTx(unsigned, signerChain1, key)
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}
	accountsigner.Set(st, from, accountsigner.SignerTypeSecp256k1, hexutil.Encode(crypto.FromECDSAPub(&key.PublicKey)))

	_, err = ResolveSender(signed, signerChain2, st)
	if !errors.Is(err, types.ErrInvalidChainId) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveSenderRejectsChainIDMismatchEd25519(t *testing.T) {
	st := newSenderTestState(t)
	signerChain1 := types.LatestSignerForChainID(big.NewInt(1))
	signerChain2 := types.LatestSignerForChainID(big.NewInt(2))
	to := common.HexToAddress("0x00000000000000000000000000000000000000b2")

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
	hash := signerChain1.Hash(unsigned)
	sig := ed25519.Sign(priv, hash[:])
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
		R:          new(big.Int).SetBytes(sig[:32]),
		S:          new(big.Int).SetBytes(sig[32:]),
	})

	_, err = ResolveSender(tx, signerChain2, st)
	if !errors.Is(err, types.ErrInvalidChainId) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveSenderRejectsSignerTypeMismatchWithConfiguredAccountSigner(t *testing.T) {
	st := newSenderTestState(t)
	chainSigner := types.LatestSignerForChainID(big.NewInt(1))
	from := common.HexToAddress("0x00000000000000000000000000000000000000b3")
	to := common.HexToAddress("0x00000000000000000000000000000000000000b4")

	r1Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate p256 key: %v", err)
	}
	r1Pub := elliptic.Marshal(elliptic.P256(), r1Key.X, r1Key.Y)
	_, _, r1Value, err := accountsigner.NormalizeSigner(accountsigner.SignerTypeSecp256r1, hexutil.Encode(r1Pub))
	if err != nil {
		t.Fatalf("normalize r1 signer failed: %v", err)
	}
	accountsigner.Set(st, from, accountsigner.SignerTypeSecp256r1, r1Value)

	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	unsigned := newSignerUnsignedTx(0, from, to, accountsigner.SignerTypeEd25519)
	hash := chainSigner.Hash(unsigned)
	edSig := ed25519.Sign(edPriv, hash[:])
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
		R:          new(big.Int).SetBytes(edSig[:32]),
		S:          new(big.Int).SetBytes(edSig[32:]),
	})

	_, err = ResolveSender(tx, chainSigner, st)
	if !errors.Is(err, ErrAccountSignerMismatch) {
		t.Fatalf("unexpected error: %v", err)
	}
}
