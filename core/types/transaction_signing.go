// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	btcschnorr "github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/crypto/ristretto255"
	"github.com/tos-network/gtos/params"
	"golang.org/x/crypto/sha3"
)

var ErrInvalidChainId = errors.New("invalid chain id for signer")
var ErrSignerTypeNotSupportedByLocalKey = errors.New("signer type not supported by local ecdsa key")
var ErrInvalidSignerPrivateKey = errors.New("invalid signer private key")

var (
	elgamalSignerHOnce sync.Once
	elgamalSignerH     *ristretto255.Element
	elgamalSignerHErr  error
)

// sigCache is used to cache the derived sender and contains
// the signer used to derive it.
type sigCache struct {
	signer Signer
	from   common.Address
}

// MakeSigner returns a Signer based on the given chain config.
func MakeSigner(config *params.ChainConfig, _ *big.Int) Signer {
	return NewLondonSigner(normalizeChainID(config.ChainID))
}

// LatestSigner returns the most permissive signer available for the given chain
// configuration. In GTOS, replay protection and typed
// transaction support are always active when chain ID is configured.
//
// Use this in transaction-handling code where the current block number is unknown. If you
// have the current block number available, use MakeSigner instead.
func LatestSigner(config *params.ChainConfig) Signer {
	return NewLondonSigner(normalizeChainID(config.ChainID))
}

// LatestSignerForChainID returns the 'most permissive' Signer available. Specifically,
// this enables support for replay protection and all implemented typed envelope
// transaction types if chainID is non-nil.
//
// Use this in transaction-handling code where the current block number and fork
// configuration are unknown. If you have a ChainConfig, use LatestSigner instead.
// If you have a ChainConfig and know the current block number, use MakeSigner instead.
func LatestSignerForChainID(chainID *big.Int) Signer {
	return NewLondonSigner(normalizeChainID(chainID))
}

func normalizeChainID(chainID *big.Int) *big.Int {
	if chainID == nil {
		return new(big.Int)
	}
	return chainID
}

// SignTx signs the transaction using the given signer and private key.
func SignTx(tx *Transaction, s Signer, prv *ecdsa.PrivateKey) (*Transaction, error) {
	sig, err := signForTx(tx, s, prv)
	if err != nil {
		return nil, err
	}
	return tx.WithSignature(s, sig)
}

// SignNewTx creates a transaction and signs it.
func SignNewTx(prv *ecdsa.PrivateKey, s Signer, txdata TxData) (*Transaction, error) {
	tx := NewTx(txdata)
	sig, err := signForTx(tx, s, prv)
	if err != nil {
		return nil, err
	}
	return tx.WithSignature(s, sig)
}

func signForTx(tx *Transaction, s Signer, prv *ecdsa.PrivateKey) ([]byte, error) {
	hash := s.Hash(tx)
	if tx.Type() != SignerTxType {
		return crypto.Sign(hash[:], prv)
	}
	signerType, ok := tx.SignerType()
	if !ok {
		return nil, ErrTxTypeNotSupported
	}
	normalized, err := canonicalSignerType(signerType)
	if err != nil {
		return nil, err
	}
	switch normalized {
	case "secp256k1":
		return crypto.Sign(hash[:], prv)
	case "schnorr":
		schnorrKey, err := asSchnorrKey(prv)
		if err != nil {
			return nil, err
		}
		return signSchnorrHash(schnorrKey, hash)
	case "secp256r1":
		p256Key, err := asSecp256r1Key(prv)
		if err != nil {
			return nil, err
		}
		return signSecp256r1Hash(p256Key, hash)
	case "ed25519":
		edKey, err := asEd25519Key(prv)
		if err != nil {
			return nil, err
		}
		return signEd25519Hash(edKey, hash)
	case "elgamal":
		elgamalKey, err := asElgamalKey(prv)
		if err != nil {
			return nil, err
		}
		return signElgamalHash(elgamalKey, hash)
	default:
		return nil, fmt.Errorf("%w: %s", ErrSignerTypeNotSupportedByLocalKey, normalized)
	}
}

func asSchnorrKey(prv *ecdsa.PrivateKey) (*btcec.PrivateKey, error) {
	if prv == nil || prv.D == nil || prv.D.Sign() <= 0 {
		return nil, ErrInvalidSignerPrivateKey
	}
	d := new(big.Int).Set(prv.D)
	d.Mod(d, btcec.S256().N)
	if d.Sign() <= 0 {
		return nil, ErrInvalidSignerPrivateKey
	}
	scalar := make([]byte, 32)
	db := d.Bytes()
	copy(scalar[len(scalar)-len(db):], db)
	key, _ := btcec.PrivKeyFromBytes(scalar)
	if key == nil {
		return nil, ErrInvalidSignerPrivateKey
	}
	return key, nil
}

func signSchnorrHash(priv *btcec.PrivateKey, txHash common.Hash) ([]byte, error) {
	if priv == nil {
		return nil, ErrInvalidSignerPrivateKey
	}
	sig, err := btcschnorr.Sign(priv, txHash[:])
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

func asSecp256r1Key(prv *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	if prv == nil || prv.D == nil || prv.D.Sign() <= 0 {
		return nil, ErrInvalidSignerPrivateKey
	}
	if prv.Curve == elliptic.P256() {
		return prv, nil
	}
	curve := elliptic.P256()
	d := new(big.Int).Set(prv.D)
	d.Mod(d, curve.Params().N)
	if d.Sign() <= 0 {
		return nil, ErrInvalidSignerPrivateKey
	}
	key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve},
		D:         d,
	}
	key.PublicKey.X, key.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())
	if key.PublicKey.X == nil || key.PublicKey.Y == nil {
		return nil, ErrInvalidSignerPrivateKey
	}
	return key, nil
}

func signSecp256r1Hash(priv *ecdsa.PrivateKey, txHash common.Hash) ([]byte, error) {
	if priv == nil || priv.Curve == nil || priv.Curve != elliptic.P256() {
		return nil, ErrInvalidSignerPrivateKey
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, txHash[:])
	if err != nil {
		return nil, err
	}
	return encodeSecp256r1Signature(r, s)
}

func asEd25519Key(prv *ecdsa.PrivateKey) (ed25519.PrivateKey, error) {
	if prv == nil || prv.D == nil || prv.D.Sign() <= 0 {
		return nil, ErrInvalidSignerPrivateKey
	}
	seed := make([]byte, ed25519.SeedSize)
	d := prv.D.Bytes()
	if len(d) > ed25519.SeedSize {
		d = d[len(d)-ed25519.SeedSize:]
	}
	copy(seed[ed25519.SeedSize-len(d):], d)
	return ed25519.NewKeyFromSeed(seed), nil
}

func signEd25519Hash(priv ed25519.PrivateKey, txHash common.Hash) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrInvalidSignerPrivateKey
	}
	return ed25519.Sign(priv, txHash[:]), nil
}

func asElgamalKey(prv *ecdsa.PrivateKey) ([]byte, error) {
	if prv == nil || prv.D == nil || prv.D.Sign() <= 0 {
		return nil, ErrInvalidSignerPrivateKey
	}
	var wide [64]byte
	d := prv.D.Bytes()
	for i := 0; i < len(d) && i < len(wide); i++ {
		// SetUniformBytes expects little-endian input. Convert big-endian bigint bytes.
		wide[i] = d[len(d)-1-i]
	}
	scalar := ristretto255.NewScalar()
	if _, err := scalar.SetUniformBytes(wide[:]); err != nil {
		return nil, ErrInvalidSignerPrivateKey
	}
	if scalar.Equal(ristretto255.NewScalar()) == 1 {
		return nil, ErrInvalidSignerPrivateKey
	}
	return scalar.Bytes(), nil
}

func elgamalSignGeneratorH() (*ristretto255.Element, error) {
	elgamalSignerHOnce.Do(func() {
		base := ristretto255.NewGeneratorElement().Bytes()
		digest := sha3.Sum512(base)
		h := ristretto255.NewIdentityElement()
		if _, err := h.SetUniformBytes(digest[:]); err != nil {
			elgamalSignerHErr = err
			return
		}
		elgamalSignerH = h
	})
	if elgamalSignerHErr != nil {
		return nil, elgamalSignerHErr
	}
	return ristretto255.NewIdentityElement().Set(elgamalSignerH), nil
}

func elgamalSignHashAndPointToScalar(pub []byte, message []byte, point *ristretto255.Element) (*ristretto255.Scalar, error) {
	hasher := sha3.New512()
	hasher.Write(pub)
	hasher.Write(message)
	hasher.Write(point.Bytes())
	digest := hasher.Sum(nil)
	out := ristretto255.NewScalar()
	if _, err := out.SetUniformBytes(digest); err != nil {
		return nil, err
	}
	return out, nil
}

func signElgamalHash(secretBytes []byte, txHash common.Hash) ([]byte, error) {
	if len(secretBytes) != 32 {
		return nil, ErrInvalidSignerPrivateKey
	}
	secret := ristretto255.NewScalar()
	if _, err := secret.SetCanonicalBytes(secretBytes); err != nil {
		return nil, ErrInvalidSignerPrivateKey
	}
	if secret.Equal(ristretto255.NewScalar()) == 1 {
		return nil, ErrInvalidSignerPrivateKey
	}
	var kWide [64]byte
	if _, err := rand.Read(kWide[:]); err != nil {
		return nil, err
	}
	k := ristretto255.NewScalar()
	if _, err := k.SetUniformBytes(kWide[:]); err != nil {
		return nil, err
	}
	if k.Equal(ristretto255.NewScalar()) == 1 {
		kWide[0] = 1
		if _, err := k.SetUniformBytes(kWide[:]); err != nil {
			return nil, err
		}
	}
	h, err := elgamalSignGeneratorH()
	if err != nil {
		return nil, err
	}
	inv := ristretto255.NewScalar().Invert(secret)
	pub := ristretto255.NewIdentityElement().ScalarMult(inv, h)
	rPoint := ristretto255.NewIdentityElement().ScalarMult(k, h)
	e, err := elgamalSignHashAndPointToScalar(pub.Bytes(), txHash[:], rPoint)
	if err != nil {
		return nil, err
	}
	s := ristretto255.NewScalar().Add(ristretto255.NewScalar().Multiply(inv, e), k)
	out := make([]byte, 64)
	copy(out[:32], s.Bytes())
	copy(out[32:], e.Bytes())
	return out, nil
}

func encodeSecp256r1Signature(r, s *big.Int) ([]byte, error) {
	if r == nil || s == nil || r.Sign() <= 0 || s.Sign() <= 0 {
		return nil, ErrInvalidSignerPrivateKey
	}
	if r.BitLen() > 256 || s.BitLen() > 256 {
		return nil, ErrInvalidSignerPrivateKey
	}
	out := make([]byte, crypto.SignatureLength)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):64], sb)
	out[64] = 0
	return out, nil
}

func canonicalSignerType(signerType string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(signerType)) {
	case "secp256k1", "ethereum_secp256k1":
		return "secp256k1", nil
	case "schnorr":
		return "schnorr", nil
	case "secp256r1":
		return "secp256r1", nil
	case "ed25519":
		return "ed25519", nil
	case "bls12-381", "bls12381":
		return "bls12-381", nil
	case "elgamal":
		return "elgamal", nil
	default:
		return "", fmt.Errorf("unknown signerType: %s", strings.TrimSpace(signerType))
	}
}

// MustSignNewTx creates a transaction and signs it.
// This panics if the transaction cannot be signed.
func MustSignNewTx(prv *ecdsa.PrivateKey, s Signer, txdata TxData) *Transaction {
	tx, err := SignNewTx(prv, s, txdata)
	if err != nil {
		panic(err)
	}
	return tx
}

// Sender returns the address derived from the signature (V, R, S) using secp256k1
// elliptic curve and an error if it failed deriving or upon an incorrect
// signature.
//
// Sender may cache the address, allowing it to be used regardless of
// signing method. The cache is invalidated if the cached signer does
// not match the signer used in the current call.
func Sender(signer Signer, tx *Transaction) (common.Address, error) {
	if sc := tx.from.Load(); sc != nil {
		sigCache := sc.(sigCache)
		// If the signer used to derive from in a previous
		// call is not the same as used current, invalidate
		// the cache.
		if sigCache.signer.Equal(signer) {
			return sigCache.from, nil
		}
	}

	addr, err := signer.Sender(tx)
	if err != nil {
		return common.Address{}, err
	}
	tx.from.Store(sigCache{signer: signer, from: addr})
	return addr, nil
}

// Signer encapsulates transaction signature handling. The name of this type is slightly
// misleading because Signers don't actually sign, they're just for validating and
// processing of signatures.
//
// Note that this interface is not a stable API and may change at any time to accommodate
// new protocol rules.
type Signer interface {
	// Sender returns the sender address of the transaction.
	Sender(tx *Transaction) (common.Address, error)

	// SignatureValues returns the raw R, S, V values corresponding to the
	// given signature.
	SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error)
	ChainID() *big.Int

	// Hash returns 'signature hash', i.e. the transaction hash that is signed by the
	// private key. This hash does not uniquely identify the transaction.
	Hash(tx *Transaction) common.Hash

	// Equal returns true if the given signer is the same as the receiver.
	Equal(Signer) bool
}

type londonSigner struct{ accessListSigner }

// NewLondonSigner returns the signer used by GTOS.
// Only SignerTx transactions are supported.
func NewLondonSigner(chainId *big.Int) Signer {
	return londonSigner{accessListSigner{NewReplayProtectedSigner(chainId)}}
}

func (s londonSigner) Sender(tx *Transaction) (common.Address, error) {
	return s.accessListSigner.Sender(tx)
}

func (s londonSigner) Equal(s2 Signer) bool {
	x, ok := s2.(londonSigner)
	return ok && x.chainId.Cmp(s.chainId) == 0
}

func (s londonSigner) SignatureValues(tx *Transaction, sig []byte) (R, S, V *big.Int, err error) {
	return s.accessListSigner.SignatureValues(tx, sig)
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s londonSigner) Hash(tx *Transaction) common.Hash {
	return s.accessListSigner.Hash(tx)
}

type accessListSigner struct{ ReplayProtectedSigner }

// New access-list signer constructor.
// In GTOS this is equivalent to the SignerTx signer and exists for compatibility.
func NewAccessListSigner(chainId *big.Int) Signer {
	return accessListSigner{NewReplayProtectedSigner(chainId)}
}

func (s accessListSigner) ChainID() *big.Int {
	return s.chainId
}

func (s accessListSigner) Equal(s2 Signer) bool {
	x, ok := s2.(accessListSigner)
	return ok && x.chainId.Cmp(s.chainId) == 0
}

func (s accessListSigner) Sender(tx *Transaction) (common.Address, error) {
	if tx.Type() != SignerTxType {
		return common.Address{}, ErrTxTypeNotSupported
	}
	V, R, S := tx.RawSignatureValues()
	signerType, ok := tx.SignerType()
	if !ok || signerType != "secp256k1" {
		return common.Address{}, ErrTxTypeNotSupported
	}
	V = new(big.Int).Add(V, big.NewInt(27))
	if tx.ChainId().Cmp(s.chainId) != 0 {
		return common.Address{}, ErrInvalidChainId
	}
	from, err := recoverPlain(s.Hash(tx), R, S, V, true)
	if err != nil {
		return common.Address{}, err
	}
	explicitFrom, ok := tx.SignerFrom()
	if !ok {
		return common.Address{}, ErrInvalidSig
	}
	// Compatibility: zero explicit from is treated as "not set" and skips equality check.
	if explicitFrom != (common.Address{}) && explicitFrom != from {
		return common.Address{}, ErrInvalidSig
	}
	return from, nil
}

func (s accessListSigner) SignatureValues(tx *Transaction, sig []byte) (R, S, V *big.Int, err error) {
	txdata, ok := tx.inner.(*SignerTx)
	if !ok {
		return nil, nil, nil, ErrTxTypeNotSupported
	}
	if txdata.ChainID.Sign() != 0 && txdata.ChainID.Cmp(s.chainId) != 0 {
		return nil, nil, nil, ErrInvalidChainId
	}
	R, S, V, err = decodeSignerTxSignature(txdata.SignerType, sig)
	if err != nil {
		return nil, nil, nil, err
	}
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s accessListSigner) Hash(tx *Transaction) common.Hash {
	if tx.Type() != SignerTxType {
		return common.Hash{}
	}
	from, ok := tx.SignerFrom()
	if !ok {
		return common.Hash{}
	}
	signerType, ok := tx.SignerType()
	if !ok {
		return common.Hash{}
	}
	return prefixedRlpHash(
		tx.Type(),
		[]interface{}{
			s.chainId,
			tx.Nonce(),
			tx.Gas(),
			tx.To(),
			tx.Value(),
			tx.Data(),
			tx.AccessList(),
			from,
			signerType,
		})
}

// ReplayProtectedSigner is kept for compatibility with older call sites.
// In GTOS it behaves the same as the SignerTx signer.
type ReplayProtectedSigner struct {
	chainId, chainIdMul *big.Int
}

func NewReplayProtectedSigner(chainId *big.Int) ReplayProtectedSigner {
	if chainId == nil {
		chainId = new(big.Int)
	}
	return ReplayProtectedSigner{
		chainId:    chainId,
		chainIdMul: new(big.Int).Mul(chainId, big.NewInt(2)),
	}
}

func (s ReplayProtectedSigner) ChainID() *big.Int {
	return s.chainId
}

func (s ReplayProtectedSigner) Equal(s2 Signer) bool {
	replayProtection, ok := s2.(ReplayProtectedSigner)
	return ok && replayProtection.chainId.Cmp(s.chainId) == 0
}

func (s ReplayProtectedSigner) Sender(tx *Transaction) (common.Address, error) {
	return accessListSigner{s}.Sender(tx)
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (s ReplayProtectedSigner) SignatureValues(tx *Transaction, sig []byte) (R, S, V *big.Int, err error) {
	return accessListSigner{s}.SignatureValues(tx, sig)
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s ReplayProtectedSigner) Hash(tx *Transaction) common.Hash {
	return accessListSigner{s}.Hash(tx)
}

func decodeSignerTxSignature(signerType string, sig []byte) (r, s, v *big.Int, err error) {
	switch strings.ToLower(strings.TrimSpace(signerType)) {
	case "bls12-381", "bls12381":
		if len(sig) != 96 {
			return nil, nil, nil, ErrInvalidSig
		}
		r = new(big.Int).SetBytes(sig[:48])
		s = new(big.Int).SetBytes(sig[48:96])
		v = new(big.Int)
		return r, s, v, nil
	case "schnorr", "secp256r1", "ed25519", "elgamal":
		switch len(sig) {
		case 64:
			r = new(big.Int).SetBytes(sig[:32])
			s = new(big.Int).SetBytes(sig[32:64])
			v = new(big.Int)
			return r, s, v, nil
		case crypto.SignatureLength:
			r = new(big.Int).SetBytes(sig[:32])
			s = new(big.Int).SetBytes(sig[32:64])
			v = new(big.Int).SetUint64(uint64(sig[64]))
			return r, s, v, nil
		default:
			return nil, nil, nil, ErrInvalidSig
		}
	default:
		if len(sig) != crypto.SignatureLength {
			return nil, nil, nil, ErrInvalidSig
		}
		r = new(big.Int).SetBytes(sig[:32])
		s = new(big.Int).SetBytes(sig[32:64])
		v = new(big.Int).SetUint64(uint64(sig[64]))
		return r, s, v, nil
	}
}

func recoverPlain(sighash common.Hash, R, S, Vb *big.Int, homestead bool) (common.Address, error) {
	if Vb.BitLen() > 8 {
		return common.Address{}, ErrInvalidSig
	}
	V := byte(Vb.Uint64() - 27)
	if !crypto.ValidateSignatureValues(V, R, S, homestead) {
		return common.Address{}, ErrInvalidSig
	}
	// encode the signature in uncompressed format
	r, s := R.Bytes(), S.Bytes()
	sig := make([]byte, crypto.SignatureLength)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V
	// recover the public key from the signature
	pub, err := crypto.Ecrecover(sighash[:], sig)
	if err != nil {
		return common.Address{}, err
	}
	if len(pub) == 0 || pub[0] != 4 {
		return common.Address{}, errors.New("invalid public key")
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pub[1:]))
	return addr, nil
}
