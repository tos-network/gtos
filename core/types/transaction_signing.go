package types

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

var ErrInvalidChainId = errors.New("invalid chain id for signer")
var ErrSignerTypeNotSupportedByLocalKey = errors.New("signer type not supported by local ecdsa key")
var ErrInvalidSignerPrivateKey = errors.New("invalid signer private key")

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
	case "secp256r1":
		p256Key, err := asSecp256r1Key(prv)
		if err != nil {
			return nil, err
		}
		return signSecp256r1Hash(p256Key, hash)
	default:
		return nil, fmt.Errorf("%w: %s", ErrSignerTypeNotSupportedByLocalKey, normalized)
	}
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
	case "secp256r1":
		return "secp256r1", nil
	case "ed25519":
		return "ed25519", nil
	case "bls12-381", "bls12381":
		return "bls12-381", nil
	case "frost":
		return "frost", nil
	case "pqc":
		return "pqc", nil
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
			tx.GasPrice(),
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
	case "secp256r1", "ed25519":
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
	copy(addr[:], crypto.Keccak256(pub[1:])[12:])
	return addr, nil
}
