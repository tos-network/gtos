// Copyright 2014 The go-ethereum Authors
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
	"bytes"
	"container/heap"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/math"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/rlp"
)

var (
	ErrInvalidSig         = errors.New("invalid transaction v, r, s values")
	ErrInvalidTxType      = errors.New("transaction type not valid in this context")
	ErrTxTypeNotSupported = errors.New("transaction type not supported")
	ErrGasFeeCapTooLow    = errors.New("fee cap less than base fee")
	errShortTypedTx       = errors.New("typed transaction too short")
)

func signatureValuesPresent(v, r, s *big.Int) bool {
	if v == nil || r == nil || s == nil {
		return false
	}
	return v.Sign() != 0 || r.Sign() != 0 || s.Sign() != 0
}

// Transaction types.
const (
	SignerTxType       = iota // 0x00
	PrivTransferTxType        // 0x01
	ShieldTxType              // 0x02
	UnshieldTxType            // 0x03
)

// IsProofFastPath returns true if this transaction type is eligible for
// proof-backed batch validation in Phase 1 (native-transfer-batch-v1).
func (tx *Transaction) IsProofFastPath() bool {
	return tx.ProofClass() != ProofCoverageNone
}

// ProofClass returns the proof coverage class for this transaction.
// In Phase 1, only transfer-class transactions are proof-eligible.
func (tx *Transaction) ProofClass() ProofCoverageClass {
	switch tx.Type() {
	case SignerTxType:
		// SignerTx is proof-eligible only if it is a plain value transfer
		// (no contract call). A plain transfer has nil or empty data and
		// a non-nil To address.
		if tx.To() != nil && len(tx.Data()) == 0 {
			return ProofCoverageTransfer
		}
		return ProofCoverageNone
	case ShieldTxType, PrivTransferTxType, UnshieldTxType:
		return ProofCoverageTransfer
	default:
		return ProofCoverageNone
	}
}

// Transaction is an TOS transaction.
type Transaction struct {
	inner TxData    // Consensus contents of a transaction
	time  time.Time // Time first seen locally (spam avoidance)

	// caches
	hash atomic.Value
	size atomic.Value
	from atomic.Value
}

// NewTx creates a new transaction.
func NewTx(inner TxData) *Transaction {
	tx := new(Transaction)
	tx.setDecoded(inner.copy(), 0)
	return tx
}

// TxData is the underlying data of a transaction.
//
// This is implemented by SignerTx.
type TxData interface {
	txType() byte // returns the type ID
	copy() TxData // creates a deep copy and initializes all fields

	chainID() *big.Int
	accessList() AccessList
	data() []byte
	gas() uint64
	txPrice() *big.Int
	gasTipCap() *big.Int
	gasFeeCap() *big.Int
	value() *big.Int
	nonce() uint64
	to() *common.Address

	rawSignatureValues() (v, r, s *big.Int)
	setSignatureValues(chainID, v, r, s *big.Int)
}

// EncodeRLP implements rlp.Encoder
func (tx *Transaction) EncodeRLP(w io.Writer) error {
	switch tx.Type() {
	case SignerTxType, PrivTransferTxType, ShieldTxType, UnshieldTxType:
	default:
		return ErrTxTypeNotSupported
	}
	buf := encodeBufferPool.Get().(*bytes.Buffer)
	defer encodeBufferPool.Put(buf)
	buf.Reset()
	if err := tx.encodeTyped(buf); err != nil {
		return err
	}
	return rlp.Encode(w, buf.Bytes())
}

// encodeTyped writes the canonical encoding of a typed transaction to w.
func (tx *Transaction) encodeTyped(w *bytes.Buffer) error {
	w.WriteByte(tx.Type())
	return rlp.Encode(w, tx.inner)
}

// MarshalBinary returns the canonical encoding of the transaction.
// For SignerTx and PrivTransferTx transactions, it returns the type and payload.
func (tx *Transaction) MarshalBinary() ([]byte, error) {
	switch tx.Type() {
	case SignerTxType, PrivTransferTxType, ShieldTxType, UnshieldTxType:
	default:
		return nil, ErrTxTypeNotSupported
	}
	var buf bytes.Buffer
	err := tx.encodeTyped(&buf)
	return buf.Bytes(), err
}

// DecodeRLP implements rlp.Decoder
func (tx *Transaction) DecodeRLP(s *rlp.Stream) error {
	kind, _, err := s.Kind()
	switch {
	case err != nil:
		return err
	case kind == rlp.List:
		return ErrTxTypeNotSupported
	default:
		// It's an typed TX envelope.
		var b []byte
		if b, err = s.Bytes(); err != nil {
			return err
		}
		inner, err := tx.decodeTyped(b)
		if err == nil {
			tx.setDecoded(inner, len(b))
		}
		return err
	}
}

// UnmarshalBinary decodes the canonical encoding of transactions.
// It supports SignerTx typed transactions only.
func (tx *Transaction) UnmarshalBinary(b []byte) error {
	if len(b) > 0 && b[0] > 0x7f {
		return ErrTxTypeNotSupported
	}
	// It's an typed transaction envelope.
	inner, err := tx.decodeTyped(b)
	if err != nil {
		return err
	}
	tx.setDecoded(inner, len(b))
	return nil
}

// decodeTyped decodes a typed transaction from the canonical format.
func (tx *Transaction) decodeTyped(b []byte) (TxData, error) {
	if len(b) <= 1 {
		return nil, errShortTypedTx
	}
	switch b[0] {
	case SignerTxType:
		var inner SignerTx
		err := rlp.DecodeBytes(b[1:], &inner)
		if err != nil {
			return nil, err
		}
		if len(inner.SignerType) > 64 { // accountsigner.MaxSignerTypeLen
			return nil, fmt.Errorf("signer type too long: %d > 64", len(inner.SignerType))
		}
		if _, err := canonicalSignerType(inner.SignerType); err != nil {
			return nil, err
		}
		if inner.Sponsor != (common.Address{}) {
			if len(inner.SponsorSignerType) > 64 {
				return nil, fmt.Errorf("sponsor signer type too long: %d > 64", len(inner.SponsorSignerType))
			}
			if inner.SponsorSignerType == "" {
				return nil, fmt.Errorf("missing sponsor signer type for sponsored tx")
			}
			if _, err := canonicalSignerType(inner.SponsorSignerType); err != nil {
				return nil, err
			}
			if inner.SponsorExpiry == 0 {
				return nil, fmt.Errorf("missing sponsor expiry for sponsored tx")
			}
		}
		if err := sanityCheckSignerTxSignature(inner.SignerType, inner.V, inner.R, inner.S); err != nil &&
			signatureValuesPresent(inner.V, inner.R, inner.S) {
			return nil, err
		}
		if inner.Sponsor != (common.Address{}) {
			if err := sanityCheckSignerTxSignature(inner.SponsorSignerType, inner.SponsorV, inner.SponsorR, inner.SponsorS); err != nil &&
				signatureValuesPresent(inner.SponsorV, inner.SponsorR, inner.SponsorS) {
				return nil, err
			}
		}
		return &inner, nil
	case PrivTransferTxType:
		var inner PrivTransferTx
		err := rlp.DecodeBytes(b[1:], &inner)
		return &inner, err
	case ShieldTxType:
		var inner ShieldTx
		err := rlp.DecodeBytes(b[1:], &inner)
		return &inner, err
	case UnshieldTxType:
		var inner UnshieldTx
		err := rlp.DecodeBytes(b[1:], &inner)
		return &inner, err
	default:
		return nil, ErrTxTypeNotSupported
	}
}

// setDecoded sets the inner transaction and size after decoding.
func (tx *Transaction) setDecoded(inner TxData, size int) {
	tx.inner = inner
	tx.time = time.Now()
	if size > 0 {
		tx.size.Store(common.StorageSize(size))
	}
}

func sanityCheckSignature(v *big.Int, r *big.Int, s *big.Int, _ bool) error {
	if v == nil || r == nil || s == nil {
		return ErrInvalidSig
	}
	if v.BitLen() > 8 {
		return ErrInvalidSig
	}
	plainV := byte(v.Uint64())
	if !crypto.ValidateSignatureValues(plainV, r, s, true) {
		return ErrInvalidSig
	}
	return nil
}

func sanityCheckSignerTxSignature(signerType string, v *big.Int, r *big.Int, s *big.Int) error {
	switch strings.ToLower(strings.TrimSpace(signerType)) {
	case "secp256k1", "ethereum_secp256k1":
		return sanityCheckSignature(v, r, s, false)
	case "schnorr", "secp256r1", "ed25519", "elgamal":
		if v == nil || r == nil || s == nil {
			return ErrInvalidSig
		}
		if v.BitLen() > 8 {
			return ErrInvalidSig
		}
		if r.Sign() < 0 || s.Sign() < 0 || r.BitLen() > 256 || s.BitLen() > 256 {
			return ErrInvalidSig
		}
		return nil
	case "bls12-381", "bls12381":
		if v == nil || r == nil || s == nil {
			return ErrInvalidSig
		}
		if v.Sign() != 0 || v.BitLen() > 8 {
			return ErrInvalidSig
		}
		if r.Sign() < 0 || s.Sign() < 0 || r.BitLen() > 384 || s.BitLen() > 384 {
			return ErrInvalidSig
		}
		return nil
	default:
		return ErrInvalidSig
	}
}

// Protected is always true for SignerTx.
func (tx *Transaction) Protected() bool {
	return tx.Type() == SignerTxType
}

// Type returns the transaction type.
func (tx *Transaction) Type() uint8 {
	return tx.inner.txType()
}

// ChainId returns the explicit chain ID of the transaction.
func (tx *Transaction) ChainId() *big.Int {
	return tx.inner.chainID()
}

// SignerFrom returns the explicit signer address if the transaction type carries one.
func (tx *Transaction) SignerFrom() (common.Address, bool) {
	if stx, ok := tx.inner.(*SignerTx); ok {
		return stx.From, true
	}
	return common.Address{}, false
}

// SignerType returns the explicit signer type if the transaction type carries one.
func (tx *Transaction) SignerType() (string, bool) {
	if stx, ok := tx.inner.(*SignerTx); ok {
		return stx.SignerType, true
	}
	return "", false
}

// SponsorFrom returns the explicit sponsor address if the transaction carries one.
func (tx *Transaction) SponsorFrom() (common.Address, bool) {
	if stx, ok := tx.inner.(*SignerTx); ok && stx.Sponsor != (common.Address{}) {
		return stx.Sponsor, true
	}
	return common.Address{}, false
}

// SponsorSignerType returns the explicit sponsor signer type if the transaction carries one.
func (tx *Transaction) SponsorSignerType() (string, bool) {
	if stx, ok := tx.inner.(*SignerTx); ok && stx.Sponsor != (common.Address{}) {
		return stx.SponsorSignerType, true
	}
	return "", false
}

// SponsorNonce returns the sponsor replay nonce for sponsored transactions.
func (tx *Transaction) SponsorNonce() (uint64, bool) {
	if stx, ok := tx.inner.(*SignerTx); ok && stx.Sponsor != (common.Address{}) {
		return stx.SponsorNonce, true
	}
	return 0, false
}

// SponsorExpiry returns the sponsor expiry timestamp for sponsored transactions.
func (tx *Transaction) SponsorExpiry() (uint64, bool) {
	if stx, ok := tx.inner.(*SignerTx); ok && stx.Sponsor != (common.Address{}) {
		return stx.SponsorExpiry, true
	}
	return 0, false
}

// SponsorPolicyHash returns the sponsor policy hash for sponsored transactions.
func (tx *Transaction) SponsorPolicyHash() (common.Hash, bool) {
	if stx, ok := tx.inner.(*SignerTx); ok && stx.Sponsor != (common.Address{}) {
		return stx.SponsorPolicyHash, true
	}
	return common.Hash{}, false
}

// TerminalClass returns the terminal class from the transaction envelope.
// Returns (0, false) for non-SignerTx types; 0 means "unset" (default: app).
func (tx *Transaction) TerminalClass() (uint8, bool) {
	if stx, ok := tx.inner.(*SignerTx); ok {
		return stx.TerminalClass, true
	}
	return 0, false
}

// TrustTier returns the trust tier from the transaction envelope.
// Returns (0, false) for non-SignerTx types; 0 means "unset" (default: full trust).
func (tx *Transaction) TrustTier() (uint8, bool) {
	if stx, ok := tx.inner.(*SignerTx); ok {
		return stx.TrustTier, true
	}
	return 0, false
}

// SponsorRawSignatureValues returns the sponsor V, R, S values if present.
func (tx *Transaction) SponsorRawSignatureValues() (v, r, s *big.Int, ok bool) {
	if stx, okType := tx.inner.(*SignerTx); okType && stx.Sponsor != (common.Address{}) {
		return stx.SponsorV, stx.SponsorR, stx.SponsorS, true
	}
	return nil, nil, nil, false
}

// IsSponsored reports whether the transaction uses native sponsor funding.
func (tx *Transaction) IsSponsored() bool {
	if stx, ok := tx.inner.(*SignerTx); ok {
		return stx.Sponsor != (common.Address{})
	}
	return false
}

// PrivTransferFrom returns the derived address of the sender's ElGamal public
// key when the transaction is a PrivTransferTx. The second return value
// indicates whether the transaction is indeed a PrivTransferTx.
func (tx *Transaction) PrivTransferFrom() (common.Address, bool) {
	if ptx, ok := tx.inner.(*PrivTransferTx); ok {
		return ptx.FromAddress(), true
	}
	return common.Address{}, false
}

// PrivTransferInner returns the underlying PrivTransferTx, or nil otherwise.
func (tx *Transaction) PrivTransferInner() *PrivTransferTx {
	if ptx, ok := tx.inner.(*PrivTransferTx); ok {
		return ptx
	}
	return nil
}

// ShieldFrom returns the derived address of the sender's ElGamal public key
// when the transaction is a ShieldTx.
func (tx *Transaction) ShieldFrom() (common.Address, bool) {
	if stx, ok := tx.inner.(*ShieldTx); ok {
		return stx.DerivedAddress(), true
	}
	return common.Address{}, false
}

// ShieldInner returns the underlying ShieldTx, or nil otherwise.
func (tx *Transaction) ShieldInner() *ShieldTx {
	if stx, ok := tx.inner.(*ShieldTx); ok {
		return stx
	}
	return nil
}

// UnshieldFrom returns the derived address of the sender's ElGamal public key
// when the transaction is an UnshieldTx.
func (tx *Transaction) UnshieldFrom() (common.Address, bool) {
	if utx, ok := tx.inner.(*UnshieldTx); ok {
		return utx.DerivedAddress(), true
	}
	return common.Address{}, false
}

// UnshieldInner returns the underlying UnshieldTx, or nil otherwise.
func (tx *Transaction) UnshieldInner() *UnshieldTx {
	if utx, ok := tx.inner.(*UnshieldTx); ok {
		return utx
	}
	return nil
}

// PrivTxFrom returns the derived address for any privacy transaction type
// (PrivTransfer, Shield, or Unshield).
func (tx *Transaction) PrivTxFrom() (common.Address, bool) {
	switch inner := tx.inner.(type) {
	case *PrivTransferTx:
		return inner.FromAddress(), true
	case *ShieldTx:
		return inner.DerivedAddress(), true
	case *UnshieldTx:
		return inner.DerivedAddress(), true
	}
	return common.Address{}, false
}

// Data returns the input data of the transaction.
func (tx *Transaction) Data() []byte { return tx.inner.data() }

// AccessList returns the access list of the transaction.
func (tx *Transaction) AccessList() AccessList { return tx.inner.accessList() }

// Gas returns the gas limit of the transaction.
func (tx *Transaction) Gas() uint64 { return tx.inner.gas() }

// TxPrice returns the tx price of the transaction.
func (tx *Transaction) TxPrice() *big.Int { return new(big.Int).Set(tx.inner.txPrice()) }

// GasTipCap returns the gasTipCap per gas of the transaction.
func (tx *Transaction) GasTipCap() *big.Int { return new(big.Int).Set(tx.inner.gasTipCap()) }

// GasFeeCap returns the fee cap per gas of the transaction.
func (tx *Transaction) GasFeeCap() *big.Int { return new(big.Int).Set(tx.inner.gasFeeCap()) }

// Value returns the tos amount of the transaction.
func (tx *Transaction) Value() *big.Int { return new(big.Int).Set(tx.inner.value()) }

// Nonce returns the sender account nonce of the transaction.
func (tx *Transaction) Nonce() uint64 { return tx.inner.nonce() }

// To returns the recipient address of the transaction.
// For contract-creation transactions, To returns nil.
func (tx *Transaction) To() *common.Address {
	return copyAddressPtr(tx.inner.to())
}

// Cost returns gas * txPrice + value.
func (tx *Transaction) Cost() *big.Int {
	total := new(big.Int).Mul(tx.TxPrice(), new(big.Int).SetUint64(tx.Gas()))
	total.Add(total, tx.Value())
	return total
}

// RawSignatureValues returns the V, R, S signature values of the transaction.
// The return values should not be modified by the caller.
func (tx *Transaction) RawSignatureValues() (v, r, s *big.Int) {
	return tx.inner.rawSignatureValues()
}

// GasFeeCapCmp compares the fee cap of two transactions.
func (tx *Transaction) GasFeeCapCmp(other *Transaction) int {
	return tx.inner.gasFeeCap().Cmp(other.inner.gasFeeCap())
}

// GasFeeCapIntCmp compares the fee cap of the transaction against the given fee cap.
func (tx *Transaction) GasFeeCapIntCmp(other *big.Int) int {
	return tx.inner.gasFeeCap().Cmp(other)
}

// GasTipCapCmp compares the gasTipCap of two transactions.
func (tx *Transaction) GasTipCapCmp(other *Transaction) int {
	return tx.inner.gasTipCap().Cmp(other.inner.gasTipCap())
}

// GasTipCapIntCmp compares the gasTipCap of the transaction against the given gasTipCap.
func (tx *Transaction) GasTipCapIntCmp(other *big.Int) int {
	return tx.inner.gasTipCap().Cmp(other)
}

// EffectiveGasTip returns the effective miner gasTipCap for the given base fee.
// Note: if the effective gasTipCap is negative, this method returns both error
// the actual negative value, _and_ ErrGasFeeCapTooLow
func (tx *Transaction) EffectiveGasTip(baseFee *big.Int) (*big.Int, error) {
	if baseFee == nil {
		return tx.GasTipCap(), nil
	}
	var err error
	gasFeeCap := tx.GasFeeCap()
	if gasFeeCap.Cmp(baseFee) == -1 {
		err = ErrGasFeeCapTooLow
	}
	return math.BigMin(tx.GasTipCap(), gasFeeCap.Sub(gasFeeCap, baseFee)), err
}

// EffectiveGasTipValue is identical to EffectiveGasTip, but does not return an
// error in case the effective gasTipCap is negative
func (tx *Transaction) EffectiveGasTipValue(baseFee *big.Int) *big.Int {
	effectiveTip, _ := tx.EffectiveGasTip(baseFee)
	return effectiveTip
}

// EffectiveGasTipCmp compares the effective gasTipCap of two transactions assuming the given base fee.
func (tx *Transaction) EffectiveGasTipCmp(other *Transaction, baseFee *big.Int) int {
	if baseFee == nil {
		return tx.GasTipCapCmp(other)
	}
	return tx.EffectiveGasTipValue(baseFee).Cmp(other.EffectiveGasTipValue(baseFee))
}

// EffectiveGasTipIntCmp compares the effective gasTipCap of a transaction to the given gasTipCap.
func (tx *Transaction) EffectiveGasTipIntCmp(other *big.Int, baseFee *big.Int) int {
	if baseFee == nil {
		return tx.GasTipCapIntCmp(other)
	}
	return tx.EffectiveGasTipValue(baseFee).Cmp(other)
}

// Hash returns the transaction hash.
func (tx *Transaction) Hash() common.Hash {
	if hash := tx.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}

	var h common.Hash
	h = prefixedRlpHash(tx.Type(), tx.inner)
	tx.hash.Store(h)
	return h
}

// Size returns the true RLP encoded storage size of the transaction, either by
// encoding and returning it, or returning a previously cached value.
func (tx *Transaction) Size() common.StorageSize {
	if size := tx.size.Load(); size != nil {
		return size.(common.StorageSize)
	}
	c := writeCounter(0)
	rlp.Encode(&c, &tx.inner)
	tx.size.Store(common.StorageSize(c))
	return common.StorageSize(c)
}

// WithSignature returns a new transaction with the given signature.
// Signatures are expected in [R || S || V] format. For SignerTx with signerType
// schnorr/secp256r1/ed25519/elgamal, [R || S] is also accepted and V defaults to 0.
func (tx *Transaction) WithSignature(signer Signer, sig []byte) (*Transaction, error) {
	r, s, v, err := signer.SignatureValues(tx, sig)
	if err != nil {
		return nil, err
	}
	cpy := tx.inner.copy()
	cpy.setSignatureValues(signer.ChainID(), v, r, s)
	return &Transaction{inner: cpy, time: tx.time}, nil
}

// WithSponsorSignature returns a new sponsored transaction with the given
// sponsor-side signature.
func (tx *Transaction) WithSponsorSignature(sig []byte) (*Transaction, error) {
	stx, ok := tx.inner.(*SignerTx)
	if !ok || stx.Sponsor == (common.Address{}) {
		return nil, ErrTxTypeNotSupported
	}
	if stx.SponsorSignerType == "" {
		return nil, ErrTxTypeNotSupported
	}
	r, s, v, err := decodeSignerTxSignature(stx.SponsorSignerType, sig)
	if err != nil {
		return nil, err
	}
	cpy := stx.copy().(*SignerTx)
	cpy.SponsorV = v
	cpy.SponsorR = r
	cpy.SponsorS = s
	return &Transaction{inner: cpy, time: tx.time}, nil
}

// Transactions implements DerivableList for transactions.
type Transactions []*Transaction

// Len returns the length of s.
func (s Transactions) Len() int { return len(s) }

// EncodeIndex encodes the i'th transaction to w. Note that this does not check for errors
// because we assume that *Transaction will only ever contain valid txs that were either
// constructed by decoding or via public API in this package.
func (s Transactions) EncodeIndex(i int, w *bytes.Buffer) {
	tx := s[i]
	tx.encodeTyped(w)
}

// TxDifference returns a new set which is the difference between a and b.
func TxDifference(a, b Transactions) Transactions {
	keep := make(Transactions, 0, len(a))

	remove := make(map[common.Hash]struct{})
	for _, tx := range b {
		remove[tx.Hash()] = struct{}{}
	}

	for _, tx := range a {
		if _, ok := remove[tx.Hash()]; !ok {
			keep = append(keep, tx)
		}
	}

	return keep
}

// HashDifference returns a new set which is the difference between a and b.
func HashDifference(a, b []common.Hash) []common.Hash {
	keep := make([]common.Hash, 0, len(a))

	remove := make(map[common.Hash]struct{})
	for _, hash := range b {
		remove[hash] = struct{}{}
	}

	for _, hash := range a {
		if _, ok := remove[hash]; !ok {
			keep = append(keep, hash)
		}
	}

	return keep
}

// TxByNonce implements the sort interface to allow sorting a list of transactions
// by their nonces. This is usually only useful for sorting transactions from a
// single account, otherwise a nonce comparison doesn't make much sense.
type TxByNonce Transactions

func (s TxByNonce) Len() int           { return len(s) }
func (s TxByNonce) Less(i, j int) bool { return s[i].Nonce() < s[j].Nonce() }
func (s TxByNonce) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// TxWithMinerFee wraps a transaction with its tx price or effective miner gasTipCap
type TxWithMinerFee struct {
	tx       *Transaction
	minerFee *big.Int
}

// NewTxWithMinerFee creates a wrapped transaction, calculating the effective
// miner gasTipCap if a base fee is provided.
// Returns error in case of a negative effective miner gasTipCap.
func NewTxWithMinerFee(tx *Transaction, baseFee *big.Int) (*TxWithMinerFee, error) {
	minerFee, err := tx.EffectiveGasTip(baseFee)
	if err != nil {
		return nil, err
	}
	return &TxWithMinerFee{
		tx:       tx,
		minerFee: minerFee,
	}, nil
}

// TxByPriceAndTime implements both the sort and the heap interface, making it useful
// for all at once sorting as well as individually adding and removing elements.
type TxByPriceAndTime []*TxWithMinerFee

func (s TxByPriceAndTime) Len() int { return len(s) }
func (s TxByPriceAndTime) Less(i, j int) bool {
	// If the prices are equal, use the time the transaction was first seen for
	// deterministic sorting
	cmp := s[i].minerFee.Cmp(s[j].minerFee)
	if cmp == 0 {
		return s[i].tx.time.Before(s[j].tx.time)
	}
	return cmp > 0
}
func (s TxByPriceAndTime) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s *TxByPriceAndTime) Push(x interface{}) {
	*s = append(*s, x.(*TxWithMinerFee))
}

func (s *TxByPriceAndTime) Pop() interface{} {
	old := *s
	n := len(old)
	x := old[n-1]
	*s = old[0 : n-1]
	return x
}

// txSenderHint returns the signer-derived sender when available and falls back
// to the sender cache populated by ResolveSender for non-secp256k1 signer types.
func txSenderHint(signer Signer, tx *Transaction) common.Address {
	if from, err := Sender(signer, tx); err == nil {
		return from
	}
	// Non-secp signer types still carry an explicit From field on SignerTx.
	// Use it as the stable account key for heap grouping even when Sender()
	// cannot recover the signer locally.
	if from, ok := tx.SignerFrom(); ok {
		return from
	}
	// Check sender cache populated by ResolveSender for non-secp256k1 types.
	if sc := tx.from.Load(); sc != nil {
		if sigCache, ok := sc.(sigCache); ok {
			return sigCache.from
		}
	}
	return common.Address{}
}

// TransactionsByPriceAndNonce represents a set of transactions that can return
// transactions in a profit-maximizing sorted order, while supporting removing
// entire batches of transactions for non-executable accounts.
type TransactionsByPriceAndNonce struct {
	txs     map[common.Address]Transactions // Per account nonce-sorted list of transactions
	heads   TxByPriceAndTime                // Next transaction for each unique account (price heap)
	signer  Signer                          // Signer for the set of transactions
	baseFee *big.Int                        // Current base fee
}

// NewTransactionsByPriceAndNonce creates a transaction set that can retrieve
// price sorted transactions in a nonce-honouring way.
//
// Note, the input map is reowned so the caller should not interact any more with
// if after providing it to the constructor.
func NewTransactionsByPriceAndNonce(signer Signer, txs map[common.Address]Transactions, baseFee *big.Int) *TransactionsByPriceAndNonce {
	// Initialize a price and received time based heap with the head transactions
	heads := make(TxByPriceAndTime, 0, len(txs))
	for from, accTxs := range txs {
		acc := txSenderHint(signer, accTxs[0])
		wrapped, err := NewTxWithMinerFee(accTxs[0], baseFee)
		// Remove transaction if sender is unknown/mismatched, or if wrapping fails.
		if acc == (common.Address{}) || acc != from || err != nil {
			delete(txs, from)
			continue
		}
		heads = append(heads, wrapped)
		txs[from] = accTxs[1:]
	}
	heap.Init(&heads)

	// Assemble and return the transaction set
	return &TransactionsByPriceAndNonce{
		txs:     txs,
		heads:   heads,
		signer:  signer,
		baseFee: baseFee,
	}
}

// Peek returns the next transaction by price.
func (t *TransactionsByPriceAndNonce) Peek() *Transaction {
	if len(t.heads) == 0 {
		return nil
	}
	return t.heads[0].tx
}

// Shift replaces the current best head with the next one from the same account.
func (t *TransactionsByPriceAndNonce) Shift() {
	acc := txSenderHint(t.signer, t.heads[0].tx)
	if acc == (common.Address{}) {
		heap.Pop(&t.heads)
		return
	}
	if txs, ok := t.txs[acc]; ok && len(txs) > 0 {
		if wrapped, err := NewTxWithMinerFee(txs[0], t.baseFee); err == nil {
			t.heads[0], t.txs[acc] = wrapped, txs[1:]
			heap.Fix(&t.heads, 0)
			return
		}
	}
	heap.Pop(&t.heads)
}

// Pop removes the best transaction, *not* replacing it with the next one from
// the same account. This should be used when a transaction cannot be executed
// and hence all subsequent ones should be discarded from the same account.
func (t *TransactionsByPriceAndNonce) Pop() {
	heap.Pop(&t.heads)
}

// Message is a fully derived transaction and implements core.Message
//
// NOTE: In a future PR this will be removed.
type Message struct {
	to                *common.Address
	from              common.Address
	sponsor           common.Address
	nonce             uint64
	sponsorNonce      uint64
	sponsorExpiry     uint64
	sponsorPolicyHash common.Hash
	amount            *big.Int
	gasLimit          uint64
	txPrice           *big.Int
	gasFeeCap         *big.Int
	gasTipCap         *big.Int
	data              []byte
	accessList        AccessList
	terminalClass     uint8
	trustTier         uint8
	isFake            bool
	txType            byte            // SignerTxType (default 0) or PrivTransferTxType/ShieldTxType/UnshieldTxType
	privTransferTx    *PrivTransferTx // non-nil for PrivTransferTxType
	shieldTx          *ShieldTx       // non-nil for ShieldTxType
	unshieldTx        *UnshieldTx     // non-nil for UnshieldTxType
}

func NewMessage(from common.Address, to *common.Address, nonce uint64, amount *big.Int, gasLimit uint64, txPrice, gasFeeCap, gasTipCap *big.Int, data []byte, accessList AccessList, isFake bool) Message {
	return Message{
		from:       from,
		to:         to,
		nonce:      nonce,
		amount:     amount,
		gasLimit:   gasLimit,
		txPrice:    txPrice,
		gasFeeCap:  gasFeeCap,
		gasTipCap:  gasTipCap,
		data:       data,
		accessList: accessList,
		isFake:     isFake,
	}
}

func (m Message) WithSponsor(sponsor common.Address, sponsorNonce uint64, sponsorExpiry uint64, sponsorPolicyHash common.Hash) Message {
	m.sponsor = sponsor
	m.sponsorNonce = sponsorNonce
	m.sponsorExpiry = sponsorExpiry
	m.sponsorPolicyHash = sponsorPolicyHash
	return m
}

// AsMessage returns the transaction as a core.Message.
func (tx *Transaction) AsMessage(s Signer, baseFee *big.Int) (Message, error) {
	msg := Message{
		nonce:      tx.Nonce(),
		gasLimit:   tx.Gas(),
		txPrice:    new(big.Int).Set(tx.TxPrice()),
		gasFeeCap:  new(big.Int).Set(tx.GasFeeCap()),
		gasTipCap:  new(big.Int).Set(tx.GasTipCap()),
		to:         tx.To(),
		amount:     tx.Value(),
		data:       tx.Data(),
		accessList: tx.AccessList(),
		isFake:     false,
		txType:     tx.Type(),
	}
	if ptx, ok := tx.inner.(*PrivTransferTx); ok {
		msg.privTransferTx = ptx
	}
	if stx, ok := tx.inner.(*ShieldTx); ok {
		msg.shieldTx = stx
	}
	if utx, ok := tx.inner.(*UnshieldTx); ok {
		msg.unshieldTx = utx
	}
	if sponsor, ok := tx.SponsorFrom(); ok {
		msg.sponsor = sponsor
	}
	if sponsorNonce, ok := tx.SponsorNonce(); ok {
		msg.sponsorNonce = sponsorNonce
	}
	if sponsorExpiry, ok := tx.SponsorExpiry(); ok {
		msg.sponsorExpiry = sponsorExpiry
	}
	if sponsorPolicyHash, ok := tx.SponsorPolicyHash(); ok {
		msg.sponsorPolicyHash = sponsorPolicyHash
	}
	if tc, ok := tx.TerminalClass(); ok {
		msg.terminalClass = tc
	}
	if tt, ok := tx.TrustTier(); ok {
		msg.trustTier = tt
	}
	// If baseFee provided, set txPrice to effectiveTxPrice.
	if baseFee != nil {
		msg.txPrice = math.BigMin(msg.txPrice.Add(msg.gasTipCap, baseFee), msg.gasFeeCap)
	}
	var err error
	msg.from, err = Sender(s, tx)
	if err == nil && tx.IsSponsored() {
		sponsor, _ := tx.SponsorFrom()
		sponsorNonce, _ := tx.SponsorNonce()
		sponsorExpiry, _ := tx.SponsorExpiry()
		sponsorPolicyHash, _ := tx.SponsorPolicyHash()
		msg = msg.WithSponsor(sponsor, sponsorNonce, sponsorExpiry, sponsorPolicyHash)
	}
	return msg, err
}

func (m Message) From() common.Address           { return m.from }
func (m Message) Sponsor() common.Address        { return m.sponsor }
func (m Message) To() *common.Address            { return m.to }
func (m Message) TxPrice() *big.Int              { return m.txPrice }
func (m Message) GasFeeCap() *big.Int            { return m.gasFeeCap }
func (m Message) GasTipCap() *big.Int            { return m.gasTipCap }
func (m Message) Value() *big.Int                { return m.amount }
func (m Message) Gas() uint64                    { return m.gasLimit }
func (m Message) Nonce() uint64                  { return m.nonce }
func (m Message) SponsorNonce() uint64           { return m.sponsorNonce }
func (m Message) SponsorExpiry() uint64          { return m.sponsorExpiry }
func (m Message) SponsorPolicyHash() common.Hash { return m.sponsorPolicyHash }
func (m Message) IsSponsored() bool              { return m.sponsor != (common.Address{}) }
func (m Message) Data() []byte                   { return m.data }
func (m Message) AccessList() AccessList         { return m.accessList }
func (m Message) IsFake() bool                   { return m.isFake }
func (m Message) Type() byte                     { return m.txType }
func (m Message) TerminalClass() uint8           { return m.terminalClass }
func (m Message) TrustTier() uint8               { return m.trustTier }

// WithTerminalContext returns a copy of the message with terminal class and trust tier set.
func (m Message) WithTerminalContext(terminalClass, trustTier uint8) Message {
	m.terminalClass = terminalClass
	m.trustTier = trustTier
	return m
}

// WithTxType returns a copy of the message with the given transaction type set.
func (m Message) WithTxType(txType byte) Message {
	m.txType = txType
	return m
}

// WithPrivTransferTx returns a copy of the message with the PrivTransferTx set.
func (m Message) WithPrivTransferTx(ptx *PrivTransferTx) Message {
	m.privTransferTx = ptx
	m.txType = PrivTransferTxType
	return m
}

// PrivTransferInner returns the underlying PrivTransferTx if this message was
// derived from a PrivTransferTxType transaction, or nil otherwise.
func (m Message) PrivTransferInner() *PrivTransferTx { return m.privTransferTx }

// WithShieldTx returns a copy of the message with the ShieldTx set.
func (m Message) WithShieldTx(stx *ShieldTx) Message {
	m.shieldTx = stx
	m.txType = ShieldTxType
	return m
}

// ShieldInner returns the underlying ShieldTx if this message was
// derived from a ShieldTxType transaction, or nil otherwise.
func (m Message) ShieldInner() *ShieldTx { return m.shieldTx }

// WithUnshieldTx returns a copy of the message with the UnshieldTx set.
func (m Message) WithUnshieldTx(utx *UnshieldTx) Message {
	m.unshieldTx = utx
	m.txType = UnshieldTxType
	return m
}

// UnshieldInner returns the underlying UnshieldTx if this message was
// derived from an UnshieldTxType transaction, or nil otherwise.
func (m Message) UnshieldInner() *UnshieldTx { return m.unshieldTx }

// copyAddressPtr copies an address.
func copyAddressPtr(a *common.Address) *common.Address {
	if a == nil {
		return nil
	}
	cpy := *a
	return &cpy
}
