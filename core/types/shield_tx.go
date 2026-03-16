package types

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/rlp"
)

// ShieldTx is a public-to-private deposit: deducts Amount+Fee from the
// sender's public balance and adds the equivalent encrypted amount to the
// recipient's private (ElGamal) balance.
//
// Pubkey identifies the sender (signs the tx, pays from public balance).
// Recipient is the ElGamal pubkey whose encrypted balance receives the deposit.
// For self-directed deposits, Recipient == Pubkey.
type ShieldTx struct {
	ChainID   *big.Int
	PrivNonce uint64
	UnoFee    uint64 // fee in UNO base units (1 = 0.01 UNO = 10^16 Wei)

	Pubkey    [32]byte // sender ElGamal compressed public key
	Recipient [32]byte // recipient ElGamal compressed public key
	UnoAmount uint64   // deposit amount in UNO base units

	// Encrypted form of Amount under Recipient's key
	Commitment [32]byte // Pedersen commitment to Amount
	Handle     [32]byte // decrypt handle under Recipient's key

	// Proofs
	ShieldProof [96]byte  // proves (Commitment, Handle) is valid encryption of Amount under Recipient
	RangeProof  [672]byte // proves committed amount in [0, 2^64)

	// ElGamal Schnorr signature (by sender)
	S [32]byte
	E [32]byte
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *ShieldTx) copy() TxData {
	cpy := &ShieldTx{
		PrivNonce:   tx.PrivNonce,
		UnoFee:      tx.UnoFee,
		Pubkey:      tx.Pubkey,
		Recipient:   tx.Recipient,
		UnoAmount:   tx.UnoAmount,
		Commitment:  tx.Commitment,
		Handle:      tx.Handle,
		ShieldProof: tx.ShieldProof,
		RangeProof:  tx.RangeProof,
		S:           tx.S,
		E:           tx.E,
		ChainID:     new(big.Int),
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	return cpy
}

// accessors for TxData interface.
func (tx *ShieldTx) txType() byte           { return ShieldTxType }
func (tx *ShieldTx) chainID() *big.Int       { return tx.ChainID }
func (tx *ShieldTx) gas() uint64             { return 0 }
func (tx *ShieldTx) txPrice() *big.Int       { return new(big.Int).SetUint64(tx.UnoFee) }
func (tx *ShieldTx) value() *big.Int         { return big.NewInt(0) }
func (tx *ShieldTx) nonce() uint64           { return tx.PrivNonce }
func (tx *ShieldTx) data() []byte            { return nil }
func (tx *ShieldTx) accessList() AccessList  { return nil }
func (tx *ShieldTx) gasTipCap() *big.Int     { return big.NewInt(0) }
func (tx *ShieldTx) gasFeeCap() *big.Int     { return big.NewInt(0) }

func (tx *ShieldTx) to() *common.Address {
	addr := tx.RecipientAddress()
	return &addr
}

func (tx *ShieldTx) rawSignatureValues() (v, r, s *big.Int) {
	return new(big.Int), new(big.Int).SetBytes(tx.S[:]), new(big.Int).SetBytes(tx.E[:])
}

func (tx *ShieldTx) setSignatureValues(chainID, v, r, s *big.Int) {
	copy(tx.S[:], r.Bytes())
	copy(tx.E[:], s.Bytes())
}

// DerivedAddress derives the sender address from Pubkey.
func (tx *ShieldTx) DerivedAddress() common.Address {
	return common.BytesToAddress(crypto.Keccak256(tx.Pubkey[:]))
}

// RecipientAddress derives the recipient address from the Recipient pubkey.
func (tx *ShieldTx) RecipientAddress() common.Address {
	return common.BytesToAddress(crypto.Keccak256(tx.Recipient[:]))
}

// SigningHash returns the hash that the ElGamal Schnorr signature (S, E) signs.
// It covers all transaction fields except S and E themselves.
func (tx *ShieldTx) SigningHash() common.Hash {
	sha := crypto.NewKeccakState()
	sha.Write([]byte{ShieldTxType})
	rlp.Encode(sha, []interface{}{
		tx.ChainID,
		tx.PrivNonce,
		tx.UnoFee,
		tx.Pubkey,
		tx.Recipient,
		tx.UnoAmount,
		tx.Commitment,
		tx.Handle,
		tx.ShieldProof,
		tx.RangeProof,
	})
	var h common.Hash
	sha.Read(h[:])
	return h
}
