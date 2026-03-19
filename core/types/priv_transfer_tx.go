package types

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/rlp"
)

// PrivTransferTx is a confidential transfer between two ElGamal accounts.
// From and To are compressed ElGamal public keys (Ristretto255), NOT hashed addresses.
// Signature is ElGamal Ristretto-Schnorr (S, E) — no SignerType field.
type PrivTransferTx struct {
	ChainID     *big.Int
	PrivNonce   uint64
	UnoFee      uint64 // fee in UNO base units (1 = 0.01 UNO = 10^16 Wei)
	UnoFeeLimit uint64 // max fee in UNO base units sender willing to pay

	From [32]byte // sender ElGamal compressed public key
	To   [32]byte // receiver ElGamal compressed public key

	// Transfer ciphertext (3 fields)
	Commitment     [32]byte // Pedersen commitment to transfer amount
	SenderHandle   [32]byte // decrypt handle under sender key
	ReceiverHandle [32]byte // decrypt handle under receiver key

	// Source commitment
	SourceCommitment [32]byte // sender's new balance commitment

	// Proofs (separated)
	CtValidityProof   []byte // ~160 bytes
	CommitmentEqProof []byte // ~192 bytes
	RangeProof        []byte // aggregated transfer range proof; legacy concatenated proofs are still accepted by verifiers

	// Auditor fields (Phase 3 selective disclosure)
	AuditorHandle    [32]byte // r·PK_audit (zero if no auditor configured)
	AuditorDLEQProof []byte   // DLEQ proof for same-randomness (nil if no auditor)

	// Encrypted memo
	EncryptedMemo      []byte // ChaCha20Poly1305 ciphertext
	MemoSenderHandle   [32]byte
	MemoReceiverHandle [32]byte

	// ElGamal Schnorr signature
	S [32]byte
	E [32]byte
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *PrivTransferTx) copy() TxData {
	cpy := &PrivTransferTx{
		PrivNonce:          tx.PrivNonce,
		UnoFee:             tx.UnoFee,
		UnoFeeLimit:        tx.UnoFeeLimit,
		From:               tx.From,
		To:                 tx.To,
		Commitment:         tx.Commitment,
		SenderHandle:       tx.SenderHandle,
		ReceiverHandle:     tx.ReceiverHandle,
		SourceCommitment:   tx.SourceCommitment,
		AuditorHandle:      tx.AuditorHandle,
		MemoSenderHandle:   tx.MemoSenderHandle,
		MemoReceiverHandle: tx.MemoReceiverHandle,
		S:                  tx.S,
		E:                  tx.E,
		ChainID:            new(big.Int),
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	cpy.CtValidityProof = common.CopyBytes(tx.CtValidityProof)
	cpy.CommitmentEqProof = common.CopyBytes(tx.CommitmentEqProof)
	cpy.RangeProof = common.CopyBytes(tx.RangeProof)
	cpy.AuditorDLEQProof = common.CopyBytes(tx.AuditorDLEQProof)
	cpy.EncryptedMemo = common.CopyBytes(tx.EncryptedMemo)
	return cpy
}

// accessors for TxData interface.
func (tx *PrivTransferTx) txType() byte           { return PrivTransferTxType }
func (tx *PrivTransferTx) chainID() *big.Int      { return tx.ChainID }
func (tx *PrivTransferTx) gas() uint64            { return 0 }
func (tx *PrivTransferTx) txPrice() *big.Int      { return new(big.Int).SetUint64(tx.UnoFee) }
func (tx *PrivTransferTx) value() *big.Int        { return big.NewInt(0) }
func (tx *PrivTransferTx) nonce() uint64          { return tx.PrivNonce }
func (tx *PrivTransferTx) data() []byte           { return nil }
func (tx *PrivTransferTx) accessList() AccessList { return nil }
func (tx *PrivTransferTx) gasTipCap() *big.Int    { return big.NewInt(0) }
func (tx *PrivTransferTx) gasFeeCap() *big.Int    { return big.NewInt(0) }

func (tx *PrivTransferTx) to() *common.Address {
	addr := common.BytesToAddress(crypto.Keccak256(tx.To[:]))
	return &addr
}

func (tx *PrivTransferTx) rawSignatureValues() (v, r, s *big.Int) {
	return new(big.Int), new(big.Int).SetBytes(tx.S[:]), new(big.Int).SetBytes(tx.E[:])
}

func (tx *PrivTransferTx) setSignatureValues(chainID, v, r, s *big.Int) {
	copy(tx.S[:], r.Bytes())
	copy(tx.E[:], s.Bytes())
}

// Helper methods.

// FromPubkey returns the sender's ElGamal compressed public key.
func (tx *PrivTransferTx) FromPubkey() [32]byte { return tx.From }

// ToPubkey returns the receiver's ElGamal compressed public key.
func (tx *PrivTransferTx) ToPubkey() [32]byte { return tx.To }

// FromAddress derives an Ethereum-style address from the sender's ElGamal public key.
func (tx *PrivTransferTx) FromAddress() common.Address {
	return common.BytesToAddress(crypto.Keccak256(tx.From[:]))
}

// ToAddress derives an Ethereum-style address from the receiver's ElGamal public key.
func (tx *PrivTransferTx) ToAddress() common.Address {
	return common.BytesToAddress(crypto.Keccak256(tx.To[:]))
}

// SigningHash returns the hash that the ElGamal Schnorr signature (S, E) signs.
// It covers all transaction fields except S and E themselves.
func (tx *PrivTransferTx) SigningHash() common.Hash {
	sha := crypto.NewKeccakState()
	sha.Write([]byte{PrivTransferTxType})
	rlp.Encode(sha, []interface{}{
		tx.ChainID,
		tx.PrivNonce,
		tx.UnoFee,
		tx.UnoFeeLimit,
		tx.From,
		tx.To,
		tx.Commitment,
		tx.SenderHandle,
		tx.ReceiverHandle,
		tx.SourceCommitment,
		tx.CtValidityProof,
		tx.CommitmentEqProof,
		tx.RangeProof,
		tx.AuditorHandle,
		tx.AuditorDLEQProof,
		tx.EncryptedMemo,
		tx.MemoSenderHandle,
		tx.MemoReceiverHandle,
	})
	var h common.Hash
	sha.Read(h[:])
	return h
}
