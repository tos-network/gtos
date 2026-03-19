package types

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/rlp"
)

// UnshieldTx is a private-to-public withdrawal: deducts Amount from the
// sender's encrypted balance and credits it to the recipient's public balance.
//
// Pubkey identifies the sender (signs the tx, owns the encrypted balance).
// Recipient is the address that receives the public TOS.
// For self-directed withdrawals, Recipient == DerivedAddress(Pubkey).
// Fee (in UNO base units) is deducted from the recipient's public balance after
// crediting Amount — the net credit is (Amount − Fee) × UNOUnit Wei.
type UnshieldTx struct {
	ChainID   *big.Int
	PrivNonce uint64
	UnoFee    uint64 // fee in UNO base units (1 = 0.01 UNO = 10^16 Wei)

	Pubkey    [32]byte       // sender ElGamal compressed public key
	Recipient common.Address // recipient of public TOS
	UnoAmount uint64         // withdrawal amount in UNO base units

	// New encrypted balance commitment after withdrawal
	SourceCommitment [32]byte

	// Proofs
	CommitmentEqProof [192]byte // proves SourceCommitment matches computed balance
	RangeProof        [672]byte // proves committed amount in [0, 2^64)

	// Auditor fields (Phase 3 selective disclosure)
	AuditorHandle    [32]byte // r·PK_audit (zero if no auditor configured)
	AuditorDLEQProof []byte   // DLEQ proof for same-randomness (nil if no auditor)

	// ElGamal Schnorr signature (by sender)
	S [32]byte
	E [32]byte
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *UnshieldTx) copy() TxData {
	cpy := &UnshieldTx{
		PrivNonce:         tx.PrivNonce,
		UnoFee:            tx.UnoFee,
		Pubkey:            tx.Pubkey,
		Recipient:         tx.Recipient,
		UnoAmount:         tx.UnoAmount,
		SourceCommitment:  tx.SourceCommitment,
		CommitmentEqProof: tx.CommitmentEqProof,
		RangeProof:        tx.RangeProof,
		AuditorHandle:     tx.AuditorHandle,
		S:                 tx.S,
		E:                 tx.E,
		ChainID:           new(big.Int),
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	cpy.AuditorDLEQProof = common.CopyBytes(tx.AuditorDLEQProof)
	return cpy
}

// accessors for TxData interface.
func (tx *UnshieldTx) txType() byte           { return UnshieldTxType }
func (tx *UnshieldTx) chainID() *big.Int       { return tx.ChainID }
func (tx *UnshieldTx) gas() uint64             { return 0 }
func (tx *UnshieldTx) txPrice() *big.Int       { return new(big.Int).SetUint64(tx.UnoFee) }
func (tx *UnshieldTx) value() *big.Int         { return big.NewInt(0) }
func (tx *UnshieldTx) nonce() uint64           { return tx.PrivNonce }
func (tx *UnshieldTx) data() []byte            { return nil }
func (tx *UnshieldTx) accessList() AccessList  { return nil }
func (tx *UnshieldTx) gasTipCap() *big.Int     { return big.NewInt(0) }
func (tx *UnshieldTx) gasFeeCap() *big.Int     { return big.NewInt(0) }

func (tx *UnshieldTx) to() *common.Address {
	r := tx.Recipient
	return &r
}

func (tx *UnshieldTx) rawSignatureValues() (v, r, s *big.Int) {
	return new(big.Int), new(big.Int).SetBytes(tx.S[:]), new(big.Int).SetBytes(tx.E[:])
}

func (tx *UnshieldTx) setSignatureValues(chainID, v, r, s *big.Int) {
	copy(tx.S[:], r.Bytes())
	copy(tx.E[:], s.Bytes())
}

// DerivedAddress derives the sender address from Pubkey.
func (tx *UnshieldTx) DerivedAddress() common.Address {
	return common.BytesToAddress(crypto.Keccak256(tx.Pubkey[:]))
}

// SigningHash returns the hash that the ElGamal Schnorr signature (S, E) signs.
// It covers all transaction fields except S and E themselves.
func (tx *UnshieldTx) SigningHash() common.Hash {
	sha := crypto.NewKeccakState()
	sha.Write([]byte{UnshieldTxType})
	rlp.Encode(sha, []interface{}{
		tx.ChainID,
		tx.PrivNonce,
		tx.UnoFee,
		tx.Pubkey,
		tx.Recipient,
		tx.UnoAmount,
		tx.SourceCommitment,
		tx.CommitmentEqProof,
		tx.RangeProof,
		tx.AuditorHandle,
		tx.AuditorDLEQProof,
	})
	var h common.Hash
	sha.Read(h[:])
	return h
}
