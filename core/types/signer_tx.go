package types

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/params"
)

// SignerTx carries explicit signer metadata in the envelope.
type SignerTx struct {
	ChainID    *big.Int
	Nonce      uint64
	Gas        uint64
	To         *common.Address `rlp:"nil"` // nil means setCode path
	Value      *big.Int
	Data       []byte
	AccessList AccessList

	From       common.Address
	SignerType string

	Sponsor           common.Address
	SponsorSignerType string
	SponsorNonce      uint64
	SponsorExpiry     uint64
	SponsorPolicyHash common.Hash

	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`

	SponsorV *big.Int `json:"sponsorV,omitempty"`
	SponsorR *big.Int `json:"sponsorR,omitempty"`
	SponsorS *big.Int `json:"sponsorS,omitempty"`

	TerminalClass uint8 `json:"terminalClass" rlp:"optional"`
	TrustTier     uint8 `json:"trustTier"     rlp:"optional"`
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *SignerTx) copy() TxData {
	cpy := &SignerTx{
		Nonce:             tx.Nonce,
		To:                copyAddressPtr(tx.To),
		Data:              common.CopyBytes(tx.Data),
		Gas:               tx.Gas,
		AccessList:        make(AccessList, len(tx.AccessList)),
		From:              tx.From,
		SignerType:        tx.SignerType,
		Sponsor:           tx.Sponsor,
		SponsorSignerType: tx.SponsorSignerType,
		SponsorNonce:      tx.SponsorNonce,
		SponsorExpiry:     tx.SponsorExpiry,
		SponsorPolicyHash: tx.SponsorPolicyHash,
		TerminalClass:     tx.TerminalClass,
		TrustTier:         tx.TrustTier,
		Value:             new(big.Int),
		ChainID:           new(big.Int),
		V:                 new(big.Int),
		R:                 new(big.Int),
		S:                 new(big.Int),
		SponsorV:          new(big.Int),
		SponsorR:          new(big.Int),
		SponsorS:          new(big.Int),
	}
	copy(cpy.AccessList, tx.AccessList)
	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.V != nil {
		cpy.V.Set(tx.V)
	}
	if tx.R != nil {
		cpy.R.Set(tx.R)
	}
	if tx.S != nil {
		cpy.S.Set(tx.S)
	}
	if tx.SponsorV != nil {
		cpy.SponsorV.Set(tx.SponsorV)
	}
	if tx.SponsorR != nil {
		cpy.SponsorR.Set(tx.SponsorR)
	}
	if tx.SponsorS != nil {
		cpy.SponsorS.Set(tx.SponsorS)
	}
	return cpy
}

// accessors for innerTx.
func (tx *SignerTx) txType() byte           { return SignerTxType }
func (tx *SignerTx) chainID() *big.Int      { return tx.ChainID }
func (tx *SignerTx) accessList() AccessList { return tx.AccessList }
func (tx *SignerTx) data() []byte           { return tx.Data }
func (tx *SignerTx) gas() uint64            { return tx.Gas }
func (tx *SignerTx) txPrice() *big.Int      { return params.TxPrice() }
func (tx *SignerTx) gasTipCap() *big.Int    { return params.TxPrice() }
func (tx *SignerTx) gasFeeCap() *big.Int    { return params.TxPrice() }
func (tx *SignerTx) value() *big.Int        { return tx.Value }
func (tx *SignerTx) nonce() uint64          { return tx.Nonce }
func (tx *SignerTx) to() *common.Address    { return tx.To }

func (tx *SignerTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *SignerTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID, tx.V, tx.R, tx.S = chainID, v, r, s
}
