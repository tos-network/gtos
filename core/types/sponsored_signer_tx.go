package types

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/params"
)

// SponsoredSignerTx carries explicit requester signer metadata and a second
// sponsor witness that pays native protocol gas.
type SponsoredSignerTx struct {
	ChainID    *big.Int
	Nonce      uint64
	Gas        uint64
	To         *common.Address `rlp:"nil"`
	Value      *big.Int
	Data       []byte
	AccessList AccessList

	From       common.Address
	SignerType string

	Sponsor           common.Address
	SponsorNonce      uint64
	SponsorExpiry     uint64
	SponsorPolicyHash common.Hash

	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`

	SponsorV *big.Int `json:"sponsorV" gencodec:"required"`
	SponsorR *big.Int `json:"sponsorR" gencodec:"required"`
	SponsorS *big.Int `json:"sponsorS" gencodec:"required"`
}

func (tx *SponsoredSignerTx) copy() TxData {
	cpy := &SponsoredSignerTx{
		Nonce:             tx.Nonce,
		To:                copyAddressPtr(tx.To),
		Data:              common.CopyBytes(tx.Data),
		Gas:               tx.Gas,
		AccessList:        make(AccessList, len(tx.AccessList)),
		From:              tx.From,
		SignerType:        tx.SignerType,
		Sponsor:           tx.Sponsor,
		SponsorNonce:      tx.SponsorNonce,
		SponsorExpiry:     tx.SponsorExpiry,
		SponsorPolicyHash: tx.SponsorPolicyHash,
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

func (tx *SponsoredSignerTx) txType() byte           { return SponsoredSignerTxType }
func (tx *SponsoredSignerTx) chainID() *big.Int      { return tx.ChainID }
func (tx *SponsoredSignerTx) accessList() AccessList { return tx.AccessList }
func (tx *SponsoredSignerTx) data() []byte           { return tx.Data }
func (tx *SponsoredSignerTx) gas() uint64            { return tx.Gas }
func (tx *SponsoredSignerTx) txPrice() *big.Int      { return params.TxPrice() }
func (tx *SponsoredSignerTx) gasTipCap() *big.Int    { return params.TxPrice() }
func (tx *SponsoredSignerTx) gasFeeCap() *big.Int    { return params.TxPrice() }
func (tx *SponsoredSignerTx) value() *big.Int        { return tx.Value }
func (tx *SponsoredSignerTx) nonce() uint64          { return tx.Nonce }
func (tx *SponsoredSignerTx) to() *common.Address    { return tx.To }

func (tx *SponsoredSignerTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *SponsoredSignerTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID, tx.V, tx.R, tx.S = chainID, v, r, s
}
