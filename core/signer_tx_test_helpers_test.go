package core

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
)

func signTestSignerTx(
	signer types.Signer,
	key *ecdsa.PrivateKey,
	nonce uint64,
	to common.Address,
	amount *big.Int,
	gasLimit uint64,
	txPrice *big.Int,
	data []byte,
) (*types.Transaction, error) {
	if amount == nil {
		amount = new(big.Int)
	}
	if txPrice == nil {
		txPrice = new(big.Int)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	tx := types.NewTx(&types.SignerTx{
		ChainID:    signer.ChainID(),
		Nonce:      nonce,
		To:         &to,
		Value:      new(big.Int).Set(amount),
		Gas:        gasLimit,
		Data:       common.CopyBytes(data),
		From:       from,
		SignerType: accountsigner.SignerTypeSecp256k1,
	})
	return types.SignTx(tx, signer, key)
}

func signSponsoredTestSignerTx(
	signer types.Signer,
	key *ecdsa.PrivateKey,
	sponsorKey *ecdsa.PrivateKey,
	nonce uint64,
	sponsorNonce uint64,
	sponsorExpiry uint64,
	to common.Address,
	amount *big.Int,
	gasLimit uint64,
	txPrice *big.Int,
	data []byte,
) (*types.Transaction, error) {
	if amount == nil {
		amount = new(big.Int)
	}
	if txPrice == nil {
		txPrice = new(big.Int)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	sponsor := crypto.PubkeyToAddress(sponsorKey.PublicKey)
	tx := types.NewTx(&types.SignerTx{
		ChainID:           signer.ChainID(),
		Nonce:             nonce,
		To:                &to,
		Value:             new(big.Int).Set(amount),
		Gas:               gasLimit,
		Data:              common.CopyBytes(data),
		From:              from,
		SignerType:        accountsigner.SignerTypeSecp256k1,
		Sponsor:           sponsor,
		SponsorSignerType: accountsigner.SignerTypeSecp256k1,
		SponsorNonce:      sponsorNonce,
		SponsorExpiry:     sponsorExpiry,
	})
	signed, err := types.SignTx(tx, signer, key)
	if err != nil {
		return nil, err
	}
	hash := signer.Hash(signed)
	sponsorSig, err := crypto.Sign(hash[:], sponsorKey)
	if err != nil {
		return nil, err
	}
	return signed.WithSponsorSignature(sponsorSig)
}
