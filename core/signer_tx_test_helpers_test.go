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
	gasPrice *big.Int,
	data []byte,
) (*types.Transaction, error) {
	if amount == nil {
		amount = new(big.Int)
	}
	if gasPrice == nil {
		gasPrice = new(big.Int)
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
