package types

import (
	"math/big"

	"github.com/tos-network/gtos/common"
)

// NewTransaction creates an unsigned SignerTx transaction.
// Deprecated: use NewTx instead.
func NewTransaction(nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, _ *big.Int, data []byte) *Transaction {
	return NewTx(&SignerTx{
		ChainID:    new(big.Int),
		Nonce:      nonce,
		To:         &to,
		Value:      amount,
		Gas:        gasLimit,
		Data:       data,
		From:       common.Address{},
		SignerType: "secp256k1",
		V:          new(big.Int),
		R:          new(big.Int),
		S:          new(big.Int),
	})
}

// NewContractCreation creates an unsigned SignerTx contract-creation transaction.
// Deprecated: use NewTx instead.
func NewContractCreation(nonce uint64, amount *big.Int, gasLimit uint64, _ *big.Int, data []byte) *Transaction {
	return NewTx(&SignerTx{
		ChainID:    new(big.Int),
		Nonce:      nonce,
		Value:      amount,
		Gas:        gasLimit,
		Data:       data,
		From:       common.Address{},
		SignerType: "secp256k1",
		V:          new(big.Int),
		R:          new(big.Int),
		S:          new(big.Int),
	})
}
