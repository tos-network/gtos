package tos

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	crand "crypto/rand"
	"math/big"
	"strings"
	"testing"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
	"github.com/tos-network/gtos/trie"
)

func stateAccessorTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to load sender key: %v", err)
	}
	return key
}

func TestStateAtTransactionUsesPreBlockSignerSnapshot(t *testing.T) {
	config := &params.ChainConfig{
		ChainID: big.NewInt(1),
		DPoS:    &params.DPoSConfig{PeriodMs: 3000, Epoch: 200, MaxValidators: 21},
	}
	chainSigner := types.LatestSigner(config)
	fromKey := stateAccessorTestKey(t)
	from := crypto.PubkeyToAddress(fromKey.PublicKey)
	to := common.HexToAddress("0x74c5f09f80cc62940a4f392f067a68b40696c06bf8e31f973efee01156caea5f")

	edPub, edPriv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	setSignerPayload, err := sysaction.MakeSysAction(sysaction.ActionAccountSetSigner, accountsigner.SetSignerPayload{
		SignerType:  accountsigner.SignerTypeEd25519,
		SignerValue: hexutil.Encode(edPub),
	})
	if err != nil {
		t.Fatalf("failed to encode setSigner payload: %v", err)
	}

	systemActionTo := params.SystemActionAddress
	txSetSignerUnsigned := types.NewTx(&types.SignerTx{
		ChainID:    chainSigner.ChainID(),
		Nonce:      0,
		To:         &systemActionTo,
		Value:      big.NewInt(0),
		Gas:        500_000,
		Data:       setSignerPayload,
		From:       from,
		SignerType: accountsigner.SignerTypeSecp256k1,
	})
	txSetSigner, err := types.SignTx(txSetSignerUnsigned, chainSigner, fromKey)
	if err != nil {
		t.Fatalf("failed to sign setSigner tx: %v", err)
	}

	txEdUnsigned := types.NewTx(&types.SignerTx{
		ChainID:    chainSigner.ChainID(),
		Nonce:      1,
		To:         &to,
		Value:      big.NewInt(1),
		Gas:        params.TxGas,
		From:       from,
		SignerType: accountsigner.SignerTypeEd25519,
	})
	hash := chainSigner.Hash(txEdUnsigned)
	edSig := ed25519.Sign(edPriv, hash[:])
	txEd := types.NewTx(&types.SignerTx{
		ChainID:    txEdUnsigned.ChainId(),
		Nonce:      txEdUnsigned.Nonce(),
		To:         txEdUnsigned.To(),
		Value:      txEdUnsigned.Value(),
		Gas:        txEdUnsigned.Gas(),
		Data:       txEdUnsigned.Data(),
		From:       from,
		SignerType: accountsigner.SignerTypeEd25519,
		V:          big.NewInt(0),
		R:          new(big.Int).SetBytes(edSig[:32]),
		S:          new(big.Int).SetBytes(edSig[32:]),
	})

	db := rawdb.NewMemoryDatabase()
	gspec := &core.Genesis{
		Config: config,
		Alloc: core.GenesisAlloc{
			from: {Balance: big.NewInt(10_000_000_000_000_000)},
			to:   {Balance: big.NewInt(0)},
		},
	}
	genesis := gspec.MustCommit(db)
	blockchain, err := core.NewBlockChain(db, nil, config, dpos.NewFaker(), nil, nil)
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer blockchain.Stop()

	header := &types.Header{
		ParentHash: genesis.Hash(),
		Number:     big.NewInt(1),
		GasLimit:   30_000_000,
		BaseFee:    big.NewInt(0),
		Time:       genesis.Time() + 10_000,
	}
	block := types.NewBlock(header, []*types.Transaction{txSetSigner, txEd}, nil, nil, trie.NewStackTrie(nil))

	tosNode := &TOS{blockchain: blockchain, chainDb: db}
	if _, _, err := tosNode.stateAtTransaction(block, 1, 0); err == nil || !strings.Contains(err.Error(), core.ErrAccountSignerMismatch.Error()) {
		t.Fatalf("expected pre-block signer mismatch, got: %v", err)
	}
}
