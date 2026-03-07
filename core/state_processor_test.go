// Copyright 2020 The go-ethereum Authors
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

package core

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	crand "crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/common/math"
	"github.com/tos-network/gtos/consensus"
	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/consensus/misc"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
	"github.com/tos-network/gtos/task"
	"github.com/tos-network/gtos/trie"
	"golang.org/x/crypto/sha3"
)

// TestStateProcessorErrors tests the output from the 'core' errors
// as defined in core/error.go. These errors are generated when the
// blockchain imports bad blocks, meaning blocks which have valid headers but
// contain invalid transactions
func TestStateProcessorErrors(t *testing.T) {
	var (
		config = &params.ChainConfig{
			ChainID: big.NewInt(1),
			DPoS:    &params.DPoSConfig{PeriodMs: 3000, Epoch: 200, MaxValidators: 21},
		}
		signer  = types.LatestSigner(config)
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		key2, _ = crypto.HexToECDSA("0202020202020202020202020202020202020202020202020202002020202020")
		addr1   = crypto.PubkeyToAddress(key1.PublicKey)
		addr2   = crypto.PubkeyToAddress(key2.PublicKey)
	)
	var makeTx = func(key *ecdsa.PrivateKey, nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, txPrice *big.Int, data []byte) *types.Transaction {
		tx, _ := signTestSignerTx(signer, key, nonce, to, amount, gasLimit, txPrice, data)
		return tx
	}
	var mkUnsupportedSignerTypeTx = func(nonce uint64, to common.Address, gasLimit uint64, txPrice *big.Int) *types.Transaction {
		if txPrice == nil {
			txPrice = big.NewInt(1)
		}
		return types.NewTx(&types.SignerTx{
			ChainID:    signer.ChainID(),
			Nonce:      nonce,
			Gas:        gasLimit,
			To:         &to,
			Value:      big.NewInt(0),
			From:       crypto.PubkeyToAddress(key1.PublicKey),
			SignerType: "frost",
			V:          new(big.Int),
			R:          new(big.Int),
			S:          new(big.Int),
		})
	}
	{ // Tests against a 'recent' chain definition
		var (
			db    = rawdb.NewMemoryDatabase()
			gspec = &Genesis{
				Config: config,
				Alloc: GenesisAlloc{
					addr1: GenesisAccount{
						Balance: big.NewInt(1000000000000000000), // 1 tos
						Nonce:   0,
					},
					addr2: GenesisAccount{
						Balance: big.NewInt(1000000000000000000), // 1 tos
						Nonce:   math.MaxUint64,
					},
				},
			}
			genesis       = gspec.MustCommit(db)
			blockchain, _ = NewBlockChain(db, nil, gspec.Config, dpos.NewFaker(), nil, nil)
		)
		defer blockchain.Stop()
		for i, tt := range []struct {
			txs  []*types.Transaction
			want string
		}{
			{ // ErrNonceTooLow
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(875000000), nil),
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(875000000), nil),
				},
				want: fmt.Sprintf("nonce too low: address %s, tx: 0 state: 1", addr1.Hex()),
			},
			{ // ErrNonceTooHigh
				txs: []*types.Transaction{
					makeTx(key1, 100, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(875000000), nil),
				},
				want: fmt.Sprintf("nonce too high: address %s, tx: 100 state: 0", addr1.Hex()),
			},
			{ // ErrNonceMax
				txs: []*types.Transaction{
					makeTx(key2, math.MaxUint64, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(875000000), nil),
				},
				want: fmt.Sprintf("nonce has max value: address %s, nonce: 18446744073709551615", addr2.Hex()),
			},
			{ // ErrGasLimitReached
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), 21000000, big.NewInt(875000000), nil),
				},
				want: "gas limit reached",
			},
			{ // ErrInsufficientFundsForTransfer
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(1000000000000000000), params.TxGas, big.NewInt(875000000), nil),
				},
				want: fmt.Sprintf("insufficient funds for gas * price + value: address %s have 1000000000000000000 want 1000030000000000000", addr1.Hex()),
			},
			// ErrGasUintOverflow
			// One missing 'core' error is ErrGasUintOverflow: "gas uint64 overflow",
			// In order to trigger that one, we'd have to allocate a _huge_ chunk of data, such that the
			// multiplication len(data) +gas_per_byte overflows uint64. Not testable at the moment
			{ // ErrIntrinsicGas
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas-1000, big.NewInt(875000000), nil),
				},
				want: "intrinsic gas too low: have 2000, want 3000",
			},
			{ // ErrGasLimitReached
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), 21_000_000, big.NewInt(875000000), nil),
				},
				want: "gas limit reached",
			},
		} {
			block := GenerateBadBlock(genesis, dpos.NewFaker(), tt.txs, gspec.Config)
			_, err := blockchain.InsertChain(types.Blocks{block})
			if err == nil {
				t.Fatal("block imported without errors")
			}
			if have, want := err.Error(), tt.want; !strings.Contains(have, want) {
				t.Errorf("test %d:\nhave \"%v\"\nwant \"%v\"\n", i, have, want)
			}
		}
	}

	// ErrTxTypeNotSupported
	{
		var (
			db    = rawdb.NewMemoryDatabase()
			gspec = &Genesis{
				Config: &params.ChainConfig{
					ChainID: big.NewInt(1),
				},
				Alloc: GenesisAlloc{
					addr1: GenesisAccount{
						Balance: big.NewInt(1000000000000000000), // 1 tos
						Nonce:   0,
					},
				},
			}
			genesis       = gspec.MustCommit(db)
			blockchain, _ = NewBlockChain(db, nil, gspec.Config, dpos.NewFaker(), nil, nil)
		)
		defer blockchain.Stop()
		for i, tt := range []struct {
			txs  []*types.Transaction
			want string
		}{
			{ // unknown signer type
				txs: []*types.Transaction{
					mkUnsupportedSignerTypeTx(0, common.Address{}, params.TxGas, big.NewInt(1)),
				},
				want: "unknown signer type",
			},
		} {
			block := GenerateBadBlock(genesis, dpos.NewFaker(), tt.txs, gspec.Config)
			_, err := blockchain.InsertChain(types.Blocks{block})
			if err == nil {
				t.Fatal("block imported without errors")
			}
			if have, want := err.Error(), tt.want; !strings.Contains(have, want) {
				t.Errorf("test %d:\nhave \"%v\"\nwant \"%v\"\n", i, have, want)
			}
		}
	}

	// ErrSenderNoEOA, for this we need the sender to have contract code
	{
		var (
			db    = rawdb.NewMemoryDatabase()
			gspec = &Genesis{
				Config: config,
				Alloc: GenesisAlloc{
					addr1: GenesisAccount{
						Balance: big.NewInt(1000000000000000000), // 1 tos
						Nonce:   0,
						Code:    common.FromHex("0xB0B0FACE"),
					},
				},
			}
			genesis       = gspec.MustCommit(db)
			blockchain, _ = NewBlockChain(db, nil, gspec.Config, dpos.NewFaker(), nil, nil)
		)
		defer blockchain.Stop()
		for i, tt := range []struct {
			txs  []*types.Transaction
			want string
		}{
			{ // ErrSenderNoEOA
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(1), nil),
				},
				want: fmt.Sprintf("sender not an eoa: address %s, codehash: 0x9280914443471259d4570a8661015ae4a5b80186dbc619658fb494bebc3da3d1", addr1.Hex()),
			},
		} {
			block := GenerateBadBlock(genesis, dpos.NewFaker(), tt.txs, gspec.Config)
			_, err := blockchain.InsertChain(types.Blocks{block})
			if err == nil {
				t.Fatal("block imported without errors")
			}
			if have, want := err.Error(), tt.want; !strings.Contains(have, want) {
				t.Errorf("test %d:\nhave \"%v\"\nwant \"%v\"\n", i, have, want)
			}
		}
	}
}

func TestDeterministicNonceStateTransitionAndReplayRejection(t *testing.T) {
	config := &params.ChainConfig{
		ChainID: big.NewInt(1),
		DPoS:    &params.DPoSConfig{PeriodMs: 3000, Epoch: 200, MaxValidators: 21},
	}
	chainSigner := types.LatestSigner(config)
	fromKey, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to load sender key: %v", err)
	}
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

	makeChain := func() (*BlockChain, *types.Block) {
		db := rawdb.NewMemoryDatabase()
		gspec := &Genesis{
			Config: config,
			Alloc: GenesisAlloc{
				from: {Balance: big.NewInt(10_000_000_000_000_000)},
				to:   {Balance: big.NewInt(0)},
			},
		}
		genesis := gspec.MustCommit(db)
		blockchain, chainErr := NewBlockChain(db, nil, gspec.Config, dpos.NewFaker(), nil, nil)
		if chainErr != nil {
			t.Fatalf("failed to create blockchain: %v", chainErr)
		}
		return blockchain, genesis
	}

	chainA, _ := makeChain()
	defer chainA.Stop()
	chainB, _ := makeChain()
	defer chainB.Stop()

	generateDB := rawdb.NewMemoryDatabase()
	generateGenesis := (&Genesis{
		Config: config,
		Alloc: GenesisAlloc{
			from: {Balance: big.NewInt(10_000_000_000_000_000)},
			to:   {Balance: big.NewInt(0)},
		},
	}).MustCommit(generateDB)
	blocks, _ := GenerateChain(config, generateGenesis, dpos.NewFaker(), generateDB, 2, func(i int, b *BlockGen) {
		switch i {
		case 0:
			b.AddTx(txSetSigner)
		case 1:
			b.AddTx(txEd)
		}
	})

	insertOne := func(chain *BlockChain, block *types.Block) {
		if n, insertErr := chain.InsertChain(types.Blocks{block}); insertErr != nil {
			t.Fatalf("insert failed at index %d: %v", n, insertErr)
		}
	}
	insertOne(chainA, blocks[0])
	insertOne(chainB, blocks[0])

	assertState := func(chain *BlockChain, wantNonce uint64) {
		st, stateErr := chain.State()
		if stateErr != nil {
			t.Fatalf("failed to load state: %v", stateErr)
		}
		if got := st.GetNonce(from); got != wantNonce {
			t.Fatalf("unexpected nonce: have %d want %d", got, wantNonce)
		}
		sType, _, ok := accountsigner.Get(st, from)
		if !ok || sType != accountsigner.SignerTypeEd25519 {
			t.Fatalf("unexpected signer metadata after setSigner: ok=%v type=%q", ok, sType)
		}
	}
	assertState(chainA, 1)
	assertState(chainB, 1)
	if chainA.CurrentBlock().Root() != chainB.CurrentBlock().Root() {
		t.Fatalf("state root mismatch after block1: A=%s B=%s", chainA.CurrentBlock().Root().Hex(), chainB.CurrentBlock().Root().Hex())
	}

	insertOne(chainA, blocks[1])
	insertOne(chainB, blocks[1])
	assertState(chainA, 2)
	assertState(chainB, 2)
	if chainA.CurrentBlock().Root() != chainB.CurrentBlock().Root() {
		t.Fatalf("state root mismatch after block2: A=%s B=%s", chainA.CurrentBlock().Root().Hex(), chainB.CurrentBlock().Root().Hex())
	}

	beforeReplayA := chainA.CurrentBlock()
	beforeReplayB := chainB.CurrentBlock()
	replayBlockA := GenerateBadBlock(beforeReplayA, dpos.NewFaker(), types.Transactions{txEd}, config)
	replayBlockB := GenerateBadBlock(beforeReplayB, dpos.NewFaker(), types.Transactions{txEd}, config)

	if _, replayErr := chainA.InsertChain(types.Blocks{replayBlockA}); replayErr == nil || !strings.Contains(replayErr.Error(), "nonce too low") {
		t.Fatalf("expected replay nonce-too-low error on chainA, got: %v", replayErr)
	}
	if _, replayErr := chainB.InsertChain(types.Blocks{replayBlockB}); replayErr == nil || !strings.Contains(replayErr.Error(), "nonce too low") {
		t.Fatalf("expected replay nonce-too-low error on chainB, got: %v", replayErr)
	}
	if chainA.CurrentBlock().Hash() != beforeReplayA.Hash() || chainB.CurrentBlock().Hash() != beforeReplayB.Hash() {
		t.Fatalf("head changed after replay rejection")
	}
	if chainA.CurrentBlock().Root() != chainB.CurrentBlock().Root() {
		t.Fatalf("state root mismatch after replay rejection: A=%s B=%s", chainA.CurrentBlock().Root().Hex(), chainB.CurrentBlock().Root().Hex())
	}
}

func TestScheduledTaskGasCountedInGeneratedBlock(t *testing.T) {
	config := &params.ChainConfig{
		ChainID: big.NewInt(1),
		DPoS:    &params.DPoSConfig{PeriodMs: 3000, Epoch: 200, MaxValidators: 21},
	}
	signer := types.LatestSigner(config)
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to load scheduler key: %v", err)
	}
	scheduler := crypto.PubkeyToAddress(key.PublicKey)
	target := common.HexToAddress("0x5001")

	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config: config,
		Alloc: GenesisAlloc{
			scheduler: {
				Balance: new(big.Int).Mul(big.NewInt(10), new(big.Int).SetUint64(params.TOS)),
			},
			target: {
				Balance: big.NewInt(0),
				Code:    []byte(`tos.sstore("task_counter", 1)`),
			},
		},
	}
	genesis := gspec.MustCommit(db)

	blocks, _ := GenerateChain(config, genesis, dpos.NewFaker(), db, 2, func(i int, b *BlockGen) {
		if i != 0 {
			return
		}
		data, err := sysaction.MakeSysAction(sysaction.ActionTaskSchedule, map[string]interface{}{
			"target":          target.Hex(),
			"selector":        "0x00000000",
			"task_data":       common.Hash{}.Hex(),
			"gas_limit":       params.TaskMinGasLimit,
			"delay_blocks":    uint64(1),
			"interval_blocks": uint64(0),
			"max_runs":        uint64(1),
		})
		if err != nil {
			t.Fatalf("MakeSysAction: %v", err)
		}
		tx, err := signTestSignerTx(
			signer, key, b.TxNonce(scheduler), params.SystemActionAddress,
			big.NewInt(0), 500_000, big.NewInt(1), data,
		)
		if err != nil {
			t.Fatalf("signTestSignerTx: %v", err)
		}
		b.AddTx(tx)
	})

	postBlock1State, err := state.New(blocks[0].Root(), state.NewDatabase(db), nil)
	if err != nil {
		t.Fatalf("state.New(block1): %v", err)
	}
	taskID := task.NewTaskID(scheduler, 2, 0)
	if rec, ok := task.ReadTask(postBlock1State, taskID); !ok || rec.TargetBlock != 2 || rec.Status != task.TaskPending {
		t.Fatalf("scheduled task missing after block 1: ok=%v rec=%+v", ok, rec)
	}

	if blocks[1].GasUsed() == 0 {
		t.Fatal("scheduled task gas was not counted into the generated block")
	}

	blockchain, err := NewBlockChain(db, nil, config, dpos.NewFaker(), nil, nil)
	if err != nil {
		t.Fatalf("NewBlockChain: %v", err)
	}
	defer blockchain.Stop()

	if _, err := blockchain.InsertChain(blocks); err != nil {
		t.Fatalf("InsertChain: %v", err)
	}
	postState, err := blockchain.State()
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if got := postState.GetState(target, vm.StorageSlot("task_counter")).Big().Uint64(); got != 1 {
		t.Fatalf("scheduled task did not mutate target storage: got %d want 1", got)
	}
}

func TestAddTxWithChainAndProcessSharePreBlockSignerSemantics(t *testing.T) {
	config := &params.ChainConfig{
		ChainID: big.NewInt(1),
		DPoS:    &params.DPoSConfig{PeriodMs: 3000, Epoch: 200, MaxValidators: 21},
	}
	chainSigner := types.LatestSigner(config)
	fromKey, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to load sender key: %v", err)
	}
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

	// Path A: AddTxWithChain (GenerateChain path) should reject the second tx
	// because sender resolution uses pre-block signer metadata.
	buildDB := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config: config,
		Alloc: GenesisAlloc{
			from: {Balance: big.NewInt(10_000_000_000_000_000)},
			to:   {Balance: big.NewInt(0)},
		},
	}
	genesis := gspec.MustCommit(buildDB)
	var panicVal interface{}
	func() {
		defer func() { panicVal = recover() }()
		GenerateChain(config, genesis, dpos.NewFaker(), buildDB, 1, func(i int, b *BlockGen) {
			b.AddTx(txSetSigner)
			b.AddTx(txEd)
		})
	}()
	if panicVal == nil {
		t.Fatal("expected AddTxWithChain path to panic on signer mismatch, got nil")
	}
	panicMsg := fmt.Sprint(panicVal)
	if !strings.Contains(panicMsg, ErrAccountSignerMismatch.Error()) {
		t.Fatalf("unexpected AddTxWithChain panic: %v", panicVal)
	}

	// Path B: Process (block import path) should reject the same tx list for the same reason.
	runDB := rawdb.NewMemoryDatabase()
	gspec.MustCommit(runDB)
	blockchain, err := NewBlockChain(runDB, nil, config, dpos.NewFaker(), nil, nil)
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer blockchain.Stop()

	badBlock := GenerateBadBlock(blockchain.CurrentBlock(), dpos.NewFaker(), types.Transactions{txSetSigner, txEd}, config)
	if _, err := blockchain.InsertChain(types.Blocks{badBlock}); err == nil || !strings.Contains(err.Error(), ErrAccountSignerMismatch.Error()) {
		t.Fatalf("expected Process path signer mismatch error, got: %v", err)
	}
}

// GenerateBadBlock constructs a "block" which contains the transactions. The transactions are not expected to be
// valid, and no proper post-state can be made. But from the perspective of the blockchain, the block is sufficiently
// valid to be considered for import:
// - valid pow (fake), ancestry, difficulty, gaslimit etc
func GenerateBadBlock(parent *types.Block, engine consensus.Engine, txs types.Transactions, config *params.ChainConfig) *types.Block {
	timeStep := uint64(10)
	if config != nil && config.DPoS != nil {
		timeStep = 10 * 1000
	}
	header := &types.Header{
		ParentHash: parent.Hash(),
		Coinbase:   parent.Coinbase(),
		Difficulty: engine.CalcDifficulty(&fakeChainReader{config: config}, parent.Time()+timeStep, &types.Header{
			Number:     parent.Number(),
			Time:       parent.Time(),
			Difficulty: parent.Difficulty(),
			UncleHash:  parent.UncleHash(),
		}),
		GasLimit:  parent.GasLimit(),
		Number:    new(big.Int).Add(parent.Number(), common.Big1),
		Time:      parent.Time() + timeStep,
		UncleHash: types.EmptyUncleHash,
	}
	header.BaseFee = misc.CalcBaseFee(config, parent.Header())
	var receipts []*types.Receipt
	// The post-state result doesn't need to be correct (this is a bad block), but we do need something there
	// Preferably something unique. So let's use a combo of blocknum + txhash
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(header.Number.Bytes())
	var cumulativeGas uint64
	for _, tx := range txs {
		txh := tx.Hash()
		hasher.Write(txh[:])
		receipt := types.NewReceipt(nil, false, cumulativeGas+tx.Gas())
		receipt.TxHash = tx.Hash()
		receipt.GasUsed = tx.Gas()
		receipts = append(receipts, receipt)
		cumulativeGas += tx.Gas()
	}
	header.Root = common.BytesToHash(hasher.Sum(nil))
	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil))
}
