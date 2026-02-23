package core

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
	"github.com/tos-network/gtos/common/math"
	"github.com/tos-network/gtos/consensus"
	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/consensus/misc"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/kvstore"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
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
			DPoS:    &params.DPoSConfig{Period: 3, Epoch: 200, MaxValidators: 21},
		}
		signer  = types.LatestSigner(config)
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		key2, _ = crypto.HexToECDSA("0202020202020202020202020202020202020202020202020202002020202020")
	)
	var makeTx = func(key *ecdsa.PrivateKey, nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *types.Transaction {
		tx, _ := signTestSignerTx(signer, key, nonce, to, amount, gasLimit, gasPrice, data)
		return tx
	}
	var mkUnsupportedSignerTypeTx = func(nonce uint64, to common.Address, gasLimit uint64, gasPrice *big.Int) *types.Transaction {
		if gasPrice == nil {
			gasPrice = big.NewInt(1)
		}
		return types.NewTx(&types.SignerTx{
			ChainID:    signer.ChainID(),
			Nonce:      nonce,
			Gas:        gasLimit,
			To:         &to,
			Value:      big.NewInt(0),
			GasPrice:   new(big.Int).Set(gasPrice),
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
					common.HexToAddress("0x71562b71999873DB5b286dF957af199Ec94617F7"): GenesisAccount{
						Balance: big.NewInt(1000000000000000000), // 1 tos
						Nonce:   0,
					},
					common.HexToAddress("0xfd0810DD14796680f72adf1a371963d0745BCc64"): GenesisAccount{
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
				want: "nonce too low: address 0x71562b71999873DB5b286dF957af199Ec94617F7, tx: 0 state: 1",
			},
			{ // ErrNonceTooHigh
				txs: []*types.Transaction{
					makeTx(key1, 100, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(875000000), nil),
				},
				want: "nonce too high: address 0x71562b71999873DB5b286dF957af199Ec94617F7, tx: 100 state: 0",
			},
			{ // ErrNonceMax
				txs: []*types.Transaction{
					makeTx(key2, math.MaxUint64, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(875000000), nil),
				},
				want: "nonce has max value: address 0xfd0810DD14796680f72adf1a371963d0745BCc64, nonce: 18446744073709551615",
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
				want: "insufficient funds for gas * price + value: address 0x71562b71999873DB5b286dF957af199Ec94617F7 have 1000000000000000000 want 1000002625000000000",
			},
			{ // ErrInsufficientFunds
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(900000000000000000), nil),
				},
				want: "insufficient funds for gas * price + value: address 0x71562b71999873DB5b286dF957af199Ec94617F7 have 1000000000000000000 want 2700000000000000000000",
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
					common.HexToAddress("0x71562b71999873DB5b286dF957af199Ec94617F7"): GenesisAccount{
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
					common.HexToAddress("0x71562b71999873DB5b286dF957af199Ec94617F7"): GenesisAccount{
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
				want: "sender not an eoa: address 0x71562b71999873DB5b286dF957af199Ec94617F7, codehash: 0x9280914443471259d4570a8661015ae4a5b80186dbc619658fb494bebc3da3d1",
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
		DPoS:    &params.DPoSConfig{Period: 3, Epoch: 200, MaxValidators: 21},
	}
	chainSigner := types.LatestSigner(config)
	fromKey, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to load sender key: %v", err)
	}
	from := crypto.PubkeyToAddress(fromKey.PublicKey)
	to := common.HexToAddress("0x00000000000000000000000000000000000000f1")

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
		GasPrice:   big.NewInt(1),
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
		GasPrice:   big.NewInt(1),
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
		GasPrice:   txEdUnsigned.GasPrice(),
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

func TestStateProcessorPrunesExpiredKVAtBlockBoundary(t *testing.T) {
	config := &params.ChainConfig{
		ChainID: big.NewInt(1),
		DPoS:    &params.DPoSConfig{Period: 3, Epoch: 200, MaxValidators: 21},
	}
	signer := types.LatestSigner(config)
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to load key: %v", err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)

	buildDB := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config: config,
		Alloc: GenesisAlloc{
			from: {Balance: big.NewInt(10_000_000_000_000_000)},
		},
	}
	genesis := gspec.MustCommit(buildDB)

	payload, err := kvstore.EncodePutPayload("ns", []byte("k"), []byte("value"), 1) // block1 -> expireAt=2
	if err != nil {
		t.Fatalf("encode kv payload: %v", err)
	}
	txKV, err := signTestSignerTx(signer, key, 0, params.KVRouterAddress, big.NewInt(0), 500_000, big.NewInt(1), payload)
	if err != nil {
		t.Fatalf("sign kv tx: %v", err)
	}

	blocks, _ := GenerateChain(config, genesis, dpos.NewFaker(), buildDB, 2, func(i int, b *BlockGen) {
		if i == 0 {
			b.AddTx(txKV)
		}
	})

	runDB := rawdb.NewMemoryDatabase()
	gspec.MustCommit(runDB)
	blockchain, err := NewBlockChain(runDB, nil, gspec.Config, dpos.NewFaker(), nil, nil)
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer blockchain.Stop()

	if _, err := blockchain.InsertChain(blocks[:1]); err != nil {
		t.Fatalf("insert block1: %v", err)
	}
	st1, err := blockchain.State()
	if err != nil {
		t.Fatalf("state at block1: %v", err)
	}
	metaAt1 := kvstore.GetMeta(st1, from, "ns", []byte("k"))
	if !metaAt1.Exists || metaAt1.ExpireAt != 2 {
		t.Fatalf("unexpected kv meta at block1: %+v", metaAt1)
	}

	if _, err := blockchain.InsertChain(blocks[1:]); err != nil {
		t.Fatalf("insert block2: %v", err)
	}
	if have, want := blockchain.CurrentBlock().NumberU64(), uint64(2); have != want {
		t.Fatalf("unexpected head number: have %d want %d", have, want)
	}
	st, err := blockchain.State()
	if err != nil {
		t.Fatalf("state at head: %v", err)
	}
	meta := kvstore.GetMeta(st, from, "ns", []byte("k"))
	if meta.Exists {
		t.Fatalf("expected kv to be pruned at block2, got meta=%+v", meta)
	}
	if _, _, found := kvstore.Get(st, from, "ns", []byte("k")); found {
		t.Fatalf("expected kv value to be removed at block2")
	}
}

func TestStateProcessorPrunesExpiredCodeAtBlockBoundary(t *testing.T) {
	config := &params.ChainConfig{
		ChainID: big.NewInt(1),
		DPoS:    &params.DPoSConfig{Period: 3, Epoch: 200, MaxValidators: 21},
	}
	signer := types.LatestSigner(config)
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to load key: %v", err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)

	buildDB := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config: config,
		Alloc: GenesisAlloc{
			from: {Balance: big.NewInt(10_000_000_000_000_000)},
		},
	}
	genesis := gspec.MustCommit(buildDB)

	payload, err := EncodeSetCodePayload(1, []byte{0x60, 0x00}) // block1 -> expireAt=2
	if err != nil {
		t.Fatalf("encode setCode payload: %v", err)
	}
	txUnsigned := types.NewTx(&types.SignerTx{
		ChainID:    signer.ChainID(),
		Nonce:      0,
		To:         nil,
		Value:      big.NewInt(0),
		Gas:        500_000,
		GasPrice:   big.NewInt(1),
		Data:       payload,
		From:       from,
		SignerType: accountsigner.SignerTypeSecp256k1,
	})
	txSetCode, err := types.SignTx(txUnsigned, signer, key)
	if err != nil {
		t.Fatalf("sign setCode tx: %v", err)
	}

	blocks, _ := GenerateChain(config, genesis, dpos.NewFaker(), buildDB, 2, func(i int, b *BlockGen) {
		if i == 0 {
			b.AddTx(txSetCode)
		}
	})

	runDB := rawdb.NewMemoryDatabase()
	gspec.MustCommit(runDB)
	blockchain, err := NewBlockChain(runDB, nil, gspec.Config, dpos.NewFaker(), nil, nil)
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer blockchain.Stop()

	if _, err := blockchain.InsertChain(blocks[:1]); err != nil {
		t.Fatalf("insert block1: %v", err)
	}
	st1, err := blockchain.State()
	if err != nil {
		t.Fatalf("state at block1: %v", err)
	}
	if code := st1.GetCode(from); len(code) == 0 {
		t.Fatalf("expected code to be set at block1")
	}
	if expireAt := stateWordToUint64(st1.GetState(from, SetCodeExpireAtSlot)); expireAt != 2 {
		t.Fatalf("unexpected expireAt at block1: have %d want 2", expireAt)
	}

	if _, err := blockchain.InsertChain(blocks[1:]); err != nil {
		t.Fatalf("insert block2: %v", err)
	}
	st2, err := blockchain.State()
	if err != nil {
		t.Fatalf("state at block2: %v", err)
	}
	if code := st2.GetCode(from); len(code) != 0 {
		t.Fatalf("expected code to be pruned at block2, have len=%d", len(code))
	}
	if createdAt := stateWordToUint64(st2.GetState(from, SetCodeCreatedAtSlot)); createdAt != 0 {
		t.Fatalf("expected createdAt cleared at block2, have %d", createdAt)
	}
	if expireAt := stateWordToUint64(st2.GetState(from, SetCodeExpireAtSlot)); expireAt != 0 {
		t.Fatalf("expected expireAt cleared at block2, have %d", expireAt)
	}
}

// GenerateBadBlock constructs a "block" which contains the transactions. The transactions are not expected to be
// valid, and no proper post-state can be made. But from the perspective of the blockchain, the block is sufficiently
// valid to be considered for import:
// - valid pow (fake), ancestry, difficulty, gaslimit etc
func GenerateBadBlock(parent *types.Block, engine consensus.Engine, txs types.Transactions, config *params.ChainConfig) *types.Block {
	header := &types.Header{
		ParentHash: parent.Hash(),
		Coinbase:   parent.Coinbase(),
		Difficulty: engine.CalcDifficulty(&fakeChainReader{config}, parent.Time()+10, &types.Header{
			Number:     parent.Number(),
			Time:       parent.Time(),
			Difficulty: parent.Difficulty(),
			UncleHash:  parent.UncleHash(),
		}),
		GasLimit:  parent.GasLimit(),
		Number:    new(big.Int).Add(parent.Number(), common.Big1),
		Time:      parent.Time() + 10,
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
