package dpos

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"reflect"
	"sort"
	"testing"

	"github.com/tos-network/gtos/accounts"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
	"github.com/tos-network/gtos/validator"
)

// TestDPoSChainInsert builds a small DPoS chain (genesis + 5 blocks) and
// inserts them into a real BlockChain, verifying that:
//   - The engine accepts signed blocks
//   - Block rewards are credited to the coinbase
//   - The chain head advances correctly
//
// Note: GenerateChain uses makeHeader() which copies parent.Coinbase() into
// each block and does not call engine.Prepare(). We set genspec.Coinbase =
// signer so that the coinbase propagates to all generated blocks, ensuring
// the state root computed during generation matches the one during insertion.
func TestDPoSChainInsert(t *testing.T) {
	key, _ := crypto.GenerateKey()
	signer := crypto.PubkeyToAddress(key.PublicKey)

	db := rawdb.NewMemoryDatabase()

	// Genesis Extra: 32-byte vanity + signer address (no seal on block 0).
	genesisExtra := make([]byte, extraVanity+common.AddressLength)
	copy(genesisExtra[extraVanity:], signer.Bytes())

	dposCfg := &params.DPoSConfig{Period: 1, Epoch: 200, MaxValidators: 21}
	chainCfg := *params.AllDPoSProtocolChanges
	chainCfg.DPoS = dposCfg

	genspec := &core.Genesis{
		Config:    &chainCfg,
		ExtraData: genesisExtra,
		Coinbase:  signer, // makeHeader copies parent.Coinbase() — set here so reward target is consistent
		Alloc: map[common.Address]core.GenesisAccount{
			signer: {Balance: new(big.Int).Mul(big.NewInt(1_000_000), big.NewInt(1e18))},
		},
		BaseFee: big.NewInt(params.InitialBaseFee),
	}
	genesis := genspec.MustCommit(db)

	engine, err := New(dposCfg, db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	engine.Authorize(signer, func(_ accounts.Account, _ string, hash []byte) ([]byte, error) {
		return crypto.Sign(hash, key)
	})

	chain, err := core.NewBlockChain(db, nil, &chainCfg, engine, nil, nil)
	if err != nil {
		t.Fatalf("NewBlockChain: %v", err)
	}
	defer chain.Stop()

	const nBlocks = 5
	// GenerateChain builds blocks without calling engine.Prepare(); it sets
	// Coinbase from parent.Coinbase() and calls FinalizeAndAssemble to seal.
	// We only need to fix up the Extra (add seal) and update ParentHash to
	// account for changed block hashes after signing.
	blocks, _ := core.GenerateChain(&chainCfg, genesis, engine, db, nBlocks,
		func(i int, b *core.BlockGen) {
			b.SetDifficulty(diffInTurn)
		})

	// Sign each block: only change Extra (add seal). Do NOT change Coinbase or
	// Root — those are already correctly set by GenerateChain's FinalizeAndAssemble.
	for i, block := range blocks {
		header := block.Header()
		if i > 0 {
			// Update ParentHash to point to the signed (hash-changed) previous block.
			header.ParentHash = blocks[i-1].Hash()
		}
		// Build a proper Extra: [extraVanity bytes][extraSeal bytes].
		// This MUST be set before calling SealHash (encodeSigHeader strips Extra[:-65]).
		// GenerateChain does not call engine.Prepare(), so Extra may be nil/short.
		newExtra := make([]byte, extraVanity+extraSeal)
		if len(header.Extra) >= extraVanity {
			copy(newExtra, header.Extra[:extraVanity]) // preserve any existing vanity
		}
		header.Extra = newExtra // set before SealHash strips it

		sig, err := crypto.Sign(SealHash(header).Bytes(), key)
		if err != nil {
			t.Fatalf("sign block %d: %v", i+1, err)
		}
		copy(header.Extra[extraVanity:], sig)

		blocks[i] = block.WithSeal(header)
	}

	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("InsertChain failed at block %d: %v", n+1, err)
	}
	if head := chain.CurrentBlock().NumberU64(); head != nBlocks {
		t.Errorf("chain head: want %d, got %d", nBlocks, head)
	}

	// Verify block rewards accrued: signer balance > initial allocation.
	st, _ := chain.State()
	initialBal := new(big.Int).Mul(big.NewInt(1_000_000), big.NewInt(1e18))
	bal := st.GetBalance(signer)
	if bal.Cmp(initialBal) <= 0 {
		t.Errorf("signer balance did not increase after %d blocks: got %v, want > %v",
			nBlocks, bal, initialBal)
	}
}

func TestDPoSThreeValidatorStabilityGate(t *testing.T) {
	const (
		nBlocks     = 1024
		insertBatch = 64
	)

	// Deterministic 3-validator fixture.
	keyHexes := []string{
		"b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291",
		"49a7b37aa6f664591f6f7d8dc908dc7ea0b89f2de0b5261f7fa693596e5361d0",
		"8a1f9a8f3c5e0a8f94c47df7fdc5fb8a0d4e7f3d7d2c24f6f9a16ddbc5c94939",
	}
	keysByAddr := make(map[common.Address]*ecdsa.PrivateKey, len(keyHexes))
	validators := make([]common.Address, 0, len(keyHexes))
	for _, hexKey := range keyHexes {
		key, err := crypto.HexToECDSA(hexKey)
		if err != nil {
			t.Fatalf("invalid fixture private key: %v", err)
		}
		addr := crypto.PubkeyToAddress(key.PublicKey)
		keysByAddr[addr] = key
		validators = append(validators, addr)
	}
	sort.Slice(validators, func(i, j int) bool {
		return validators[i].Hex() < validators[j].Hex()
	})

	dposCfg := &params.DPoSConfig{Period: 1, Epoch: 5000, MaxValidators: 21}
	chainCfg := *params.AllDPoSProtocolChanges
	chainCfg.DPoS = dposCfg

	genesisExtra := make([]byte, extraVanity+len(validators)*common.AddressLength)
	for i, v := range validators {
		copy(genesisExtra[extraVanity+i*common.AddressLength:], v.Bytes())
	}
	genspec := &core.Genesis{
		Config:    &chainCfg,
		ExtraData: genesisExtra,
		Coinbase:  validators[0],
		BaseFee:   big.NewInt(params.InitialBaseFee),
	}

	// Build one canonical 1024-block sequence with deterministic validator rotation.
	buildDB := rawdb.NewMemoryDatabase()
	genesis := genspec.MustCommit(buildDB)
	buildEngine, err := New(dposCfg, buildDB)
	if err != nil {
		t.Fatalf("New(buildEngine): %v", err)
	}
	blocks, _ := core.GenerateChain(&chainCfg, genesis, buildEngine, buildDB, nBlocks, func(i int, b *core.BlockGen) {
		number := uint64(i + 1)
		signer := validators[number%uint64(len(validators))]
		b.SetCoinbase(signer)
		b.SetDifficulty(diffInTurn) // signer follows in-turn schedule by construction.
	})
	for i, block := range blocks {
		header := block.Header()
		if i > 0 {
			// Re-link to the previous signed block hash.
			header.ParentHash = blocks[i-1].Hash()
		}
		number := header.Number.Uint64()
		signer := validators[number%uint64(len(validators))]
		key := keysByAddr[signer]
		if key == nil {
			t.Fatalf("missing key for signer %s", signer.Hex())
		}
		header.Coinbase = signer
		newExtra := make([]byte, extraVanity+extraSeal)
		if len(header.Extra) >= extraVanity {
			copy(newExtra, header.Extra[:extraVanity])
		}
		header.Extra = newExtra
		sig, signErr := crypto.Sign(SealHash(header).Bytes(), key)
		if signErr != nil {
			t.Fatalf("sign block %d: %v", number, signErr)
		}
		copy(header.Extra[extraVanity:], sig)
		blocks[i] = block.WithSeal(header)
	}

	type gateNode struct {
		engine *DPoS
		chain  *core.BlockChain
	}
	nodes := make([]gateNode, 0, 3)
	for i := 0; i < 3; i++ {
		db := rawdb.NewMemoryDatabase()
		genspec.MustCommit(db)
		engine, newErr := New(dposCfg, db)
		if newErr != nil {
			t.Fatalf("New(node %d): %v", i, newErr)
		}
		chain, chainErr := core.NewBlockChain(db, nil, &chainCfg, engine, nil, nil)
		if chainErr != nil {
			t.Fatalf("NewBlockChain(node %d): %v", i, chainErr)
		}
		defer chain.Stop()
		nodes = append(nodes, gateNode{engine: engine, chain: chain})
	}

	for start := 0; start < nBlocks; start += insertBatch {
		end := start + insertBatch
		if end > nBlocks {
			end = nBlocks
		}
		chunk := blocks[start:end]
		for i, node := range nodes {
			if n, insErr := node.chain.InsertChain(chunk); insErr != nil {
				t.Fatalf("InsertChain node=%d failed at local index=%d global_height=%d: %v", i, n, start+n+1, insErr)
			}
		}
		refHead := nodes[0].chain.CurrentBlock()
		for i := 1; i < len(nodes); i++ {
			head := nodes[i].chain.CurrentBlock()
			if head.Hash() != refHead.Hash() || head.Root() != refHead.Root() || head.NumberU64() != refHead.NumberU64() {
				t.Fatalf("divergence after chunk [%d,%d): node0=(num=%d hash=%s root=%s) node%d=(num=%d hash=%s root=%s)",
					start, end, refHead.NumberU64(), refHead.Hash().Hex(), refHead.Root().Hex(),
					i, head.NumberU64(), head.Hash().Hex(), head.Root().Hex())
			}
		}
	}

	// Final gate assertions: 1000+ sequential blocks and full per-height agreement.
	if head := nodes[0].chain.CurrentBlock().NumberU64(); head != nBlocks {
		t.Fatalf("unexpected head height: have %d want %d", head, nBlocks)
	}
	for h := uint64(0); h <= nBlocks; h++ {
		ref := nodes[0].chain.GetBlockByNumber(h)
		if ref == nil {
			t.Fatalf("missing reference block at height %d", h)
		}
		for i := 1; i < len(nodes); i++ {
			got := nodes[i].chain.GetBlockByNumber(h)
			if got == nil {
				t.Fatalf("node %d missing block at height %d", i, h)
			}
			if got.Hash() != ref.Hash() || got.Root() != ref.Root() {
				t.Fatalf("block mismatch at height %d: node0=(hash=%s root=%s) node%d=(hash=%s root=%s)",
					h, ref.Hash().Hex(), ref.Root().Hex(), i, got.Hash().Hex(), got.Root().Hex())
			}
		}
	}

	// Snapshot-level agreement at head (validators + recents).
	refHead := nodes[0].chain.CurrentBlock()
	refSnap, err := nodes[0].engine.snapshot(nodes[0].chain, refHead.NumberU64(), refHead.Hash(), nil)
	if err != nil {
		t.Fatalf("snapshot node0: %v", err)
	}
	for i := 1; i < len(nodes); i++ {
		head := nodes[i].chain.CurrentBlock()
		snap, snapErr := nodes[i].engine.snapshot(nodes[i].chain, head.NumberU64(), head.Hash(), nil)
		if snapErr != nil {
			t.Fatalf("snapshot node%d: %v", i, snapErr)
		}
		if !reflect.DeepEqual(snap.Validators, refSnap.Validators) {
			t.Fatalf("validator set mismatch node%d: have=%v want=%v", i, snap.Validators, refSnap.Validators)
		}
		if !reflect.DeepEqual(snap.Recents, refSnap.Recents) {
			t.Fatalf("snapshot recents mismatch node%d: have=%v want=%v", i, snap.Recents, refSnap.Recents)
		}
	}
}

func TestDPoSEpochRotationUsesValidatorRegistrySet(t *testing.T) {
	keyHexes := []string{
		"b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291",
		"49a7b37aa6f664591f6f7d8dc908dc7ea0b89f2de0b5261f7fa693596e5361d0",
		"8a1f9a8f3c5e0a8f94c47df7fdc5fb8a0d4e7f3d7d2c24f6f9a16ddbc5c94939",
	}
	var (
		keys       []*ecdsa.PrivateKey
		validators []common.Address
	)
	keysByAddr := make(map[common.Address]*ecdsa.PrivateKey, len(keyHexes))
	for _, hexKey := range keyHexes {
		key, err := crypto.HexToECDSA(hexKey)
		if err != nil {
			t.Fatalf("invalid fixture private key: %v", err)
		}
		addr := crypto.PubkeyToAddress(key.PublicKey)
		keys = append(keys, key)
		validators = append(validators, addr)
		keysByAddr[addr] = key
	}
	// Keep expected validator order deterministic (address ascending), matching validator.ReadActiveValidators.
	expectedValidators := append([]common.Address(nil), validators...)
	sort.Slice(expectedValidators, func(i, j int) bool {
		return bytes.Compare(expectedValidators[i][:], expectedValidators[j][:]) < 0
	})

	dposCfg := &params.DPoSConfig{Period: 1, Epoch: 2, MaxValidators: 21}
	chainCfg := *params.AllDPoSProtocolChanges
	chainCfg.DPoS = dposCfg

	genesisSigner := validators[0]
	block3Signer := expectedValidators[0]
	if block3Signer == genesisSigner {
		for _, v := range expectedValidators {
			if v != genesisSigner {
				block3Signer = v
				break
			}
		}
	}
	if block3Signer == genesisSigner {
		t.Fatalf("failed to pick non-recent signer for block3")
	}
	stake := new(big.Int).Set(params.DPoSMinValidatorStake)
	genesisExtra := make([]byte, extraVanity+common.AddressLength)
	copy(genesisExtra[extraVanity:], genesisSigner.Bytes())

	genspec := &core.Genesis{
		Config:    &chainCfg,
		ExtraData: genesisExtra,
		Coinbase:  genesisSigner,
		Alloc: map[common.Address]core.GenesisAccount{
			validators[0]: {Balance: new(big.Int).Mul(stake, big.NewInt(10))},
			validators[1]: {Balance: new(big.Int).Mul(stake, big.NewInt(10))},
			validators[2]: {Balance: new(big.Int).Mul(stake, big.NewInt(10))},
		},
		BaseFee: big.NewInt(params.InitialBaseFee),
	}

	registerPayload, err := sysaction.MakeSysAction(sysaction.ActionValidatorRegister, nil)
	if err != nil {
		t.Fatalf("make register payload: %v", err)
	}
	txSigner := types.LatestSignerForChainID(chainCfg.ChainID)
	mkRegisterTx := func(key *ecdsa.PrivateKey) *types.Transaction {
		from := crypto.PubkeyToAddress(key.PublicKey)
		to := params.SystemActionAddress
		unsigned := types.NewTx(&types.SignerTx{
			ChainID:    txSigner.ChainID(),
			Nonce:      0,
			To:         &to,
			Value:      new(big.Int).Set(stake),
			Gas:        500_000,
			GasPrice:   big.NewInt(1),
			Data:       registerPayload,
			From:       from,
			SignerType: "secp256k1",
		})
		signed, signErr := types.SignTx(unsigned, txSigner, key)
		if signErr != nil {
			t.Fatalf("sign register tx: %v", signErr)
		}
		return signed
	}
	txRegister := []*types.Transaction{
		mkRegisterTx(keys[0]),
		mkRegisterTx(keys[1]),
		mkRegisterTx(keys[2]),
	}

	// Build 3 blocks:
	// block1: register A/B/C (under genesis validator A).
	// block2 (epoch): signed by old set (A), embeds new validator set from registry.
	// block3: must be signed by in-turn proposer from the new 3-validator set.
	generateDB := rawdb.NewMemoryDatabase()
	generateGenesis := genspec.MustCommit(generateDB)
	buildEngine, err := New(dposCfg, generateDB)
	if err != nil {
		t.Fatalf("New(buildEngine): %v", err)
	}
	blocks, _ := core.GenerateChain(&chainCfg, generateGenesis, buildEngine, generateDB, 3, func(i int, b *core.BlockGen) {
		b.SetExtra(make([]byte, extraVanity))
		switch i {
		case 0:
			b.SetCoinbase(genesisSigner)
			b.SetDifficulty(diffInTurn)
			for _, tx := range txRegister {
				b.AddTx(tx)
			}
		case 1:
			b.SetCoinbase(genesisSigner)
			b.SetDifficulty(diffInTurn)
		case 2:
			b.SetCoinbase(block3Signer)
			if expectedValidators[3%len(expectedValidators)] == block3Signer {
				b.SetDifficulty(diffInTurn)
			} else {
				b.SetDifficulty(diffNoTurn)
			}
		}
	})

	for i, block := range blocks {
		header := block.Header()
		if i > 0 {
			header.ParentHash = blocks[i-1].Hash()
		}
		number := header.Number.Uint64()
		var signer common.Address
		if number <= 2 {
			signer = genesisSigner
		} else {
			signer = block3Signer
		}
		key := keysByAddr[signer]
		if key == nil {
			t.Fatalf("missing key for signer %s", signer.Hex())
		}
		header.Coinbase = signer

		newExtra := make([]byte, extraVanity+extraSeal)
		copy(newExtra[:extraVanity], header.Extra[:extraVanity])
		if number%dposCfg.Epoch == 0 {
			validatorPayloadLen := len(header.Extra) - extraVanity - extraSeal
			if validatorPayloadLen < 0 {
				t.Fatalf("invalid epoch extra length for block %d", number)
			}
			withPayload := make([]byte, extraVanity+validatorPayloadLen+extraSeal)
			copy(withPayload[:extraVanity], header.Extra[:extraVanity])
			if validatorPayloadLen > 0 {
				copy(withPayload[extraVanity:extraVanity+validatorPayloadLen], header.Extra[extraVanity:len(header.Extra)-extraSeal])
			}
			newExtra = withPayload
		}
		header.Extra = newExtra

		sig, signErr := crypto.Sign(SealHash(header).Bytes(), key)
		if signErr != nil {
			t.Fatalf("sign block %d: %v", number, signErr)
		}
		copy(header.Extra[len(header.Extra)-extraSeal:], sig)
		blocks[i] = block.WithSeal(header)
	}

	runDB := rawdb.NewMemoryDatabase()
	genspec.MustCommit(runDB)
	runEngine, err := New(dposCfg, runDB)
	if err != nil {
		t.Fatalf("New(runEngine): %v", err)
	}
	chain, err := core.NewBlockChain(runDB, nil, &chainCfg, runEngine, nil, nil)
	if err != nil {
		t.Fatalf("NewBlockChain: %v", err)
	}
	defer chain.Stop()

	if n, insErr := chain.InsertChain(blocks); insErr != nil {
		t.Fatalf("InsertChain failed at block %d: %v", n+1, insErr)
	}
	if have, want := chain.CurrentBlock().NumberU64(), uint64(3); have != want {
		t.Fatalf("unexpected head number: have %d want %d", have, want)
	}

	epochValidators, err := parseEpochValidators(blocks[1].Header().Extra)
	if err != nil {
		t.Fatalf("parse epoch validators: %v", err)
	}
	if !reflect.DeepEqual(epochValidators, expectedValidators) {
		t.Fatalf("epoch validator list mismatch: have=%v want=%v", epochValidators, expectedValidators)
	}

	head := chain.CurrentBlock()
	snap, err := runEngine.snapshot(chain, head.NumberU64(), head.Hash(), nil)
	if err != nil {
		t.Fatalf("snapshot at head: %v", err)
	}
	if !reflect.DeepEqual(snap.Validators, expectedValidators) {
		t.Fatalf("snapshot validators mismatch: have=%v want=%v", snap.Validators, expectedValidators)
	}

	st, err := chain.State()
	if err != nil {
		t.Fatalf("chain state: %v", err)
	}
	for _, addr := range expectedValidators {
		if status := validator.ReadValidatorStatus(st, addr); status != validator.Active {
			t.Fatalf("validator %s status mismatch: have=%d want=%d", addr.Hex(), status, validator.Active)
		}
		if have := validator.ReadSelfStake(st, addr); have.Cmp(stake) != 0 {
			t.Fatalf("validator %s stake mismatch: have=%s want=%s", addr.Hex(), have.String(), stake.String())
		}
	}
}

func TestDPoSProposalSafetyChecks(t *testing.T) {
	keyHexes := []string{
		"b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291",
		"49a7b37aa6f664591f6f7d8dc908dc7ea0b89f2de0b5261f7fa693596e5361d0",
		"8a1f9a8f3c5e0a8f94c47df7fdc5fb8a0d4e7f3d7d2c24f6f9a16ddbc5c94939",
	}
	keysByAddr := make(map[common.Address]*ecdsa.PrivateKey, len(keyHexes))
	validators := make([]common.Address, 0, len(keyHexes))
	for _, hexKey := range keyHexes {
		key, err := crypto.HexToECDSA(hexKey)
		if err != nil {
			t.Fatalf("invalid fixture private key: %v", err)
		}
		addr := crypto.PubkeyToAddress(key.PublicKey)
		keysByAddr[addr] = key
		validators = append(validators, addr)
	}
	sort.Slice(validators, func(i, j int) bool {
		return validators[i].Hex() < validators[j].Hex()
	})

	dposCfg := &params.DPoSConfig{Period: 1, Epoch: 5000, MaxValidators: 21}
	chainCfg := *params.AllDPoSProtocolChanges
	chainCfg.DPoS = dposCfg

	genesisExtra := make([]byte, extraVanity+len(validators)*common.AddressLength)
	for i, v := range validators {
		copy(genesisExtra[extraVanity+i*common.AddressLength:], v.Bytes())
	}
	genspec := &core.Genesis{
		Config:    &chainCfg,
		ExtraData: genesisExtra,
		Coinbase:  validators[0],
		BaseFee:   big.NewInt(params.InitialBaseFee),
	}

	buildDB := rawdb.NewMemoryDatabase()
	genesis := genspec.MustCommit(buildDB)
	buildEngine, err := New(dposCfg, buildDB)
	if err != nil {
		t.Fatalf("New(buildEngine): %v", err)
	}
	blocks, _ := core.GenerateChain(&chainCfg, genesis, buildEngine, buildDB, 1, func(i int, b *core.BlockGen) {
		signer := validators[1%len(validators)] // block 1 in-turn proposer
		b.SetCoinbase(signer)
		b.SetDifficulty(diffInTurn)
	})
	base := blocks[0].Header()
	baseSigner := validators[1%len(validators)]
	baseKey := keysByAddr[baseSigner]
	if baseKey == nil {
		t.Fatalf("missing key for base signer %s", baseSigner.Hex())
	}

	outsiderKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate outsider key: %v", err)
	}
	outsider := crypto.PubkeyToAddress(outsiderKey.PublicKey)

	type tc struct {
		name        string
		coinbase    common.Address
		difficulty  *big.Int
		signKey     *ecdsa.PrivateKey
		expectedErr error
	}
	tests := []tc{
		{
			name:        "wrong-difficulty",
			coinbase:    baseSigner,
			difficulty:  new(big.Int).Set(diffNoTurn),
			signKey:     baseKey,
			expectedErr: errWrongDifficulty,
		},
		{
			name:        "coinbase-mismatch",
			coinbase:    validators[2%len(validators)],
			difficulty:  new(big.Int).Set(diffInTurn),
			signKey:     baseKey,
			expectedErr: errInvalidCoinbase,
		},
		{
			name:        "unauthorized-validator",
			coinbase:    outsider,
			difficulty:  new(big.Int).Set(diffNoTurn),
			signKey:     outsiderKey,
			expectedErr: errUnauthorizedValidator,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := types.CopyHeader(base)
			header.Coinbase = tt.coinbase
			header.Difficulty = tt.difficulty

			newExtra := make([]byte, extraVanity+extraSeal)
			if len(header.Extra) >= extraVanity {
				copy(newExtra, header.Extra[:extraVanity])
			}
			header.Extra = newExtra

			sig, signErr := crypto.Sign(SealHash(header).Bytes(), tt.signKey)
			if signErr != nil {
				t.Fatalf("sign header: %v", signErr)
			}
			copy(header.Extra[extraVanity:], sig)
			badBlock := blocks[0].WithSeal(header)

			runDB := rawdb.NewMemoryDatabase()
			genspec.MustCommit(runDB)
			runEngine, newErr := New(dposCfg, runDB)
			if newErr != nil {
				t.Fatalf("New(runEngine): %v", newErr)
			}
			chain, chainErr := core.NewBlockChain(runDB, nil, &chainCfg, runEngine, nil, nil)
			if chainErr != nil {
				t.Fatalf("NewBlockChain: %v", chainErr)
			}
			defer chain.Stop()

			if _, insErr := chain.InsertChain([]*types.Block{badBlock}); insErr == nil {
				t.Fatalf("expected insert failure (%v), got nil", tt.expectedErr)
			} else if !errors.Is(insErr, tt.expectedErr) {
				t.Fatalf("unexpected error: have %v want %v", insErr, tt.expectedErr)
			}
		})
	}
}
