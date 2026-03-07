package dpos

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"math/big"
	"reflect"
	"sort"
	"testing"

	"github.com/tos-network/gtos/accounts"
	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
	"github.com/tos-network/gtos/validator"
)

func buildSignedSingleValidatorChain(t *testing.T, nBlocks int) (*core.BlockChain, *DPoS, []*types.Block, common.Address, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	pub, priv, signer := testIntegrationEd25519Key(0x41)
	db := rawdb.NewMemoryDatabase()

	genesisExtra := make([]byte, extraVanity+common.AddressLength)
	copy(genesisExtra[extraVanity:], signer.Bytes())

	dposCfg := &params.DPoSConfig{
		PeriodMs:       1000,
		Epoch:          208,
		MaxValidators:  21,
		TurnLength:     params.DPoSTurnLength,
		SealSignerType: params.DPoSSealSignerTypeEd25519,
	}
	chainCfg := *params.AllDPoSProtocolChanges
	chainCfg.DPoS = dposCfg

	genspec := &core.Genesis{
		Config:    &chainCfg,
		ExtraData: genesisExtra,
		Coinbase:  signer,
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
		sig := ed25519.Sign(priv, hash)
		out := make([]byte, 0, ed25519.PublicKeySize+ed25519.SignatureSize)
		out = append(out, pub...)
		out = append(out, sig...)
		return out, nil
	})

	chain, err := core.NewBlockChain(db, nil, &chainCfg, engine, nil, nil)
	if err != nil {
		t.Fatalf("NewBlockChain: %v", err)
	}

	blocks, _ := core.GenerateChain(&chainCfg, genesis, engine, db, nBlocks, func(i int, b *core.BlockGen) {
		b.SetCoinbase(signer)
		b.SetDifficulty(diffInTurn)
	})
	for i, block := range blocks {
		header := block.Header()
		if i > 0 {
			header.ParentHash = blocks[i-1].Hash()
		}
		newExtra := make([]byte, extraVanity+extraSealEd25519)
		if len(header.Extra) >= extraVanity {
			copy(newExtra, header.Extra[:extraVanity])
		}
		header.Extra = newExtra
		signIntegrationHeader(t, engine, header, pub, priv)
		blocks[i] = block.WithSeal(header)
	}
	return chain, engine, blocks, signer, pub, priv
}

func testIntegrationEd25519Key(seed byte) (ed25519.PublicKey, ed25519.PrivateKey, common.Address) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, common.BytesToAddress(crypto.Keccak256(pub))
}

func signIntegrationHeader(t *testing.T, engine *DPoS, header *types.Header, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	sig := ed25519.Sign(priv, engine.SealHash(header).Bytes())
	seal := make([]byte, 0, ed25519.PublicKeySize+ed25519.SignatureSize)
	seal = append(seal, pub...)
	seal = append(seal, sig...)
	copy(header.Extra[len(header.Extra)-extraSealEd25519:], seal)
}

func turnSignerForSlot(validators []common.Address, slot, turnLength uint64) common.Address {
	if len(validators) == 0 || slot == 0 || turnLength == 0 {
		return common.Address{}
	}
	index := ((slot - 1) / turnLength) % uint64(len(validators))
	return validators[index]
}

func turnSignerForGeneratedBlock(validators []common.Address, blockNumber, periodMs, turnLength uint64) common.Address {
	const generatedDPoSTimeStepMs = uint64(10_000)
	if blockNumber == 0 || periodMs == 0 {
		return common.Address{}
	}
	slot := (blockNumber * generatedDPoSTimeStepMs) / periodMs
	if slot == 0 {
		slot = 1
	}
	return turnSignerForSlot(validators, slot, turnLength)
}

func signEd25519SignerTx(t *testing.T, signer types.Signer, from common.Address, priv ed25519.PrivateKey, nonce uint64, to *common.Address, value *big.Int, gas uint64, data []byte) *types.Transaction {
	t.Helper()
	unsigned := types.NewTx(&types.SignerTx{
		ChainID:    signer.ChainID(),
		Nonce:      nonce,
		To:         to,
		Value:      value,
		Gas:        gas,
		Data:       data,
		From:       from,
		SignerType: accountsigner.SignerTypeEd25519,
	})
	hash := signer.Hash(unsigned)
	sig := ed25519.Sign(priv, hash[:])
	return types.NewTx(&types.SignerTx{
		ChainID:    signer.ChainID(),
		Nonce:      nonce,
		To:         to,
		Value:      value,
		Gas:        gas,
		Data:       data,
		From:       from,
		SignerType: accountsigner.SignerTypeEd25519,
		V:          big.NewInt(0),
		R:          new(big.Int).SetBytes(sig[:32]),
		S:          new(big.Int).SetBytes(sig[32:]),
	})
}

func makeAccountSetSignerTx(t *testing.T, signer types.Signer, nonce uint64, from common.Address, pub ed25519.PublicKey, priv ed25519.PrivateKey) *types.Transaction {
	t.Helper()
	payload, err := sysaction.MakeSysAction(sysaction.ActionAccountSetSigner, accountsigner.SetSignerPayload{
		SignerType:  accountsigner.SignerTypeEd25519,
		SignerValue: hexutil.Encode(pub),
	})
	if err != nil {
		t.Fatalf("make account_set_signer payload: %v", err)
	}
	sysTo := params.SystemActionAddress
	return signEd25519SignerTx(t, signer, from, priv, nonce, &sysTo, big.NewInt(0), 500_000, payload)
}

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
	pub, priv, signer := testIntegrationEd25519Key(0x11)

	db := rawdb.NewMemoryDatabase()

	// Genesis Extra: 32-byte vanity + signer address (no seal on block 0).
	genesisExtra := make([]byte, extraVanity+common.AddressLength)
	copy(genesisExtra[extraVanity:], signer.Bytes())

	dposCfg := &params.DPoSConfig{
		PeriodMs:       1000,
		Epoch:          208,
		MaxValidators:  21,
		TurnLength:     params.DPoSTurnLength,
		SealSignerType: params.DPoSSealSignerTypeEd25519,
	}
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
		sig := ed25519.Sign(priv, hash)
		out := make([]byte, 0, ed25519.PublicKeySize+ed25519.SignatureSize)
		out = append(out, pub...)
		out = append(out, sig...)
		return out, nil
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
		// Build a proper Extra: [extraVanity bytes][extraSealEd25519 bytes].
		// This MUST be set before calling SealHash.
		// GenerateChain does not call engine.Prepare(), so Extra may be nil/short.
		newExtra := make([]byte, extraVanity+extraSealEd25519)
		if len(header.Extra) >= extraVanity {
			copy(newExtra, header.Extra[:extraVanity]) // preserve any existing vanity
		}
		header.Extra = newExtra // set before SealHash strips it

		signIntegrationHeader(t, engine, header, pub, priv)

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

func TestCheckpointFinalityCommitsOnCanonicalCarrierImport(t *testing.T) {
	chain, engine, blocks, _, _, _ := buildSignedSingleValidatorChain(t, 2)
	defer chain.Stop()

	engine.SetVoteCallbacks(
		chain,
		nil,
		func(h *types.Header) { chain.SetFinalized(types.NewBlockWithHeader(h)) },
		chain.Config().ChainID,
	)

	finalized := blocks[0]
	carrier := blocks[1]
	vsHash := common.HexToHash("0xfeed")
	engine.stageFinalityResult(carrier.Hash(), finalized.NumberU64(), finalized.Hash(), vsHash)

	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("InsertChain: %v", err)
	}
	have := chain.CurrentFinalizedBlock()
	if have == nil {
		t.Fatal("missing finalized block after canonical carrier import")
	}
	if have.Hash() != finalized.Hash() || have.NumberU64() != finalized.NumberU64() {
		t.Fatalf("finalized mismatch: have(num=%d hash=%s) want(num=%d hash=%s)",
			have.NumberU64(), have.Hash().Hex(), finalized.NumberU64(), finalized.Hash().Hex())
	}
	if got := engine.FinalizedValidatorSetHash(); got != vsHash {
		t.Fatalf("validatorSetHash mismatch: have %s want %s", got.Hex(), vsHash.Hex())
	}
}

func TestDPoSThreeValidatorStabilityGate(t *testing.T) {
	const (
		nBlocks     = 1024
		insertBatch = 64
	)

	// Deterministic 3-validator fixture.
	type validatorKey struct {
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	}
	keysByAddr := make(map[common.Address]validatorKey, 3)
	validators := make([]common.Address, 0, 3)
	for _, seed := range []byte{0x21, 0x22, 0x23} {
		pub, priv, addr := testIntegrationEd25519Key(seed)
		keysByAddr[addr] = validatorKey{pub: pub, priv: priv}
		validators = append(validators, addr)
	}
	sort.Slice(validators, func(i, j int) bool {
		return validators[i].Hex() < validators[j].Hex()
	})

	dposCfg := &params.DPoSConfig{
		PeriodMs:       1000,
		Epoch:          5008,
		MaxValidators:  21,
		TurnLength:     params.DPoSTurnLength,
		SealSignerType: params.DPoSSealSignerTypeEd25519,
	}
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
		signer := turnSignerForGeneratedBlock(validators, number, dposCfg.PeriodMs, dposCfg.TurnLength)
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
		signer := turnSignerForGeneratedBlock(validators, number, dposCfg.PeriodMs, dposCfg.TurnLength)
		entry, ok := keysByAddr[signer]
		if !ok {
			t.Fatalf("missing key for signer %s", signer.Hex())
		}
		header.Coinbase = signer
		newExtra := make([]byte, extraVanity+extraSealEd25519)
		if len(header.Extra) >= extraVanity {
			copy(newExtra, header.Extra[:extraVanity])
		}
		header.Extra = newExtra
		signIntegrationHeader(t, buildEngine, header, entry.pub, entry.priv)
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
	type validatorKey struct {
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	}
	keysByAddr := make(map[common.Address]validatorKey, 3)
	validators := make([]common.Address, 0, 3)
	for _, seed := range []byte{0x31, 0x32, 0x33} {
		pub, priv, addr := testIntegrationEd25519Key(seed)
		keysByAddr[addr] = validatorKey{pub: pub, priv: priv}
		validators = append(validators, addr)
	}
	expectedValidators := append([]common.Address(nil), validators...)
	sort.Slice(expectedValidators, func(i, j int) bool {
		return bytes.Compare(expectedValidators[i][:], expectedValidators[j][:]) < 0
	})

	dposCfg := &params.DPoSConfig{
		PeriodMs:       1000,
		Epoch:          3,
		MaxValidators:  21,
		TurnLength:     1,
		SealSignerType: params.DPoSSealSignerTypeEd25519,
	}
	chainCfg := *params.AllDPoSProtocolChanges
	chainCfg.DPoS = dposCfg

	genesisSigner := validators[0]
	block4Signer := turnSignerForGeneratedBlock(expectedValidators, 4, dposCfg.PeriodMs, dposCfg.TurnLength)
	if block4Signer == genesisSigner {
		for _, v := range expectedValidators {
			if v != genesisSigner {
				block4Signer = v
				break
			}
		}
	}
	if block4Signer == genesisSigner {
		t.Fatalf("failed to pick non-recent signer for block4")
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
	mkRegisterTx := func(from common.Address, priv ed25519.PrivateKey) *types.Transaction {
		to := params.SystemActionAddress
		return signEd25519SignerTx(t, txSigner, from, priv, 1, &to, new(big.Int).Set(stake), 500_000, registerPayload)
	}
	txBootstrap := make([]*types.Transaction, 0, len(validators))
	txRegister := make([]*types.Transaction, 0, len(validators))
	for _, addr := range validators {
		entry := keysByAddr[addr]
		txBootstrap = append(txBootstrap, makeAccountSetSignerTx(t, txSigner, 0, addr, entry.pub, entry.priv))
		txRegister = append(txRegister, mkRegisterTx(addr, entry.priv))
	}

	// Build 4 blocks:
	// block1: bootstrap ed25519 signer metadata for A/B/C.
	// block2: register A/B/C under those signer bindings.
	// block3 (epoch): signed by old set (A), embeds new validator set from parent state.
	// block4: must be signed by a proposer from the new 3-validator set.
	generateDB := rawdb.NewMemoryDatabase()
	generateGenesis := genspec.MustCommit(generateDB)
	buildEngine, err := New(dposCfg, generateDB)
	if err != nil {
		t.Fatalf("New(buildEngine): %v", err)
	}
	blocks, _ := core.GenerateChain(&chainCfg, generateGenesis, buildEngine, generateDB, 4, func(i int, b *core.BlockGen) {
		b.SetExtra(make([]byte, extraVanity))
		switch i {
		case 0:
			b.SetCoinbase(genesisSigner)
			b.SetDifficulty(diffInTurn)
			for _, tx := range txBootstrap {
				b.AddTx(tx)
			}
		case 1:
			b.SetCoinbase(genesisSigner)
			b.SetDifficulty(diffInTurn)
			for _, tx := range txRegister {
				b.AddTx(tx)
			}
		case 2:
			b.SetCoinbase(genesisSigner)
			b.SetDifficulty(diffInTurn)
		case 3:
			b.SetCoinbase(block4Signer)
			if turnSignerForGeneratedBlock(expectedValidators, 4, dposCfg.PeriodMs, dposCfg.TurnLength) == block4Signer {
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
		signer := genesisSigner
		if number == 4 {
			signer = block4Signer
		}
		entry, ok := keysByAddr[signer]
		if !ok {
			t.Fatalf("missing key for signer %s", signer.Hex())
		}
		header.Coinbase = signer

		newExtra := make([]byte, extraVanity+extraSealEd25519)
		copy(newExtra[:extraVanity], header.Extra[:extraVanity])
		if number%dposCfg.Epoch == 0 {
			validatorPayloadLen := len(header.Extra) - extraVanity - extraSealEd25519
			if validatorPayloadLen < 0 {
				t.Fatalf("invalid epoch extra length for block %d", number)
			}
			withPayload := make([]byte, extraVanity+validatorPayloadLen+extraSealEd25519)
			copy(withPayload[:extraVanity], header.Extra[:extraVanity])
			if validatorPayloadLen > 0 {
				copy(withPayload[extraVanity:extraVanity+validatorPayloadLen], header.Extra[extraVanity:len(header.Extra)-extraSealEd25519])
			}
			newExtra = withPayload
		}
		header.Extra = newExtra

		signIntegrationHeader(t, buildEngine, header, entry.pub, entry.priv)
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
	if have, want := chain.CurrentBlock().NumberU64(), uint64(4); have != want {
		t.Fatalf("unexpected head number: have %d want %d", have, want)
	}

	epochValidators, err := parseEpochValidators(blocks[2].Header().Extra, dposCfg, false)
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
	type validatorKey struct {
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	}
	keysByAddr := make(map[common.Address]validatorKey, 3)
	validators := make([]common.Address, 0, 3)
	for _, seed := range []byte{0x41, 0x42, 0x43} {
		pub, priv, addr := testIntegrationEd25519Key(seed)
		keysByAddr[addr] = validatorKey{pub: pub, priv: priv}
		validators = append(validators, addr)
	}
	sort.Slice(validators, func(i, j int) bool {
		return validators[i].Hex() < validators[j].Hex()
	})

	dposCfg := &params.DPoSConfig{
		PeriodMs:       1000,
		Epoch:          5008,
		MaxValidators:  21,
		TurnLength:     params.DPoSTurnLength,
		SealSignerType: params.DPoSSealSignerTypeEd25519,
	}
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
		signer := turnSignerForGeneratedBlock(validators, 1, dposCfg.PeriodMs, dposCfg.TurnLength) // block 1 in-turn proposer
		b.SetCoinbase(signer)
		b.SetDifficulty(diffInTurn)
	})
	base := blocks[0].Header()
	baseSigner := turnSignerForGeneratedBlock(validators, 1, dposCfg.PeriodMs, dposCfg.TurnLength)
	baseEntry, ok := keysByAddr[baseSigner]
	if !ok {
		t.Fatalf("missing key for base signer %s", baseSigner.Hex())
	}

	outsiderPub, outsiderPriv, outsider := testIntegrationEd25519Key(0x44)

	type tc struct {
		name        string
		coinbase    common.Address
		difficulty  *big.Int
		signPub     ed25519.PublicKey
		signPriv    ed25519.PrivateKey
		expectedErr error
	}
	tests := []tc{
		{
			name:        "wrong-difficulty",
			coinbase:    baseSigner,
			difficulty:  new(big.Int).Set(diffNoTurn),
			signPub:     baseEntry.pub,
			signPriv:    baseEntry.priv,
			expectedErr: errWrongDifficulty,
		},
		{
			name:        "coinbase-mismatch",
			coinbase:    validators[1],
			difficulty:  new(big.Int).Set(diffInTurn),
			signPub:     baseEntry.pub,
			signPriv:    baseEntry.priv,
			expectedErr: errInvalidCoinbase,
		},
		{
			name:        "unauthorized-validator",
			coinbase:    outsider,
			difficulty:  new(big.Int).Set(diffNoTurn),
			signPub:     outsiderPub,
			signPriv:    outsiderPriv,
			expectedErr: errUnauthorizedValidator,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := types.CopyHeader(base)
			header.Coinbase = tt.coinbase
			header.Difficulty = tt.difficulty

			newExtra := make([]byte, extraVanity+extraSealEd25519)
			if len(header.Extra) >= extraVanity {
				copy(newExtra, header.Extra[:extraVanity])
			}
			header.Extra = newExtra

			signIntegrationHeader(t, buildEngine, header, tt.signPub, tt.signPriv)
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

func TestDPoSEpochExtraUsesParentState(t *testing.T) {
	genesisPub, genesisPriv, genesisSigner := testIntegrationEd25519Key(0x51)
	registrantPub, registrantPriv, registrant := testIntegrationEd25519Key(0x52)
	stake := new(big.Int).Set(params.DPoSMinValidatorStake)

	dposCfg := &params.DPoSConfig{
		PeriodMs:       1000,
		Epoch:          3,
		MaxValidators:  21,
		TurnLength:     1,
		SealSignerType: params.DPoSSealSignerTypeEd25519,
	}
	chainCfg := *params.AllDPoSProtocolChanges
	chainCfg.DPoS = dposCfg

	genesisExtra := make([]byte, extraVanity+common.AddressLength)
	copy(genesisExtra[extraVanity:], genesisSigner.Bytes())
	genspec := &core.Genesis{
		Config:    &chainCfg,
		ExtraData: genesisExtra,
		Coinbase:  genesisSigner,
		Alloc: map[common.Address]core.GenesisAccount{
			genesisSigner: {Balance: new(big.Int).Mul(big.NewInt(10), stake)},
			registrant:    {Balance: new(big.Int).Mul(big.NewInt(10), stake)},
		},
		BaseFee: big.NewInt(params.InitialBaseFee),
	}

	registerPayload, err := sysaction.MakeSysAction(sysaction.ActionValidatorRegister, nil)
	if err != nil {
		t.Fatalf("make register payload: %v", err)
	}
	txSigner := types.LatestSignerForChainID(chainCfg.ChainID)
	registerTo := params.SystemActionAddress
	bootstrapTx := makeAccountSetSignerTx(t, txSigner, 0, registrant, registrantPub, registrantPriv)
	registerTx := signEd25519SignerTx(t, txSigner, registrant, registrantPriv, 1, &registerTo, new(big.Int).Set(stake), 500_000, registerPayload)

	buildDB := rawdb.NewMemoryDatabase()
	genesis := genspec.MustCommit(buildDB)
	buildEngine, err := New(dposCfg, buildDB)
	if err != nil {
		t.Fatalf("New(buildEngine): %v", err)
	}
	blocks, _ := core.GenerateChain(&chainCfg, genesis, buildEngine, buildDB, 3, func(i int, b *core.BlockGen) {
		b.SetExtra(make([]byte, extraVanity))
		b.SetCoinbase(genesisSigner)
		b.SetDifficulty(diffInTurn)
		if i == 0 {
			b.AddTx(bootstrapTx)
		}
		if i == 2 {
			b.AddTx(registerTx)
		}
	})
	for i, block := range blocks {
		header := block.Header()
		if i > 0 {
			header.ParentHash = blocks[i-1].Hash()
		}
		newExtra := make([]byte, extraVanity+extraSealEd25519)
		copy(newExtra[:extraVanity], header.Extra[:extraVanity])
		if header.Number.Uint64()%dposCfg.Epoch == 0 {
			validatorPayloadLen := len(header.Extra) - extraVanity - extraSealEd25519
			withPayload := make([]byte, extraVanity+validatorPayloadLen+extraSealEd25519)
			copy(withPayload[:extraVanity], header.Extra[:extraVanity])
			copy(withPayload[extraVanity:extraVanity+validatorPayloadLen], header.Extra[extraVanity:len(header.Extra)-extraSealEd25519])
			newExtra = withPayload
		}
		header.Extra = newExtra
		signIntegrationHeader(t, buildEngine, header, genesisPub, genesisPriv)
		blocks[i] = block.WithSeal(header)
	}

	epochValidators, err := parseEpochValidators(blocks[2].Header().Extra, dposCfg, false)
	if err != nil {
		t.Fatalf("parse epoch validators: %v", err)
	}
	if want := []common.Address{genesisSigner}; !reflect.DeepEqual(epochValidators, want) {
		t.Fatalf("epoch validator list must come from parent state: have=%v want=%v", epochValidators, want)
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
	if _, err := chain.InsertChain(blocks[:2]); err != nil {
		t.Fatalf("InsertChain(prefix): %v", err)
	}
	if err := runEngine.VerifyHeader(chain, blocks[2].Header(), true); err != nil {
		t.Fatalf("VerifyHeader(valid epoch block): %v", err)
	}

	tampered := types.CopyHeader(blocks[2].Header())
	payloadValidators := []common.Address{genesisSigner, registrant}
	sort.Sort(addressAscending(payloadValidators))
	tampered.Extra = make([]byte, extraVanity+len(payloadValidators)*common.AddressLength+extraSealEd25519)
	copy(tampered.Extra[:extraVanity], blocks[2].Header().Extra[:extraVanity])
	for i, addr := range payloadValidators {
		copy(tampered.Extra[extraVanity+i*common.AddressLength:], addr.Bytes())
	}
	signIntegrationHeader(t, buildEngine, tampered, genesisPub, genesisPriv)
	tamperedBlock := blocks[2].WithSeal(tampered)

	if _, err := chain.InsertChain([]*types.Block{tamperedBlock}); err == nil {
		t.Fatal("expected insert failure for epoch extra derived from in-block state")
	}
}
