package core

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/params"
)

func TestRestartRecoversLatestFinalizedAndResumesImport(t *testing.T) {
	config := &params.ChainConfig{
		ChainID: big.NewInt(1),
		DPoS:    &params.DPoSConfig{Period: 3, Epoch: 200, MaxValidators: 21},
	}
	gspec := &Genesis{
		Config: config,
		Alloc:  GenesisAlloc{},
	}
	db := rawdb.NewMemoryDatabase()
	gspec.MustCommit(db)

	chain, err := NewBlockChain(db, nil, config, dpos.NewFaker(), nil, nil)
	if err != nil {
		t.Fatalf("new blockchain: %v", err)
	}

	// Build import blocks from an isolated build DB to force full processing on runtime DB.
	buildDB := rawdb.NewMemoryDatabase()
	buildGenesis := gspec.MustCommit(buildDB)
	blocks, _ := GenerateChain(config, buildGenesis, dpos.NewFaker(), buildDB, 12, func(int, *BlockGen) {})
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("insert initial chain: %v", err)
	}

	headBefore := chain.CurrentBlock()
	if headBefore.NumberU64() != 12 {
		t.Fatalf("unexpected head before restart: have %d want 12", headBefore.NumberU64())
	}
	finalizedBefore := chain.GetBlockByNumber(9)
	if finalizedBefore == nil {
		t.Fatalf("missing finalized candidate at height 9")
	}
	chain.SetFinalized(finalizedBefore)
	chain.Stop()

	reopened, err := NewBlockChain(db, nil, config, dpos.NewFaker(), nil, nil)
	if err != nil {
		t.Fatalf("reopen blockchain: %v", err)
	}
	defer reopened.Stop()

	headAfter := reopened.CurrentBlock()
	if headAfter.Hash() != headBefore.Hash() || headAfter.NumberU64() != headBefore.NumberU64() {
		t.Fatalf("head mismatch after restart: have(num=%d hash=%s) want(num=%d hash=%s)",
			headAfter.NumberU64(), headAfter.Hash().Hex(), headBefore.NumberU64(), headBefore.Hash().Hex())
	}
	finalizedAfter := reopened.CurrentFinalizedBlock()
	if finalizedAfter == nil {
		t.Fatalf("finalized block missing after restart")
	}
	if finalizedAfter.Hash() != finalizedBefore.Hash() || finalizedAfter.NumberU64() != finalizedBefore.NumberU64() {
		t.Fatalf("finalized mismatch after restart: have(num=%d hash=%s) want(num=%d hash=%s)",
			finalizedAfter.NumberU64(), finalizedAfter.Hash().Hex(), finalizedBefore.NumberU64(), finalizedBefore.Hash().Hex())
	}
	safeAfter := reopened.CurrentSafeBlock()
	if safeAfter == nil || safeAfter.Hash() != finalizedBefore.Hash() {
		t.Fatalf("safe block mismatch after restart: have=%v want=%s", safeAfter, finalizedBefore.Hash().Hex())
	}

	// Recovery drill: continue importing on top of recovered head.
	moreBlocks, _ := GenerateChain(config, headAfter, dpos.NewFaker(), db, 3, func(int, *BlockGen) {})
	if _, err := reopened.InsertChain(moreBlocks); err != nil {
		t.Fatalf("insert post-restart chain: %v", err)
	}
	if have, want := reopened.CurrentBlock().NumberU64(), uint64(15); have != want {
		t.Fatalf("unexpected head after post-restart import: have %d want %d", have, want)
	}
}
