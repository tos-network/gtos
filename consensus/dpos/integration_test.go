package dpos

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/accounts"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
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
