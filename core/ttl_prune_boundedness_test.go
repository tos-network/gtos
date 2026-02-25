package core

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/kvstore"
	"github.com/tos-network/gtos/params"
)

func TestTTLPruneLongRunBoundedStorageAndDeterministicRoots(t *testing.T) {
	const (
		nBlocks    = 512
		insertStep = 32
		ttl        = uint64(8)
	)

	config := &params.ChainConfig{
		ChainID: big.NewInt(1337),
		DPoS:    &params.DPoSConfig{PeriodMs: 1000, Epoch: 200, MaxValidators: 21},
	}
	signer := types.LatestSigner(config)

	codeKey, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("code key: %v", err)
	}
	kvKey, err := crypto.HexToECDSA("49a7b37aa6f664591f6f7d8dc908dc7ea0b89f2de0b5261f7fa693596e5361d0")
	if err != nil {
		t.Fatalf("kv key: %v", err)
	}
	codeOwner := crypto.PubkeyToAddress(codeKey.PublicKey)
	kvOwner := crypto.PubkeyToAddress(kvKey.PublicKey)

	gspec := &Genesis{
		Config: config,
		Alloc: GenesisAlloc{
			codeOwner: {Balance: big.NewInt(10_000_000_000_000_000)},
			kvOwner:   {Balance: big.NewInt(10_000_000_000_000_000)},
		},
	}

	buildDB := rawdb.NewMemoryDatabase()
	genesis := gspec.MustCommit(buildDB)

	var (
		codeNonce uint64
		kvNonce   uint64
	)
	blocks, _ := GenerateChain(config, genesis, dpos.NewFaker(), buildDB, nBlocks, func(i int, b *BlockGen) {
		codePayload, payloadErr := EncodeSetCodePayload(ttl, []byte{0x60, byte(i), 0x60, 0x00})
		if payloadErr != nil {
			t.Fatalf("encode setCode payload: %v", payloadErr)
		}
		codeTxUnsigned := types.NewTx(&types.SignerTx{
			ChainID:    signer.ChainID(),
			Nonce:      codeNonce,
			To:         nil,
			Value:      big.NewInt(0),
			Gas:        500_000,
			Data:       codePayload,
			From:       codeOwner,
			SignerType: "secp256k1",
		})
		codeTx, signErr := types.SignTx(codeTxUnsigned, signer, codeKey)
		if signErr != nil {
			t.Fatalf("sign setCode tx: %v", signErr)
		}
		codeNonce++
		b.AddTx(codeTx)

		value := []byte("short")
		if i%2 == 0 {
			value = bytes.Repeat([]byte{byte(i + 1)}, 96)
		}
		kvPayload, payloadErr := kvstore.EncodePutPayload("app", []byte("k"), value, ttl)
		if payloadErr != nil {
			t.Fatalf("encode kv payload: %v", payloadErr)
		}
		kvTx, signErr := signTestSignerTx(signer, kvKey, kvNonce, params.KVRouterAddress, big.NewInt(0), 500_000, big.NewInt(1), kvPayload)
		if signErr != nil {
			t.Fatalf("sign kv tx: %v", signErr)
		}
		kvNonce++
		b.AddTx(kvTx)
	})

	newChain := func() *BlockChain {
		runDB := rawdb.NewMemoryDatabase()
		gspec.MustCommit(runDB)
		chain, newErr := NewBlockChain(runDB, nil, config, dpos.NewFaker(), nil, nil)
		if newErr != nil {
			t.Fatalf("new blockchain: %v", newErr)
		}
		return chain
	}

	chainA := newChain()
	defer chainA.Stop()
	chainB := newChain()
	defer chainB.Stop()

	var (
		maxCodeOwnerSlots uint64
		maxKVOwnerSlots   uint64
	)

	for start := 0; start < nBlocks; start += insertStep {
		end := start + insertStep
		if end > nBlocks {
			end = nBlocks
		}
		chunk := blocks[start:end]
		if n, err := chainA.InsertChain(chunk); err != nil {
			t.Fatalf("insert chainA failed at %d: %v", start+n+1, err)
		}
		if n, err := chainB.InsertChain(chunk); err != nil {
			t.Fatalf("insert chainB failed at %d: %v", start+n+1, err)
		}

		headA := chainA.CurrentBlock()
		headB := chainB.CurrentBlock()
		if headA.NumberU64() != headB.NumberU64() || headA.Hash() != headB.Hash() || headA.Root() != headB.Root() {
			t.Fatalf("node divergence at chunk [%d,%d): A(num=%d hash=%s root=%s) B(num=%d hash=%s root=%s)",
				start, end,
				headA.NumberU64(), headA.Hash().Hex(), headA.Root().Hex(),
				headB.NumberU64(), headB.Hash().Hex(), headB.Root().Hex())
		}

		stateA, err := chainA.State()
		if err != nil {
			t.Fatalf("chainA state: %v", err)
		}
		stateB, err := chainB.State()
		if err != nil {
			t.Fatalf("chainB state: %v", err)
		}
		codeOwnerSlotsA := countStorageSlots(t, stateA, codeOwner)
		kvOwnerSlotsA := countStorageSlots(t, stateA, kvOwner)

		codeOwnerSlotsB := countStorageSlots(t, stateB, codeOwner)
		kvOwnerSlotsB := countStorageSlots(t, stateB, kvOwner)

		if codeOwnerSlotsA != codeOwnerSlotsB || kvOwnerSlotsA != kvOwnerSlotsB {
			t.Fatalf("slot mismatch across nodes at height %d: A(codeOwner=%d kvOwner=%d) B(codeOwner=%d kvOwner=%d)",
				headA.NumberU64(),
				codeOwnerSlotsA, kvOwnerSlotsA,
				codeOwnerSlotsB, kvOwnerSlotsB)
		}

		if codeOwnerSlotsA > maxCodeOwnerSlots {
			maxCodeOwnerSlots = codeOwnerSlotsA
		}
		if kvOwnerSlotsA > maxKVOwnerSlots {
			maxKVOwnerSlots = kvOwnerSlotsA
		}
	}

	// Boundedness: sender-owned slots must stay bounded (lazy expiry, no global index).
	if maxCodeOwnerSlots > 2 {
		t.Fatalf("code owner slots unbounded: have %d want <= 2", maxCodeOwnerSlots)
	}
	if maxKVOwnerSlots > 7 {
		t.Fatalf("kv owner slots unbounded: have %d want <= 7", maxKVOwnerSlots)
	}
}

func countStorageSlots(t *testing.T, st *state.StateDB, addr common.Address) uint64 {
	t.Helper()
	var count uint64
	if err := st.ForEachStorage(addr, func(key, value common.Hash) bool {
		count++
		return true
	}); err != nil {
		t.Fatalf("ForEachStorage(%s): %v", addr.Hex(), err)
	}
	return count
}
