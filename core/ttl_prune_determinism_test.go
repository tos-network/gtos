package core

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/kvstore"
	"github.com/tos-network/gtos/params"
)

func TestTTLPruneWindowDeterministicRootsAcrossNodes(t *testing.T) {
	const (
		blockCodeWrite   = uint64(100)
		blockKVWrite     = uint64(101)
		blockCodeRewrite = uint64(107)
		blockKVRewrite   = uint64(108)
	)
	var (
		codeOwner = common.HexToAddress("0x1000000000000000000000000000000000000001")
		kvOwner   = common.HexToAddress("0x1000000000000000000000000000000000000002")
		coinbase  = common.HexToAddress("0x2000000000000000000000000000000000000002")
		cfg       = &params.ChainConfig{ChainID: big.NewInt(1337)}
		gasLimit  = uint64(500_000)
	)

	left := newTTLDeterminismState(t, codeOwner, kvOwner)
	right := newTTLDeterminismState(t, codeOwner, kvOwner)
	assertStateRootEqual(t, left, right, "initial")

	codeV1 := []byte{0x60, 0x01, 0x60, 0x00}
	setCodeV1, err := EncodeSetCodePayload(3, codeV1) // expire at 103
	if err != nil {
		t.Fatalf("encode setCode v1: %v", err)
	}
	applyTTLMessage(t, left, cfg, coinbase, blockCodeWrite, newTTLMessage(codeOwner, nil, 0, gasLimit, setCodeV1))
	applyTTLMessage(t, right, cfg, coinbase, blockCodeWrite, newTTLMessage(codeOwner, nil, 0, gasLimit, setCodeV1))

	toKV := params.KVRouterAddress
	kvV1, err := kvstore.EncodePutPayload("app", []byte("k"), bytes.Repeat([]byte{0xAB}, 96), 5) // expire at 106
	if err != nil {
		t.Fatalf("encode kv v1: %v", err)
	}
	applyTTLMessage(t, left, cfg, coinbase, blockKVWrite, newTTLMessage(kvOwner, &toKV, 0, gasLimit, kvV1))
	applyTTLMessage(t, right, cfg, coinbase, blockKVWrite, newTTLMessage(kvOwner, &toKV, 0, gasLimit, kvV1))

	rootBeforeWindow := assertStateRootEqual(t, left, right, "before prune window")

	codeExpire := stateWordToUint64(left.GetState(codeOwner, SetCodeExpireAtSlot))
	if codeExpire != 103 {
		t.Fatalf("unexpected code expireAt: have %d want %d", codeExpire, 103)
	}
	kvMeta := kvstore.GetMeta(left, kvOwner, "app", []byte("k"))
	if !kvMeta.Exists || kvMeta.ExpireAt != 106 {
		t.Fatalf("unexpected kv meta before window: %+v", kvMeta)
	}
	if blockCodeRewrite <= codeExpire || blockKVRewrite <= kvMeta.ExpireAt {
		t.Fatalf("rewrite blocks must be after expiry, codeExpire=%d kvExpire=%d", codeExpire, kvMeta.ExpireAt)
	}

	codeV2 := []byte{0x60, 0x02, 0x60, 0x03}
	setCodeV2, err := EncodeSetCodePayload(4, codeV2) // block 107 -> expire at 111
	if err != nil {
		t.Fatalf("encode setCode v2: %v", err)
	}
	applyTTLMessage(t, left, cfg, coinbase, blockCodeRewrite, newTTLMessage(codeOwner, nil, 1, gasLimit, setCodeV2))
	applyTTLMessage(t, right, cfg, coinbase, blockCodeRewrite, newTTLMessage(codeOwner, nil, 1, gasLimit, setCodeV2))

	// Overwrite with a shorter value to exercise deterministic remainder clearing.
	kvV2, err := kvstore.EncodePutPayload("app", []byte("k"), []byte("short"), 6) // block 108 -> expire at 114
	if err != nil {
		t.Fatalf("encode kv v2: %v", err)
	}
	applyTTLMessage(t, left, cfg, coinbase, blockKVRewrite, newTTLMessage(kvOwner, &toKV, 1, gasLimit, kvV2))
	applyTTLMessage(t, right, cfg, coinbase, blockKVRewrite, newTTLMessage(kvOwner, &toKV, 1, gasLimit, kvV2))

	rootAfterWindow := assertStateRootEqual(t, left, right, "after prune window")
	if rootAfterWindow == rootBeforeWindow {
		t.Fatalf("state root did not change across prune window rewrite, root=%s", rootAfterWindow.Hex())
	}

	if have, want := stateWordToUint64(left.GetState(codeOwner, SetCodeCreatedAtSlot)), uint64(107); have != want {
		t.Fatalf("left code createdAt mismatch: have %d want %d", have, want)
	}
	if have, want := stateWordToUint64(left.GetState(codeOwner, SetCodeExpireAtSlot)), uint64(111); have != want {
		t.Fatalf("left code expireAt mismatch: have %d want %d", have, want)
	}
	if have, want := stateWordToUint64(right.GetState(codeOwner, SetCodeCreatedAtSlot)), uint64(107); have != want {
		t.Fatalf("right code createdAt mismatch: have %d want %d", have, want)
	}
	if have, want := stateWordToUint64(right.GetState(codeOwner, SetCodeExpireAtSlot)), uint64(111); have != want {
		t.Fatalf("right code expireAt mismatch: have %d want %d", have, want)
	}

	leftKV := kvstore.GetMeta(left, kvOwner, "app", []byte("k"))
	rightKV := kvstore.GetMeta(right, kvOwner, "app", []byte("k"))
	if leftKV != rightKV {
		t.Fatalf("kv meta mismatch left=%+v right=%+v", leftKV, rightKV)
	}
	if !leftKV.Exists || leftKV.CreatedAt != 108 || leftKV.ExpireAt != 114 {
		t.Fatalf("unexpected kv meta after window: %+v", leftKV)
	}
}

func newTTLDeterminismState(t *testing.T, funded ...common.Address) *state.StateDB {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	statedb, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
	if err != nil {
		t.Fatalf("create statedb: %v", err)
	}
	for _, addr := range funded {
		statedb.SetBalance(addr, big.NewInt(1))
	}
	return statedb
}

func newTTLMessage(from common.Address, to *common.Address, nonce, gas uint64, data []byte) types.Message {
	zero := big.NewInt(0)
	return types.NewMessage(
		from,
		to,
		nonce,
		zero,
		gas,
		zero,
		zero,
		zero,
		data,
		nil,
		false,
	)
}

func ttlBlockContext(block uint64, coinbase common.Address) vm.BlockContext {
	return vm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		Coinbase:    coinbase,
		BlockNumber: new(big.Int).SetUint64(block),
		GasLimit:    30_000_000,
	}
}

func applyTTLMessage(t *testing.T, statedb *state.StateDB, cfg *params.ChainConfig, coinbase common.Address, block uint64, msg types.Message) {
	t.Helper()
	gp := new(GasPool).AddGas(msg.Gas())
	result, err := ApplyMessage(ttlBlockContext(block, coinbase), cfg, msg, gp, statedb)
	if err != nil {
		t.Fatalf("apply message at block %d: %v", block, err)
	}
	if result.Err != nil {
		t.Fatalf("execution failed at block %d: %v", block, result.Err)
	}
}

func assertStateRootEqual(t *testing.T, left, right *state.StateDB, label string) common.Hash {
	t.Helper()
	leftRoot := left.IntermediateRoot(true)
	rightRoot := right.IntermediateRoot(true)
	if leftRoot != rightRoot {
		t.Fatalf("%s root mismatch: left=%s right=%s", label, leftRoot.Hex(), rightRoot.Hex())
	}
	return leftRoot
}
