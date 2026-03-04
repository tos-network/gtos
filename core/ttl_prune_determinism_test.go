package core

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/params"
)

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
