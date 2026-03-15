package lease

import (
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/params"
)

func leaseTestConfig(epoch uint64) *params.ChainConfig {
	return &params.ChainConfig{
		DPoS: &params.DPoSConfig{Epoch: epoch},
	}
}

func activateLeaseForPruneTest(t *testing.T, st *state.StateDB, addr common.Address, owner common.Address, cfg *params.ChainConfig) Meta {
	t.Helper()

	deposit, err := DepositFor(32, 5)
	if err != nil {
		t.Fatalf("DepositFor: %v", err)
	}
	meta, err := Activate(st, addr, owner, 10, 5, 32, deposit, cfg)
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	st.CreateAccount(addr)
	st.SetNonce(addr, 1)
	st.SetCode(addr, []byte{0x01})
	st.AddBalance(params.LeaseRegistryAddress, deposit)
	return meta
}

func TestEffectiveStatusBecomesPrunableAtScheduledEpoch(t *testing.T) {
	st := newTestState()
	cfg := leaseTestConfig(10)
	meta := activateLeaseForPruneTest(t, st, testAddr(0x51), testAddr(0x61), cfg)

	if got := EffectiveStatus(meta, 24, cfg); got != StatusFrozen {
		t.Fatalf("status at 24: want %v, got %v", StatusFrozen, got)
	}
	if got := EffectiveStatus(meta, 29, cfg); got != StatusExpired {
		t.Fatalf("status at 29: want %v, got %v", StatusExpired, got)
	}
	if got := EffectiveStatus(meta, 30, cfg); got != StatusPrunable {
		t.Fatalf("status at 30: want %v, got %v", StatusPrunable, got)
	}
}

func TestRunPruneSweepRespectsBudget(t *testing.T) {
	st := newTestState()
	cfg := leaseTestConfig(10)
	firstAddr := testAddr(0x71)
	secondAddr := testAddr(0x72)
	owner := testAddr(0x81)

	activateLeaseForPruneTest(t, st, firstAddr, owner, cfg)
	secondMeta := activateLeaseForPruneTest(t, st, secondAddr, owner, cfg)

	runPruneSweep(st, 30, cfg, 1)

	if _, ok := ReadMeta(st, firstAddr); ok {
		t.Fatal("expected first lease to be pruned in first budgeted sweep")
	}
	if _, ok := ReadTombstone(st, firstAddr); !ok {
		t.Fatal("expected first lease tombstone after pruning")
	}
	if _, ok := ReadMeta(st, secondAddr); !ok {
		t.Fatal("expected second lease to remain pending after first budgeted sweep")
	}
	if got := EffectiveStatus(secondMeta, 30, cfg); got != StatusPrunable {
		t.Fatalf("second lease status at 30: want %v, got %v", StatusPrunable, got)
	}
	if got := ReadPruneCursor(st, secondMeta.ScheduledPruneEpoch); got != 1 {
		t.Fatalf("prune cursor after first sweep: want 1, got %d", got)
	}

	runPruneSweep(st, 40, cfg, 1)

	if _, ok := ReadMeta(st, secondAddr); ok {
		t.Fatal("expected second lease to be pruned in second budgeted sweep")
	}
	if _, ok := ReadTombstone(st, secondAddr); !ok {
		t.Fatal("expected second lease tombstone after second sweep")
	}
}
