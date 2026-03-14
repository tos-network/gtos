package lease

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

func newTestState() *state.StateDB {
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	s, _ := state.New(common.Hash{}, db, nil)
	return s
}

func newCtx(st *state.StateDB, from common.Address, block uint64) *sysaction.Context {
	return &sysaction.Context{
		From:        from,
		Value:       new(big.Int),
		BlockNumber: new(big.Int).SetUint64(block),
		StateDB:     st,
		ChainConfig: &params.ChainConfig{},
	}
}

func testAddr(b byte) common.Address { return common.Address{b} }

func TestHandleRenewUpdatesMetaAndDeposit(t *testing.T) {
	st := newTestState()
	owner := testAddr(0x11)
	contractAddr := testAddr(0x22)

	initialDeposit, err := DepositFor(128, 100)
	if err != nil {
		t.Fatalf("DepositFor initial: %v", err)
	}
	if _, err := Activate(st, contractAddr, owner, 10, 100, 128, initialDeposit, &params.ChainConfig{}); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	st.AddBalance(params.LeaseRegistryAddress, initialDeposit)

	renewDeposit, err := DepositFor(128, 50)
	if err != nil {
		t.Fatalf("DepositFor renew: %v", err)
	}
	st.AddBalance(owner, renewDeposit)

	wire, err := sysaction.MakeSysAction(sysaction.ActionLeaseRenew, RenewAction{
		ContractAddr: contractAddr,
		DeltaBlocks:  50,
	})
	if err != nil {
		t.Fatalf("MakeSysAction: %v", err)
	}
	ctx := newCtx(st, owner, 20)
	if err := sysaction.ExecuteWithContext(ctx, wire); err != nil {
		t.Fatalf("ExecuteWithContext renew: %v", err)
	}

	meta, ok := ReadMeta(st, contractAddr)
	if !ok {
		t.Fatal("expected lease metadata after renew")
	}
	if meta.ExpireAtBlock != 160 {
		t.Fatalf("ExpireAtBlock: want 160, got %d", meta.ExpireAtBlock)
	}
	wantDeposit := new(big.Int).Add(initialDeposit, renewDeposit)
	if meta.DepositWei.Cmp(wantDeposit) != 0 {
		t.Fatalf("DepositWei: want %v, got %v", wantDeposit, meta.DepositWei)
	}
	if st.GetBalance(params.LeaseRegistryAddress).Cmp(wantDeposit) != 0 {
		t.Fatalf("registry balance: want %v, got %v", wantDeposit, st.GetBalance(params.LeaseRegistryAddress))
	}
}

func TestHandleCloseRefundsOwner(t *testing.T) {
	st := newTestState()
	owner := testAddr(0x33)
	contractAddr := testAddr(0x44)

	deposit, err := DepositFor(256, 200)
	if err != nil {
		t.Fatalf("DepositFor: %v", err)
	}
	if _, err := Activate(st, contractAddr, owner, 10, 200, 256, deposit, &params.ChainConfig{}); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	st.AddBalance(params.LeaseRegistryAddress, deposit)

	wire, err := sysaction.MakeSysAction(sysaction.ActionLeaseClose, CloseAction{
		ContractAddr: contractAddr,
	})
	if err != nil {
		t.Fatalf("MakeSysAction: %v", err)
	}
	ctx := newCtx(st, owner, 25)
	if err := sysaction.ExecuteWithContext(ctx, wire); err != nil {
		t.Fatalf("ExecuteWithContext close: %v", err)
	}

	refund := RefundFor(deposit)
	if st.GetBalance(owner).Cmp(refund) != 0 {
		t.Fatalf("owner refund: want %v, got %v", refund, st.GetBalance(owner))
	}
	meta, ok := ReadMeta(st, contractAddr)
	if !ok {
		t.Fatal("expected lease metadata after close")
	}
	if meta.DepositWei.Sign() != 0 {
		t.Fatalf("DepositWei after close: want 0, got %v", meta.DepositWei)
	}
	if meta.ExpireAtBlock != 25 || meta.GraceUntilBlock != 25 {
		t.Fatalf("close should expire immediately, got expire=%d grace=%d", meta.ExpireAtBlock, meta.GraceUntilBlock)
	}
}
