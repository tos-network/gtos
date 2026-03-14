package tosapi

import (
	"context"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/lease"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/rpc"
	"github.com/tos-network/gtos/sysaction"
)

func TestBuildLeaseDeployTxBuildsSystemActionTx(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	from := common.HexToAddress("0x85b1F044Bab6D30F3A19c1501563915E194D8CFBa1943570603f7606a3115508")
	value := (*hexutil.Big)(big.NewInt(77))
	res, err := api.BuildLeaseDeployTx(context.Background(), RPCLeaseDeployArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: from},
		Code:            hexutil.Bytes{0x01, 0x02, 0x03},
		LeaseBlocks:     hexutil.Uint64(100),
		Value:           value,
	})
	if err != nil {
		t.Fatalf("unexpected build error: %v", err)
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(res.Raw); err != nil {
		t.Fatalf("failed to decode raw tx: %v", err)
	}
	if tx.To() == nil || *tx.To() != params.SystemActionAddress {
		t.Fatalf("unexpected tx to: %v", tx.To())
	}
	if tx.Value().Cmp(big.NewInt(77)) != 0 {
		t.Fatalf("expected forwarded value 77, got %s", tx.Value())
	}
	wantGas, err := estimateSystemActionGas(tx.Data())
	if err != nil {
		t.Fatalf("failed to estimate gas: %v", err)
	}
	if tx.Gas() != wantGas {
		t.Fatalf("unexpected gas: have %d want %d", tx.Gas(), wantGas)
	}
	sa, err := sysaction.Decode(tx.Data())
	if err != nil {
		t.Fatalf("failed to decode sysaction: %v", err)
	}
	if sa.Action != sysaction.ActionLeaseDeploy {
		t.Fatalf("unexpected action: %s", sa.Action)
	}
	var payload lease.DeployAction
	if err := sysaction.DecodePayload(sa, &payload); err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	if payload.LeaseBlocks != 100 || len(payload.Code) != 3 {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestBuildLeaseRenewTxBuildsZeroValueSystemActionTx(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	from := common.HexToAddress("0xAe6856AAc48989adf1E084945CbDD86a2fa8dc4bddD8a8f69DBa48572Eec07FB")
	contractAddr := common.HexToAddress("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	res, err := api.BuildLeaseRenewTx(context.Background(), RPCLeaseRenewArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: from},
		ContractAddr:    contractAddr,
		DeltaBlocks:     hexutil.Uint64(50),
	})
	if err != nil {
		t.Fatalf("unexpected build error: %v", err)
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(res.Raw); err != nil {
		t.Fatalf("failed to decode raw tx: %v", err)
	}
	if tx.Value().Sign() != 0 {
		t.Fatalf("expected zero value tx, got %s", tx.Value())
	}
	sa, err := sysaction.Decode(tx.Data())
	if err != nil {
		t.Fatalf("failed to decode sysaction: %v", err)
	}
	if sa.Action != sysaction.ActionLeaseRenew {
		t.Fatalf("unexpected action: %s", sa.Action)
	}
}

func TestGetLeaseReadsActiveLeaseMetadata(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	addr := common.HexToAddress("0xf81c536380b2dd5ef5c4ae95e1fae9b4fab2f5726677ecfa912d96b0b683e6a9")
	owner := common.HexToAddress("0x1111111111111111111111111111111111111111111111111111111111111111")
	deposit := big.NewInt(12345)
	if _, err := lease.Activate(st, addr, owner, 10, 100, 256, deposit, &params.ChainConfig{}); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	api := NewTOSAPI(&getSignerBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(20)},
	})
	got, err := api.GetLease(context.Background(), addr, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected lease record")
	}
	if got.LeaseOwner != owner || got.Status != "active" {
		t.Fatalf("unexpected lease record: %+v", got)
	}
	if got.DepositWei == nil || (*big.Int)(got.DepositWei).Cmp(deposit) != 0 {
		t.Fatalf("unexpected deposit: %v", got.DepositWei)
	}
}

func TestGetLeaseReadsTombstone(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	addr := common.HexToAddress("0xb422a2991bf0212aae4f7493ff06ad5d076fa274b49c297f3fe9e29b5ba9aadc")
	codeHash := common.HexToHash("0xabc")
	lease.WriteTombstone(st, addr, lease.Tombstone{LastCodeHash: codeHash, ExpiredAtBlock: 77})

	api := NewTOSAPI(&getSignerBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(100)},
	})
	block := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	got, err := api.GetLease(context.Background(), addr, &block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || !got.Tombstoned || got.Status != "tombstoned" {
		t.Fatalf("unexpected tombstone record: %+v", got)
	}
	if got.TombstoneCodeHash != codeHash || uint64(got.TombstoneExpiredAt) != 77 {
		t.Fatalf("unexpected tombstone fields: %+v", got)
	}
}
