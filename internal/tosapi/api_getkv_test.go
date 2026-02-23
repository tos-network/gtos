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
	"github.com/tos-network/gtos/kvstore"
	"github.com/tos-network/gtos/rpc"
)

type getKVBackendMock struct {
	*backendMock
	st   *state.StateDB
	head *types.Header
}

func (b *getKVBackendMock) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	return b.st, b.head, nil
}

func TestGetKVRespectsExpireAt(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	owner := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	kvstore.Put(st, owner, "ns", []byte("k"), []byte("value"), 100, 200)

	api := NewTOSAPI(&getKVBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(199)},
	})
	got, err := api.GetKV(context.Background(), owner, "ns", hexutil.Bytes("k"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got.Value) != "value" {
		t.Fatalf("unexpected value: %s", string(got.Value))
	}

	apiExpired := NewTOSAPI(&getKVBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(200)},
	})
	_, err = apiExpired.GetKV(context.Background(), owner, "ns", hexutil.Bytes("k"), rpcBlockPtr(rpc.LatestBlockNumber))
	if err == nil {
		t.Fatalf("expected not found for expired key")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrNotFound {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrNotFound)
	}
}

func TestGetKVMetaIncludesExpiredFlag(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	owner := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	kvstore.Put(st, owner, "ns", []byte("k"), []byte("value"), 10, 20)

	api := NewTOSAPI(&getKVBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(20)},
	})
	meta, err := api.GetKVMeta(context.Background(), owner, "ns", hexutil.Bytes("k"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !meta.Expired {
		t.Fatalf("expected expired=true")
	}
	if uint64(meta.CreatedAt) != 10 || uint64(meta.ExpireAt) != 20 {
		t.Fatalf("unexpected meta heights: %+v", meta)
	}
}

func TestGetKVMissingReturnsNotFound(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	api := NewTOSAPI(&getKVBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(1)},
	})

	owner := common.HexToAddress("0x00000000000000000000000000000000000000cc")
	_, err = api.GetKV(context.Background(), owner, "ns", hexutil.Bytes("missing"), nil)
	if err == nil {
		t.Fatalf("expected not found")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok || rpcErr.code != rpcErrNotFound {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = api.GetKVMeta(context.Background(), owner, "ns", hexutil.Bytes("missing"), nil)
	if err == nil {
		t.Fatalf("expected not found")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok || rpcErr.code != rpcErrNotFound {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetKVHistoryPrunedByRetentionWindow(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	owner := common.HexToAddress("0x00000000000000000000000000000000000000dd")
	kvstore.Put(st, owner, "ns", []byte("k"), []byte("value"), 100, 1000)

	api := NewTOSAPI(&getKVBackendMock{
		backendMock: newBackendMock(), // head=1100, retain=200 -> oldest available=901
		st:          st,
		head:        &types.Header{Number: big.NewInt(900)},
	})
	reqBlock := rpcBlockPtr(rpc.BlockNumber(900))

	_, err = api.GetKV(context.Background(), owner, "ns", hexutil.Bytes("k"), reqBlock)
	if err == nil {
		t.Fatalf("expected history pruned error")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrHistoryPruned {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrHistoryPruned)
	}

	_, err = api.GetKVMeta(context.Background(), owner, "ns", hexutil.Bytes("k"), reqBlock)
	if err == nil {
		t.Fatalf("expected history pruned error for getKVMeta")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrHistoryPruned {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrHistoryPruned)
	}
}

func rpcBlockPtr(number rpc.BlockNumber) *rpc.BlockNumberOrHash {
	v := rpc.BlockNumberOrHashWithNumber(number)
	return &v
}
