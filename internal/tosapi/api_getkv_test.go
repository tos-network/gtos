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
	owner := common.HexToAddress("0xf81c536380b2dd5ef5c4ae95e1fae9b4fab2f5726677ecfa912d96b0b683e6a9")
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

func TestGetKVMetaExpiredKeyNotFound(t *testing.T) {
	// With lazy expiry, GetKVMeta returns "not found" when expireAt <= currentBlock.
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	owner := common.HexToAddress("0xb422a2991bf0212aae4f7493ff06ad5d076fa274b49c297f3fe9e29b5ba9aadc")
	kvstore.Put(st, owner, "ns", []byte("k"), []byte("value"), 10, 20)

	// At the expiry block the key is treated as not found.
	api := NewTOSAPI(&getKVBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(20)},
	})
	if _, err := api.GetKVMeta(context.Background(), owner, "ns", hexutil.Bytes("k"), nil); err == nil {
		t.Fatalf("expected not-found error for expired key at block 20")
	}

	// One block before expiry the key is still visible.
	api19 := NewTOSAPI(&getKVBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(19)},
	})
	meta, err := api19.GetKVMeta(context.Background(), owner, "ns", hexutil.Bytes("k"), nil)
	if err != nil {
		t.Fatalf("unexpected error at block 19: %v", err)
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

	owner := common.HexToAddress("0xe8b0087eec10090b15f4fc4bc96aaa54e2d44c299564da76e1cd3184a2386b8d")
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
	owner := common.HexToAddress("0xd0c8d1bb01b01528cd7fa3145d46ac553a974ef992a08eeef0a05990802f01f6")
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
