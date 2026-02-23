package tosapi

import (
	"context"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/rpc"
)

type getCodeBackendMock struct {
	*backendMock
	st   *state.StateDB
	head *types.Header
}

func (b *getCodeBackendMock) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	return b.st, b.head, nil
}

func TestGetCodeRespectsExpireAt(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	addr := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	code := []byte{0x60, 0x00}
	st.SetCode(addr, code)
	st.SetState(addr, core.SetCodeExpireAtSlot, common.BigToHash(new(big.Int).SetUint64(200)))

	api := NewBlockChainAPI(&getCodeBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(199)},
	})
	got, err := api.GetCode(context.Background(), addr, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(code) {
		t.Fatalf("unexpected active code: have %x want %x", []byte(got), code)
	}

	apiExpired := NewBlockChainAPI(&getCodeBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(200)},
	})
	got, err = apiExpired.GetCode(context.Background(), addr, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected expired code to return 0x, have %x", []byte(got))
	}
}

func TestGetCodeMetaIncludesExpiryFields(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	addr := common.HexToAddress("0x00000000000000000000000000000000000000ab")
	code := []byte{0x60, 0x01}
	st.SetCode(addr, code)
	st.SetState(addr, core.SetCodeCreatedAtSlot, common.BigToHash(new(big.Int).SetUint64(100)))
	st.SetState(addr, core.SetCodeExpireAtSlot, common.BigToHash(new(big.Int).SetUint64(200)))

	api := NewBlockChainAPI(&getCodeBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(150)},
	})
	meta, err := api.GetCodeMeta(context.Background(), addr, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Address != addr {
		t.Fatalf("unexpected address: have %s want %s", meta.Address.Hex(), addr.Hex())
	}
	if meta.CodeHash != st.GetCodeHash(addr) {
		t.Fatalf("unexpected code hash: have %s want %s", meta.CodeHash.Hex(), st.GetCodeHash(addr).Hex())
	}
	if uint64(meta.CreatedAt) != 100 || uint64(meta.ExpireAt) != 200 {
		t.Fatalf("unexpected metadata heights: %+v", meta)
	}
	if meta.Expired {
		t.Fatalf("expected expired=false")
	}

	apiExpired := NewBlockChainAPI(&getCodeBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(200)},
	})
	meta, err = apiExpired.GetCodeMeta(context.Background(), addr, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !meta.Expired {
		t.Fatalf("expected expired=true")
	}
}

func TestGetCodeHistoryPrunedByRetentionWindow(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	addr := common.HexToAddress("0x00000000000000000000000000000000000000ac")
	st.SetCode(addr, []byte{0x60, 0x00})
	st.SetState(addr, core.SetCodeExpireAtSlot, common.BigToHash(new(big.Int).SetUint64(1200)))

	api := NewBlockChainAPI(&getCodeBackendMock{
		backendMock: newBackendMock(), // head=1100, retain=200 -> oldest available=901
		st:          st,
		head:        &types.Header{Number: big.NewInt(900)},
	})
	_, err = api.GetCode(context.Background(), addr, rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(900)))
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

	_, err = api.GetCodeMeta(context.Background(), addr, rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(900)))
	if err == nil {
		t.Fatalf("expected history pruned error for getCodeMeta")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrHistoryPruned {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrHistoryPruned)
	}
}
