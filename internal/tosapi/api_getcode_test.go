package tosapi

import (
	"context"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
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

func TestGetCodeReturnsStoredCode(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	addr := common.HexToAddress("0xf81c536380b2dd5ef5c4ae95e1fae9b4fab2f5726677ecfa912d96b0b683e6a9")
	code := []byte{0x60, 0x00}
	st.SetCode(addr, code)

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
		t.Fatalf("unexpected code: have %x want %x", []byte(got), code)
	}
}

func TestGetCodeHistoryPrunedByRetentionWindow(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	addr := common.HexToAddress("0x3ac976f9d2acd22c761751d7ae72a48c1a36bd18af168541c53037965d26e4a8")
	st.SetCode(addr, []byte{0x60, 0x00})

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
}
