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
