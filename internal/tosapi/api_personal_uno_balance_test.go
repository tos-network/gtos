package tosapi

import (
	"context"
	"strings"
	"testing"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto/ristretto255"
	"github.com/tos-network/gtos/rpc"
)

func TestPersonalUnoBalanceRejectsZeroAddress(t *testing.T) {
	api := NewPersonalAccountAPI(newBackendMock(), new(AddrLocker))
	_, err := api.UnoBalance(context.Background(), common.Address{}, "pw", nil, nil)
	if err == nil {
		t.Fatal("expected error for zero address")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T: %v", err, err)
	}
	if rpcErr.code != rpcErrInvalidParams {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidParams)
	}
}

func TestPersonalUnoBalanceRejectsNilBackend(t *testing.T) {
	api := &PersonalAccountAPI{}
	addr := common.HexToAddress("0x1234")
	_, err := api.UnoBalance(context.Background(), addr, "pw", nil, nil)
	if err == nil {
		t.Fatal("expected not-implemented error")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T: %v", err, err)
	}
	if rpcErr.code != rpcErrNotImplemented {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrNotImplemented)
	}
}

func TestPersonalUnoBalanceHistoryPruned(t *testing.T) {
	api := NewPersonalAccountAPI(newBackendMock(), new(AddrLocker)) // head=1100, retain=200 -> oldest available=901
	addr := common.HexToAddress("0x5678")
	reqBlock := rpcBlockPtr(rpc.BlockNumber(900))
	_, err := api.UnoBalance(context.Background(), addr, "pw", nil, reqBlock)
	if err == nil {
		t.Fatal("expected history pruned error")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T: %v", err, err)
	}
	if rpcErr.code != rpcErrHistoryPruned {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrHistoryPruned)
	}
}

func TestPersonalUnoBalanceRejectsMissingAccountManager(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	addr := common.HexToAddress("0x9f020f9cb0fbc07bb5f359ff7efeb7b1fefc3100934d13f61cb7eb7f33f95ba5")
	pub := ristretto255.NewGeneratorElement().Bytes()
	accountsigner.Set(st, addr, accountsigner.SignerTypeElgamal, hexutil.Encode(pub))

	api := NewPersonalAccountAPI(&getUNOBackendMock{
		backendMock: newBackendMock(), // AccountManager() is nil in backendMock.
		st:          st,
		head:        &types.Header{},
	}, new(AddrLocker))

	_, err = api.UnoBalance(context.Background(), addr, "pw", nil, nil)
	if err == nil {
		t.Fatal("expected missing account manager error")
	}
	if !strings.Contains(err.Error(), "account manager unavailable") {
		t.Fatalf("unexpected error: %v", err)
	}
}
