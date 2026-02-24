package tosapi

import (
	"context"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/rpc"
)

type getSignerBackendMock struct {
	*backendMock
	st   *state.StateDB
	head *types.Header
}

func (b *getSignerBackendMock) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	return b.st, b.head, nil
}

func TestGetSignerReadsStoredSignerMetadata(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	addr := common.HexToAddress("0xf81c536380b2dd5ef5c4ae95e1fae9b4fab2f5726677ecfa912d96b0b683e6a9")
	accountsigner.Set(st, addr, "ed25519", testAPIEd25519PubHex)

	api := NewTOSAPI(&getSignerBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(100)},
	})
	got, err := api.GetSigner(context.Background(), addr, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Signer.Defaulted {
		t.Fatalf("expected defaulted=false")
	}
	if got.Signer.Type != "ed25519" || got.Signer.Value != testAPIEd25519PubHex {
		t.Fatalf("unexpected signer %+v", got.Signer)
	}

	acc, err := api.GetAccount(context.Background(), addr, nil)
	if err != nil {
		t.Fatalf("unexpected account error: %v", err)
	}
	if acc.Signer.Defaulted {
		t.Fatalf("expected account signer defaulted=false")
	}
	if acc.Signer.Type != "ed25519" || acc.Signer.Value != testAPIEd25519PubHex {
		t.Fatalf("unexpected account signer %+v", acc.Signer)
	}
}

func TestGetSignerFallbackToAddressWhenUnset(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	addr := common.HexToAddress("0xb422a2991bf0212aae4f7493ff06ad5d076fa274b49c297f3fe9e29b5ba9aadc")

	api := NewTOSAPI(&getSignerBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(100)},
	})
	got, err := api.GetSigner(context.Background(), addr, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Signer.Defaulted {
		t.Fatalf("expected defaulted=true")
	}
	if got.Signer.Type != "address" || got.Signer.Value != addr.Hex() {
		t.Fatalf("unexpected fallback signer %+v", got.Signer)
	}
}

func TestGetAccountHistoryPrunedByRetentionWindow(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	addr := common.HexToAddress("0xe8b0087eec10090b15f4fc4bc96aaa54e2d44c299564da76e1cd3184a2386b8d")

	api := NewTOSAPI(&getSignerBackendMock{
		backendMock: newBackendMock(), // head=1100, retain=200 -> oldest available=901
		st:          st,
		head:        &types.Header{Number: big.NewInt(900)},
	})
	block := rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(900))
	_, err = api.GetAccount(context.Background(), addr, &block)
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
