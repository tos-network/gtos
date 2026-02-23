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
	addr := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	accountsigner.Set(st, addr, "ed25519", "z6MkiSigner")

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
	if got.Signer.Type != "ed25519" || got.Signer.Value != "z6MkiSigner" {
		t.Fatalf("unexpected signer %+v", got.Signer)
	}

	acc, err := api.GetAccount(context.Background(), addr, nil)
	if err != nil {
		t.Fatalf("unexpected account error: %v", err)
	}
	if acc.Signer.Defaulted {
		t.Fatalf("expected account signer defaulted=false")
	}
	if acc.Signer.Type != "ed25519" || acc.Signer.Value != "z6MkiSigner" {
		t.Fatalf("unexpected account signer %+v", acc.Signer)
	}
}

func TestGetSignerFallbackToAddressWhenUnset(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	addr := common.HexToAddress("0x00000000000000000000000000000000000000bb")

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
