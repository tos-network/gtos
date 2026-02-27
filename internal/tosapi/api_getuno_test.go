package tosapi

import (
	"bytes"
	"context"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	coreuno "github.com/tos-network/gtos/core/uno"
	"github.com/tos-network/gtos/crypto/ristretto255"
	"github.com/tos-network/gtos/rpc"
)

type getUNOBackendMock struct {
	*backendMock
	st   *state.StateDB
	head *types.Header
}

func (b *getUNOBackendMock) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	return b.st, b.head, nil
}

func TestGetUNOCiphertextReadsState(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	addr := common.HexToAddress("0x9f020f9cb0fbc07bb5f359ff7efeb7b1fefc3100934d13f61cb7eb7f33f95ba5")

	var ct coreuno.Ciphertext
	copy(ct.Commitment[:], ristretto255.NewGeneratorElement().Bytes())
	copy(ct.Handle[:], ristretto255.NewIdentityElement().Bytes())
	coreuno.SetAccountState(st, addr, coreuno.AccountState{Ciphertext: ct, Version: 8})

	api := NewTOSAPI(&getUNOBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(321)},
	})
	got, err := api.GetUNOCiphertext(context.Background(), addr, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Address != addr {
		t.Fatalf("unexpected address: have %s want %s", got.Address.Hex(), addr.Hex())
	}
	if uint64(got.Version) != 8 {
		t.Fatalf("unexpected version: have %d want %d", got.Version, 8)
	}
	if uint64(got.BlockNumber) != 321 {
		t.Fatalf("unexpected block number: have %d want %d", got.BlockNumber, 321)
	}
	if !bytes.Equal(got.Commitment, ct.Commitment[:]) {
		t.Fatalf("unexpected commitment")
	}
	if !bytes.Equal(got.Handle, ct.Handle[:]) {
		t.Fatalf("unexpected handle")
	}
}

func TestGetUNOCiphertextRejectsZeroAddress(t *testing.T) {
	api := &TOSAPI{}
	_, err := api.GetUNOCiphertext(context.Background(), common.Address{}, nil)
	if err == nil {
		t.Fatalf("expected invalid params error")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidParams {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidParams)
	}
}

func TestGetUNOCiphertextHistoryPrunedByRetentionWindow(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	addr := common.HexToAddress("0x2f6b99899c179892ff4f8cb72e627cd9f874b70c90d6b530997a81d35f4f241e")

	api := NewTOSAPI(&getUNOBackendMock{
		backendMock: newBackendMock(), // head=1100, retain=200 -> oldest available=901
		st:          st,
		head:        &types.Header{Number: big.NewInt(900)},
	})
	reqBlock := rpcBlockPtr(rpc.BlockNumber(900))

	_, err = api.GetUNOCiphertext(context.Background(), addr, reqBlock)
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
