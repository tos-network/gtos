package tosapi

import (
	"context"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/rpc"
)

// TestUnoDecryptBalanceRejectsZeroAddress verifies that a zero address is rejected.
func TestUnoDecryptBalanceRejectsZeroAddress(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	_, err := api.UnoDecryptBalance(context.Background(), common.Address{}, make(hexutil.Bytes, 32), nil, nil)
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

// TestUnoDecryptBalanceRejectsShortPrivKey verifies that a privKey != 32 bytes is rejected.
func TestUnoDecryptBalanceRejectsShortPrivKey(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	addr := common.HexToAddress("0x1234")
	_, err := api.UnoDecryptBalance(context.Background(), addr, make(hexutil.Bytes, 31), nil, nil)
	if err == nil {
		t.Fatal("expected error for 31-byte privKey")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T: %v", err, err)
	}
	if rpcErr.code != rpcErrInvalidParams {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidParams)
	}
}

// TestUnoDecryptBalanceRejectsNilBackend verifies that a nil backend returns not-implemented.
func TestUnoDecryptBalanceRejectsNilBackend(t *testing.T) {
	api := &TOSAPI{}
	addr := common.HexToAddress("0x1234")
	_, err := api.UnoDecryptBalance(context.Background(), addr, make(hexutil.Bytes, 32), nil, nil)
	if err == nil {
		t.Fatal("expected not-implemented error for nil backend")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T: %v", err, err)
	}
	if rpcErr.code != rpcErrNotImplemented {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrNotImplemented)
	}
}

// TestUnoDecryptBalanceHistoryPruned verifies that a pruned block number is rejected.
func TestUnoDecryptBalanceHistoryPruned(t *testing.T) {
	api := NewTOSAPI(newBackendMock()) // head=1100, retain=200 → oldest available=901
	addr := common.HexToAddress("0x5678")
	reqBlock := rpcBlockPtr(rpc.BlockNumber(900)) // block 900 is pruned (< 901)
	_, err := api.UnoDecryptBalance(context.Background(), addr, make(hexutil.Bytes, 32), nil, reqBlock)
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
