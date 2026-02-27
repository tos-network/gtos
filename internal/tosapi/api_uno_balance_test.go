package tosapi

import (
	"context"
	"testing"

	"github.com/tos-network/gtos/accounts"
	"github.com/tos-network/gtos/accounts/keystore"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/rpc"
)

// lockedAccountBackend wraps backendMock but returns a real accounts.Manager.
type lockedAccountBackend struct {
	*backendMock
	am *accounts.Manager
}

func (b *lockedAccountBackend) AccountManager() *accounts.Manager { return b.am }

// TestUnoBalanceRejectsZeroAddress verifies that a zero address is rejected.
func TestUnoBalanceRejectsZeroAddress(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	_, err := api.UnoBalance(context.Background(), common.Address{}, nil, nil)
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

// TestUnoBalanceRejectsNilBackend verifies that a nil backend returns not-implemented.
func TestUnoBalanceRejectsNilBackend(t *testing.T) {
	api := &TOSAPI{}
	addr := common.HexToAddress("0x1234")
	_, err := api.UnoBalance(context.Background(), addr, nil, nil)
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

// TestUnoBalanceHistoryPruned verifies that a pruned block number is rejected.
func TestUnoBalanceHistoryPruned(t *testing.T) {
	api := NewTOSAPI(newBackendMock()) // head=1100, retain=200 → oldest available=901
	addr := common.HexToAddress("0x5678")
	reqBlock := rpcBlockPtr(rpc.BlockNumber(900)) // block 900 is pruned (< 901)
	_, err := api.UnoBalance(context.Background(), addr, nil, reqBlock)
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

// TestUnoBalanceRejectsLockedAccount verifies that an account that is registered
// in the keystore but not unlocked returns rpcErrPermissionDenied.
func TestUnoBalanceRejectsLockedAccount(t *testing.T) {
	ks := keystore.NewKeyStore(t.TempDir(), keystore.LightScryptN, keystore.LightScryptP)
	acct, err := ks.NewElgamalAccount("pass")
	if err != nil {
		t.Fatalf("new elgamal account: %v", err)
	}
	// deliberately do NOT call ks.Unlock(acct, "pass")
	am := accounts.NewManager(&accounts.Config{}, ks)
	defer am.Close()

	backend := &lockedAccountBackend{backendMock: newBackendMock(), am: am}
	api := NewTOSAPI(backend)
	_, err = api.UnoBalance(context.Background(), acct.Address, nil, nil)
	if err == nil {
		t.Fatal("expected permission-denied error for locked account")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T: %v", err, err)
	}
	if rpcErr.code != rpcErrPermissionDenied {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrPermissionDenied)
	}
}
