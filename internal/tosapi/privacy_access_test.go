package tosapi

import (
	"context"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	corepriv "github.com/tos-network/gtos/core/priv"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/rpc"
)

func TestIsPrivacySlot(t *testing.T) {
	// All four privacy slots must be detected.
	privSlots := []common.Hash{
		corepriv.CommitmentSlot,
		corepriv.HandleSlot,
		corepriv.VersionSlot,
		corepriv.NonceSlot,
	}
	for _, slot := range privSlots {
		if !isPrivacySlot(slot) {
			t.Errorf("expected slot %s to be recognised as privacy slot", slot.Hex())
		}
	}

	// Random slots must NOT be detected.
	randomSlots := []common.Hash{
		common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),
		common.HexToHash("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
		{}, // zero hash
	}
	for _, slot := range randomSlots {
		if isPrivacySlot(slot) {
			t.Errorf("slot %s should not be a privacy slot", slot.Hex())
		}
	}
}

// storageAtBackendMock wraps backendMock and returns a real state for storage reads.
type storageAtBackendMock struct {
	*backendMock
	st   *state.StateDB
	head *types.Header
}

func (b *storageAtBackendMock) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	return b.st, b.head, nil
}

func TestGetStorageAtPrivacySlotBlocked(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}

	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	// Write a non-zero value into the commitment slot so we can verify it is
	// returned when unrestricted, and blocked when restricted.
	val := common.HexToHash("0xaa")
	st.SetState(addr, corepriv.CommitmentSlot, val)

	api := NewBlockChainAPI(&storageAtBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(1)},
	})

	latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)

	// Unrestricted: privacy slot reads should succeed.
	PrivacyRPCRestricted = false
	got, err := api.GetStorageAt(context.Background(), addr, corepriv.CommitmentSlot.Hex(), latest)
	if err != nil {
		t.Fatalf("unrestricted GetStorageAt failed: %v", err)
	}
	if common.BytesToHash(got) != val {
		t.Fatalf("unrestricted GetStorageAt returned wrong value: have %x want %x", got, val)
	}

	// Restricted: privacy slot reads should be denied.
	PrivacyRPCRestricted = true
	defer func() { PrivacyRPCRestricted = false }()

	for _, slot := range []common.Hash{
		corepriv.CommitmentSlot,
		corepriv.HandleSlot,
		corepriv.VersionSlot,
		corepriv.NonceSlot,
	} {
		_, err = api.GetStorageAt(context.Background(), addr, slot.Hex(), latest)
		if err == nil {
			t.Errorf("expected error for privacy slot %s when restricted", slot.Hex())
		}
	}

	// Non-privacy slot should still work when restricted.
	nonPrivSlot := common.HexToHash("0x01")
	st.SetState(addr, nonPrivSlot, common.HexToHash("0xbb"))
	got, err = api.GetStorageAt(context.Background(), addr, nonPrivSlot.Hex(), latest)
	if err != nil {
		t.Fatalf("restricted GetStorageAt for non-privacy slot failed: %v", err)
	}
	if common.BytesToHash(got) != common.HexToHash("0xbb") {
		t.Fatalf("restricted GetStorageAt for non-privacy slot returned wrong value")
	}
}

func TestGetStorageAtPrivacySlotAllowedWhenUnrestricted(t *testing.T) {
	PrivacyRPCRestricted = false

	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}

	addr := common.HexToAddress("0xabcdef")
	val := common.HexToHash("0xcc")
	st.SetState(addr, corepriv.CommitmentSlot, val)

	api := NewBlockChainAPI(&storageAtBackendMock{
		backendMock: newBackendMock(),
		st:          st,
		head:        &types.Header{Number: big.NewInt(1)},
	})

	latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	got, err := api.GetStorageAt(context.Background(), addr, corepriv.CommitmentSlot.Hex(), latest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if common.BytesToHash(got) != val {
		t.Fatalf("wrong value: have %x want %x", got, val)
	}
}
