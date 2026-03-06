package core

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/params"
)

// TestAccessListIntrinsicGasIsZero verifies that including an access list in a
// transaction does not increase intrinsic gas.  GTOS uses flat gas costs (no
// EIP-2929 warm/cold distinction), so the access list provides no runtime
// benefit; charging for it would be a net tax on users.
func TestAccessListIntrinsicGasIsZero(t *testing.T) {
	// A non-trivial access list with one address + one storage slot.
	al := types.AccessList{
		{
			Address:     common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
			StorageKeys: []common.Hash{common.HexToHash("0x01")},
		},
	}

	gasWithout, err := IntrinsicGas(nil, nil, false, true, true)
	if err != nil {
		t.Fatalf("IntrinsicGas (no AL): %v", err)
	}
	gasWithAL, err := IntrinsicGas(nil, al, false, true, true)
	if err != nil {
		t.Fatalf("IntrinsicGas (with AL): %v", err)
	}
	if gasWithout != gasWithAL {
		t.Errorf("intrinsic gas differs: without AL = %d, with AL = %d (diff = %d); "+
			"TxAccessListAddressGas and TxAccessListStorageKeyGas must both be 0 in GTOS",
			gasWithout, gasWithAL, int64(gasWithAL)-int64(gasWithout))
	}
}

// TestAccessListParamsAreZero asserts that the protocol params are set to 0,
// documenting the intentional design choice.
func TestAccessListParamsAreZero(t *testing.T) {
	if params.TxAccessListAddressGas != 0 {
		t.Errorf("TxAccessListAddressGas = %d, want 0 (GTOS has no warm/cold distinction)",
			params.TxAccessListAddressGas)
	}
	if params.TxAccessListStorageKeyGas != 0 {
		t.Errorf("TxAccessListStorageKeyGas = %d, want 0 (GTOS has no warm/cold distinction)",
			params.TxAccessListStorageKeyGas)
	}
}

// TestAccessListIntrinsicGasLargeList verifies that even a large access list
// does not inflate intrinsic gas.
func TestAccessListIntrinsicGasLargeList(t *testing.T) {
	al := make(types.AccessList, 10)
	for i := range al {
		al[i] = types.AccessTuple{
			Address:     common.BigToAddress(big.NewInt(int64(i + 1))),
			StorageKeys: []common.Hash{common.BigToHash(big.NewInt(int64(i))), common.BigToHash(big.NewInt(int64(i + 100)))},
		}
	}
	gasBase, _ := IntrinsicGas(nil, nil, false, true, true)
	gasWithAL, _ := IntrinsicGas(nil, al, false, true, true)
	if gasBase != gasWithAL {
		t.Errorf("10-entry access list inflated intrinsic gas from %d to %d", gasBase, gasWithAL)
	}
}
