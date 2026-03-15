package lease

import (
	"testing"

	"github.com/tos-network/gtos/params"
)

func TestCreateXGasScalesBaseWithLeaseBlocks(t *testing.T) {
	const codeBytes = 1024

	shortGas, err := CreateXGas(codeBytes, params.LeaseMinBlocks)
	if err != nil {
		t.Fatalf("CreateXGas short: %v", err)
	}
	longGas, err := CreateXGas(codeBytes, params.LeaseReferenceBlocks)
	if err != nil {
		t.Fatalf("CreateXGas long: %v", err)
	}

	wantShort := params.LeaseCreateXBaseGas + 1 + params.LeaseCreateXByteGas*codeBytes
	if shortGas != wantShort {
		t.Fatalf("CreateXGas short: want %d, got %d", wantShort, shortGas)
	}

	wantLong := params.LeaseCreateXBaseGas*2 + params.LeaseCreateXByteGas*codeBytes
	if longGas != wantLong {
		t.Fatalf("CreateXGas long: want %d, got %d", wantLong, longGas)
	}
	if longGas <= shortGas {
		t.Fatalf("CreateXGas should increase with leaseBlocks: short=%d long=%d", shortGas, longGas)
	}
}

func TestCreate2XGasScalesBaseWithLeaseBlocks(t *testing.T) {
	const codeBytes = 256

	shortGas, err := Create2XGas(codeBytes, params.LeaseMinBlocks)
	if err != nil {
		t.Fatalf("Create2XGas short: %v", err)
	}
	longGas, err := Create2XGas(codeBytes, params.LeaseReferenceBlocks)
	if err != nil {
		t.Fatalf("Create2XGas long: %v", err)
	}

	wantShort := params.LeaseCreate2XBaseGas + 1 + params.LeaseCreate2XByteGas*codeBytes
	if shortGas != wantShort {
		t.Fatalf("Create2XGas short: want %d, got %d", wantShort, shortGas)
	}

	wantLong := params.LeaseCreate2XBaseGas*2 + params.LeaseCreate2XByteGas*codeBytes
	if longGas != wantLong {
		t.Fatalf("Create2XGas long: want %d, got %d", wantLong, longGas)
	}
	if longGas <= shortGas {
		t.Fatalf("Create2XGas should increase with leaseBlocks: short=%d long=%d", shortGas, longGas)
	}
}
