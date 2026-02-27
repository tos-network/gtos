package uno

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
)

func TestBuildUNOTranscriptContextLayout(t *testing.T) {
	chainID := big.NewInt(1666)
	from := common.HexToAddress("0x1111111111111111111111111111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222222222222222222222222222")

	ctx := BuildUNOTranscriptContext(chainID, ActionTransfer, from, to)

	if len(ctx) != unoContextSize {
		t.Fatalf("unexpected context length: got %d want %d", len(ctx), unoContextSize)
	}

	gotChainID := binary.BigEndian.Uint64(ctx[0:8])
	if gotChainID != 1666 {
		t.Fatalf("chainID: got %d want 1666", gotChainID)
	}
	if ctx[8] != ActionTransfer {
		t.Fatalf("action: got %d want %d", ctx[8], ActionTransfer)
	}
	var gotFrom common.Address
	copy(gotFrom[:], ctx[9:41])
	if gotFrom != from {
		t.Fatalf("from: got %x want %x", gotFrom, from)
	}
	var gotTo common.Address
	copy(gotTo[:], ctx[41:73])
	if gotTo != to {
		t.Fatalf("to: got %x want %x", gotTo, to)
	}
}

func TestBuildUNOTranscriptContextDiffersByField(t *testing.T) {
	chainID := big.NewInt(1666)
	from := common.HexToAddress("0xAAAA")
	to := common.HexToAddress("0xBBBB")
	zero := common.Address{}

	ctxShield := BuildUNOTranscriptContext(chainID, ActionShield, from, zero)
	ctxTransfer := BuildUNOTranscriptContext(chainID, ActionTransfer, from, to)
	ctxUnshield := BuildUNOTranscriptContext(chainID, ActionUnshield, from, to)
	ctxOtherChain := BuildUNOTranscriptContext(big.NewInt(1), ActionShield, from, zero)

	for name, pair := range map[string][2][]byte{
		"shield vs transfer":    {ctxShield, ctxTransfer},
		"transfer vs unshield":  {ctxTransfer, ctxUnshield},
		"chain1 vs chain1666":   {ctxOtherChain, ctxShield},
	} {
		a, b := pair[0], pair[1]
		equal := true
		for i := range a {
			if a[i] != b[i] {
				equal = false
				break
			}
		}
		if equal {
			t.Errorf("%s: contexts are identical but should differ", name)
		}
	}
}

func TestBuildUNOTranscriptContextNilChainID(t *testing.T) {
	ctx := BuildUNOTranscriptContext(nil, ActionShield, common.Address{}, common.Address{})
	if len(ctx) != unoContextSize {
		t.Fatalf("nil chainID should produce valid context, got len=%d", len(ctx))
	}
	// chainID should be 0 when nil
	gotChainID := binary.BigEndian.Uint64(ctx[0:8])
	if gotChainID != 0 {
		t.Fatalf("nil chainID: got %d want 0", gotChainID)
	}
}
