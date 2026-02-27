package uno

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
)

func testContextCiphertext(seed byte) Ciphertext {
	var ct Ciphertext
	for i := 0; i < len(ct.Commitment); i++ {
		ct.Commitment[i] = seed + byte(i)
		ct.Handle[i] = seed + 0x40 + byte(i)
	}
	return ct
}

func TestBuildUNOTranscriptContextLayout(t *testing.T) {
	chainID := big.NewInt(1666)
	from := common.HexToAddress("0x1111111111111111111111111111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222222222222222222222222222")
	nonce := uint64(19)

	ctx := BuildUNOTranscriptContext(chainID, ActionTransfer, from, to, nonce)

	if len(ctx) != 83 {
		t.Fatalf("unexpected context length: got %d want 83", len(ctx))
	}
	if got := ctx[0]; got != unoContextVersion {
		t.Fatalf("version: got %d want %d", got, unoContextVersion)
	}
	if got := binary.BigEndian.Uint64(ctx[1:9]); got != 1666 {
		t.Fatalf("chainID: got %d want 1666", got)
	}
	if got := ctx[9]; got != ActionTransfer {
		t.Fatalf("action: got %d want %d", got, ActionTransfer)
	}
	if got := ctx[10]; got != unoNativeAssetTag {
		t.Fatalf("assetTag: got %d want %d", got, unoNativeAssetTag)
	}
	var gotFrom common.Address
	copy(gotFrom[:], ctx[11:43])
	if gotFrom != from {
		t.Fatalf("from: got %x want %x", gotFrom, from)
	}
	var gotTo common.Address
	copy(gotTo[:], ctx[43:75])
	if gotTo != to {
		t.Fatalf("to: got %x want %x", gotTo, to)
	}
	if got := binary.BigEndian.Uint64(ctx[75:83]); got != nonce {
		t.Fatalf("nonce: got %d want %d", got, nonce)
	}
}

func TestBuildUNOTranscriptContextDiffersByField(t *testing.T) {
	chainID := big.NewInt(1666)
	from := common.HexToAddress("0xAAAA")
	to := common.HexToAddress("0xBBBB")

	ctxShield := BuildUNOTranscriptContext(chainID, ActionShield, from, common.Address{}, 1)
	ctxTransfer := BuildUNOTranscriptContext(chainID, ActionTransfer, from, to, 1)
	ctxUnshield := BuildUNOTranscriptContext(chainID, ActionUnshield, from, to, 1)
	ctxOtherChain := BuildUNOTranscriptContext(big.NewInt(1), ActionShield, from, common.Address{}, 1)
	ctxOtherNonce := BuildUNOTranscriptContext(chainID, ActionShield, from, common.Address{}, 2)

	for name, pair := range map[string][2][]byte{
		"shield vs transfer":   {ctxShield, ctxTransfer},
		"transfer vs unshield": {ctxTransfer, ctxUnshield},
		"chain1 vs chain1666":  {ctxOtherChain, ctxShield},
		"nonce1 vs nonce2":     {ctxShield, ctxOtherNonce},
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

func TestBuildUNOTranscriptContextChainIDOverflowClamp(t *testing.T) {
	overflow := new(big.Int).Lsh(big.NewInt(1), 80)
	ctx := BuildUNOTranscriptContext(overflow, ActionShield, common.Address{}, common.Address{}, 0)
	if got := binary.BigEndian.Uint64(ctx[1:9]); got != ^uint64(0) {
		t.Fatalf("overflow chainID: got %d want %d", got, ^uint64(0))
	}
}

func TestBuildUNOActionContextsLengths(t *testing.T) {
	chainID := big.NewInt(1666)
	from := common.HexToAddress("0x01")
	to := common.HexToAddress("0x02")
	oldSender := testContextCiphertext(0x10)
	newSender := testContextCiphertext(0x20)
	oldReceiver := testContextCiphertext(0x30)
	receiverDelta := testContextCiphertext(0x40)

	shieldCtx := BuildUNOShieldTranscriptContext(chainID, from, 8, 7, oldSender, receiverDelta)
	if len(shieldCtx) != 83+8+64+64 {
		t.Fatalf("unexpected shield ctx len %d", len(shieldCtx))
	}
	transferCtx := BuildUNOTransferTranscriptContext(chainID, from, to, 9, oldSender, newSender, oldReceiver, receiverDelta)
	if len(transferCtx) != 83+64+64+64+64 {
		t.Fatalf("unexpected transfer ctx len %d", len(transferCtx))
	}
	unshieldCtx := BuildUNOUnshieldTranscriptContext(chainID, from, to, 10, 11, oldSender, newSender)
	if len(unshieldCtx) != 83+8+64+64 {
		t.Fatalf("unexpected unshield ctx len %d", len(unshieldCtx))
	}
}
