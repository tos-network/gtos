package priv

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
)

func TestBuildPrivTransferTranscriptContext(t *testing.T) {
	chainID := big.NewInt(1337)
	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	senderCt := ZeroCiphertext()
	receiverCt := ZeroCiphertext()
	var srcCommit [32]byte
	srcCommit[0] = 0xFF

	ctx := BuildPrivTransferTranscriptContext(
		chainID,
		5,     // privNonce
		10000, // fee
		20000, // feeLimit
		from, to,
		senderCt, receiverCt,
		srcCommit,
	)

	// Address is 32 bytes in this chain, so total is:
	// 1+8+1+1+32+32+8+8+8+64+64+32 = 259 bytes.
	const expectedLen = 259
	if len(ctx) != expectedLen {
		t.Fatalf("context length: got %d want %d", len(ctx), expectedLen)
	}

	// [0:1] contextVersion == 1
	if ctx[0] != 1 {
		t.Fatalf("contextVersion: got %d want 1", ctx[0])
	}

	// [1:9] chainId big-endian uint64
	gotChainID := binary.BigEndian.Uint64(ctx[1:9])
	if gotChainID != 1337 {
		t.Fatalf("chainId: got %d want 1337", gotChainID)
	}

	// [9:10] actionTag == 0x10
	if ctx[9] != 0x10 {
		t.Fatalf("actionTag: got 0x%02x want 0x10", ctx[9])
	}

	// [10:11] assetTag == 0
	if ctx[10] != 0 {
		t.Fatalf("assetTag: got %d want 0", ctx[10])
	}

	// [11:43] from address (32 bytes)
	if common.BytesToAddress(ctx[11:43]) != from {
		t.Fatal("from address mismatch")
	}

	// [43:75] to address (32 bytes)
	if common.BytesToAddress(ctx[43:75]) != to {
		t.Fatal("to address mismatch")
	}

	// [75:83] privNonce
	if gotNonce := binary.BigEndian.Uint64(ctx[75:83]); gotNonce != 5 {
		t.Fatalf("privNonce: got %d want 5", gotNonce)
	}

	// [83:91] fee
	if gotFee := binary.BigEndian.Uint64(ctx[83:91]); gotFee != 10000 {
		t.Fatalf("fee: got %d want 10000", gotFee)
	}

	// [91:99] feeLimit
	if gotFL := binary.BigEndian.Uint64(ctx[91:99]); gotFL != 20000 {
		t.Fatalf("feeLimit: got %d want 20000", gotFL)
	}

	// [227:259] sourceCommitment (last 32 bytes)
	var gotSrcCommit [32]byte
	copy(gotSrcCommit[:], ctx[227:259])
	if gotSrcCommit != srcCommit {
		t.Fatal("sourceCommitment mismatch")
	}
}

func TestBuildPrivTransferTranscriptContext_NilChainID(t *testing.T) {
	ctx := BuildPrivTransferTranscriptContext(
		nil, 0, 0, 0,
		common.Address{}, common.Address{},
		ZeroCiphertext(), ZeroCiphertext(),
		[32]byte{},
	)
	if len(ctx) != 259 {
		t.Fatalf("context length: got %d want 259", len(ctx))
	}
	// nil chainID should encode as 0.
	if gotChainID := binary.BigEndian.Uint64(ctx[1:9]); gotChainID != 0 {
		t.Fatalf("nil chainId: got %d want 0", gotChainID)
	}
}
