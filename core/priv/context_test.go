package priv

import (
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	cryptopriv "github.com/tos-network/gtos/crypto/priv"
)

// ---------------------------------------------------------------------------
// Deterministic ElGamal test keypairs.
//
// Generated from fixed seeds via SHA-512 → Ristretto scalar → pubkey.
//   alice seed: "gtos-test-alice"
//   bob   seed: "gtos-test-bob"
//
// Addresses are Keccak256(pubkey), matching the on-chain derivation used in
// PrivTransferTx.FromAddress / ShieldTx.DerivedAddress / UnshieldTx.DerivedAddress.
// ---------------------------------------------------------------------------

var (
	// alice
	alicePrivHex = "4b39db8513e2a92829fb281c25a3480794c3460ab6e46ab732568d2f583d1204"
	alicePubHex  = "a0bd89782863c447cb70095f12967c0a0f0c0c71bc295e3d43dc7c66fbbfbd7c"
	// bob
	bobPrivHex = "98c0107b71797f5fd8ef8e874058b88364e185c5e067d4633e7b4d22d19c9301"
	bobPubHex  = "260985307325013ecf52d9249d06d87536b8d4e10c21e6618052bbe8bd0e2f65"
)

// mustDecodePub decodes a hex pubkey and returns the 32-byte array and its
// Keccak256-derived address.
func mustDecodePub(hexStr string) ([32]byte, common.Address) {
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(b) != 32 {
		panic("bad test pubkey: " + hexStr)
	}
	var pub [32]byte
	copy(pub[:], b)
	addr := common.BytesToAddress(crypto.Keccak256(pub[:]))
	return pub, addr
}

func TestBuildPrivTransferTranscriptContext(t *testing.T) {
	chainID := big.NewInt(1337)

	_, aliceAddr := mustDecodePub(alicePubHex)
	_, bobAddr := mustDecodePub(bobPubHex)

	senderCt := ZeroCiphertext()
	receiverCt := ZeroCiphertext()
	var srcCommit [32]byte
	srcCommit[0] = 0xFF

	ctx := BuildPrivTransferTranscriptContext(
		chainID,
		5,     // privNonce
		10000, // fee
		20000, // feeLimit
		aliceAddr, bobAddr,
		senderCt, receiverCt,
		srcCommit,
	)

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
	if common.BytesToAddress(ctx[11:43]) != aliceAddr {
		t.Fatal("from address mismatch")
	}

	// [43:75] to address (32 bytes)
	if common.BytesToAddress(ctx[43:75]) != bobAddr {
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

func TestBuildShieldTranscriptContext(t *testing.T) {
	chainID := big.NewInt(1337)
	_, aliceAddr := mustDecodePub(alicePubHex)

	var commitment, handle [32]byte
	commitment[0] = 0xAA
	handle[0] = 0xBB

	ctx := BuildShieldTranscriptContext(
		chainID,
		5,     // privNonce
		10000, // fee
		5000,  // amount
		aliceAddr,
		commitment,
		handle,
	)

	// 1+8+1+1+32+8+8+8+32+32 = 131 bytes
	const expectedLen = 131
	if len(ctx) != expectedLen {
		t.Fatalf("context length: got %d want %d", len(ctx), expectedLen)
	}

	if ctx[0] != 1 {
		t.Fatalf("contextVersion: got %d want 1", ctx[0])
	}
	if gotChainID := binary.BigEndian.Uint64(ctx[1:9]); gotChainID != 1337 {
		t.Fatalf("chainId: got %d want 1337", gotChainID)
	}
	if ctx[9] != 0x11 {
		t.Fatalf("actionTag: got 0x%02x want 0x11", ctx[9])
	}
	if ctx[10] != 0 {
		t.Fatalf("assetTag: got %d want 0", ctx[10])
	}
	if common.BytesToAddress(ctx[11:43]) != aliceAddr {
		t.Fatal("address mismatch")
	}
	if gotNonce := binary.BigEndian.Uint64(ctx[43:51]); gotNonce != 5 {
		t.Fatalf("privNonce: got %d want 5", gotNonce)
	}
	if gotFee := binary.BigEndian.Uint64(ctx[51:59]); gotFee != 10000 {
		t.Fatalf("fee: got %d want 10000", gotFee)
	}
	if gotAmount := binary.BigEndian.Uint64(ctx[59:67]); gotAmount != 5000 {
		t.Fatalf("amount: got %d want 5000", gotAmount)
	}
	var gotCommitment [32]byte
	copy(gotCommitment[:], ctx[67:99])
	if gotCommitment != commitment {
		t.Fatal("commitment mismatch")
	}
	var gotHandle [32]byte
	copy(gotHandle[:], ctx[99:131])
	if gotHandle != handle {
		t.Fatal("handle mismatch")
	}
}

func TestBuildUnshieldTranscriptContext(t *testing.T) {
	chainID := big.NewInt(1337)
	_, aliceAddr := mustDecodePub(alicePubHex)

	zeroedCt := ZeroCiphertext()
	zeroedCt.Commitment[0] = 0xCC
	var srcCommit [32]byte
	srcCommit[0] = 0xDD

	ctx := BuildUnshieldTranscriptContext(
		chainID,
		3,     // privNonce
		10000, // fee
		2500,  // amount
		aliceAddr,
		zeroedCt,
		srcCommit,
	)

	// 1+8+1+1+32+8+8+8+64+32 = 163 bytes
	const expectedLen = 163
	if len(ctx) != expectedLen {
		t.Fatalf("context length: got %d want %d", len(ctx), expectedLen)
	}

	if ctx[0] != 1 {
		t.Fatalf("contextVersion: got %d want 1", ctx[0])
	}
	if ctx[9] != 0x12 {
		t.Fatalf("actionTag: got 0x%02x want 0x12", ctx[9])
	}
	if common.BytesToAddress(ctx[11:43]) != aliceAddr {
		t.Fatal("address mismatch")
	}
	if gotAmount := binary.BigEndian.Uint64(ctx[59:67]); gotAmount != 2500 {
		t.Fatalf("amount: got %d want 2500", gotAmount)
	}
	var gotSrcCommit [32]byte
	copy(gotSrcCommit[:], ctx[131:163])
	if gotSrcCommit != srcCommit {
		t.Fatal("sourceCommitment mismatch")
	}
}

// TestTestKeypairDerivation verifies the hardcoded test keypair constants are
// self-consistent: Keccak256(pub) must produce the expected address, and the
// private key must derive the matching public key.
func TestTestKeypairDerivation(t *testing.T) {
	for _, tc := range []struct {
		label   string
		privHex string
		pubHex  string
	}{
		{"alice", alicePrivHex, alicePubHex},
		{"bob", bobPrivHex, bobPubHex},
	} {
		priv, err := hex.DecodeString(tc.privHex)
		if err != nil {
			t.Fatalf("%s: decode priv: %v", tc.label, err)
		}
		pub, err := hex.DecodeString(tc.pubHex)
		if err != nil {
			t.Fatalf("%s: decode pub: %v", tc.label, err)
		}

		// Derive pubkey from privkey and compare.
		derivedPub, err := cryptopriv.PublicKeyFromPrivate(priv)
		if err != nil {
			t.Fatalf("%s: PublicKeyFromPrivate: %v", tc.label, err)
		}
		if !bytesEqual(derivedPub, pub) {
			t.Fatalf("%s: derived pub %x != expected %x", tc.label, derivedPub, pub)
		}

		// Derive address and verify it is a full 32-byte address (no zero-padding).
		addr := common.BytesToAddress(crypto.Keccak256(pub))
		if addr == (common.Address{}) {
			t.Fatalf("%s: derived address is zero", tc.label)
		}
		// Keccak256 output fills all 32 bytes — first byte should be non-zero
		// (statistically certain for these fixed inputs).
		if addr[0] == 0 && addr[1] == 0 {
			t.Fatalf("%s: address has suspicious leading zeros: %x", tc.label, addr)
		}
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
