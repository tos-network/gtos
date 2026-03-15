package priv

import (
	"encoding/binary"
	"math/big"

	"github.com/tos-network/gtos/common"
)

const (
	privContextVersion byte = 1
	privNativeAssetTag byte = 0
	privActionTransfer byte = 0x10 // distinct from old action IDs
	privActionShield   byte = 0x11
	privActionUnshield byte = 0x12
)

func appendU8(dst []byte, v byte) []byte {
	return append(dst, v)
}

func appendU64(dst []byte, v uint64) []byte {
	var word [8]byte
	binary.BigEndian.PutUint64(word[:], v)
	return append(dst, word[:]...)
}

func appendAddress(dst []byte, addr common.Address) []byte {
	return append(dst, addr[:]...)
}

func appendCiphertext(dst []byte, ct Ciphertext) []byte {
	dst = append(dst, ct.Commitment[:]...)
	dst = append(dst, ct.Handle[:]...)
	return dst
}

func appendBytes32(dst []byte, b [32]byte) []byte {
	return append(dst, b[:]...)
}

func chainIDToU64(chainID *big.Int) uint64 {
	if chainID == nil {
		return 0
	}
	if chainID.IsUint64() {
		return chainID.Uint64()
	}
	return ^uint64(0)
}

// BuildPrivTransferTranscriptContext constructs the canonical chain context
// that is committed into every PrivTransfer proof's Merlin transcript before
// verification.
//
// Layout:
//
//	[0:1]     contextVersion (1)
//	[1:9]     chainId, big-endian uint64
//	[9:10]    actionTag (0x10 = priv transfer)
//	[10:11]   native asset tag (0)
//	[11:43]   from address (sender, 32 bytes)
//	[43:75]   to address (receiver, 32 bytes)
//	[75:83]   privNonce (big-endian uint64)
//	[83:91]   fee (big-endian uint64)
//	[91:99]   feeLimit (big-endian uint64)
//	[99:163]  sender ciphertext (commitment 32 + handle 32)
//	[163:227] receiver ciphertext (commitment 32 + handle 32)
//	[227:259] sourceCommitment (32 bytes)
func BuildPrivTransferTranscriptContext(
	chainID *big.Int,
	privNonce uint64,
	fee uint64,
	feeLimit uint64,
	from, to common.Address,
	senderCt, receiverCt Ciphertext,
	sourceCommitment [32]byte,
) []byte {
	// Pre-allocate: 1+8+1+1+32+32+8+8+8+64+64+32 = 259 bytes
	ctx := make([]byte, 0, 259)
	ctx = appendU8(ctx, privContextVersion)
	ctx = appendU64(ctx, chainIDToU64(chainID))
	ctx = appendU8(ctx, privActionTransfer)
	ctx = appendU8(ctx, privNativeAssetTag)
	ctx = appendAddress(ctx, from)
	ctx = appendAddress(ctx, to)
	ctx = appendU64(ctx, privNonce)
	ctx = appendU64(ctx, fee)
	ctx = appendU64(ctx, feeLimit)
	ctx = appendCiphertext(ctx, senderCt)
	ctx = appendCiphertext(ctx, receiverCt)
	ctx = appendBytes32(ctx, sourceCommitment)
	return ctx
}

// BuildShieldTranscriptContext constructs the canonical chain context for
// Shield proof verification.
//
// Layout (131 bytes):
//
//	[0:1]     contextVersion (1)
//	[1:9]     chainId, big-endian uint64
//	[9:10]    actionTag (0x11 = shield)
//	[10:11]   native asset tag (0)
//	[11:43]   address (sender, 32 bytes)
//	[43:51]   privNonce (big-endian uint64)
//	[51:59]   fee (big-endian uint64)
//	[59:67]   amount (big-endian uint64)
//	[67:99]   commitment (32 bytes)
//	[99:131]  handle (32 bytes)
func BuildShieldTranscriptContext(
	chainID *big.Int,
	privNonce uint64,
	fee uint64,
	amount uint64,
	addr common.Address,
	commitment, handle [32]byte,
) []byte {
	// Pre-allocate: 1+8+1+1+32+8+8+8+32+32 = 131 bytes
	ctx := make([]byte, 0, 131)
	ctx = appendU8(ctx, privContextVersion)
	ctx = appendU64(ctx, chainIDToU64(chainID))
	ctx = appendU8(ctx, privActionShield)
	ctx = appendU8(ctx, privNativeAssetTag)
	ctx = appendAddress(ctx, addr)
	ctx = appendU64(ctx, privNonce)
	ctx = appendU64(ctx, fee)
	ctx = appendU64(ctx, amount)
	ctx = appendBytes32(ctx, commitment)
	ctx = appendBytes32(ctx, handle)
	return ctx
}

// BuildUnshieldTranscriptContext constructs the canonical chain context for
// Unshield proof verification.
//
// Layout (163 bytes):
//
//	[0:1]     contextVersion (1)
//	[1:9]     chainId, big-endian uint64
//	[9:10]    actionTag (0x12 = unshield)
//	[10:11]   native asset tag (0)
//	[11:43]   address (sender, 32 bytes)
//	[43:51]   privNonce (big-endian uint64)
//	[51:59]   fee (big-endian uint64)
//	[59:67]   amount (big-endian uint64)
//	[67:131]  zeroed ciphertext (commitment 32 + handle 32)
//	[131:163] sourceCommitment (32 bytes)
func BuildUnshieldTranscriptContext(
	chainID *big.Int,
	privNonce uint64,
	fee uint64,
	amount uint64,
	addr common.Address,
	zeroedCt Ciphertext,
	sourceCommitment [32]byte,
) []byte {
	// Pre-allocate: 1+8+1+1+32+8+8+8+64+32 = 163 bytes
	ctx := make([]byte, 0, 163)
	ctx = appendU8(ctx, privContextVersion)
	ctx = appendU64(ctx, chainIDToU64(chainID))
	ctx = appendU8(ctx, privActionUnshield)
	ctx = appendU8(ctx, privNativeAssetTag)
	ctx = appendAddress(ctx, addr)
	ctx = appendU64(ctx, privNonce)
	ctx = appendU64(ctx, fee)
	ctx = appendU64(ctx, amount)
	ctx = appendCiphertext(ctx, zeroedCt)
	ctx = appendBytes32(ctx, sourceCommitment)
	return ctx
}
