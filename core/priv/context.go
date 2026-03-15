package priv

import (
	"encoding/binary"
	"math/big"

	"github.com/tos-network/gtos/common"
)

const (
	privContextVersion  byte = 1
	privNativeAssetTag  byte = 0
	privActionTransfer  byte = 0x10 // distinct from old action IDs
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
//	[11:31]   from address (sender, 20 bytes)
//	[31:51]   to address (receiver, 20 bytes)
//	[51:59]   privNonce (big-endian uint64)
//	[59:67]   fee (big-endian uint64)
//	[67:75]   feeLimit (big-endian uint64)
//	[75:139]  sender ciphertext (commitment 32 + handle 32)
//	[139:203] receiver ciphertext (commitment 32 + handle 32)
//	[203:235] sourceCommitment (32 bytes)
func BuildPrivTransferTranscriptContext(
	chainID *big.Int,
	privNonce uint64,
	fee uint64,
	feeLimit uint64,
	from, to common.Address,
	senderCt, receiverCt Ciphertext,
	sourceCommitment [32]byte,
) []byte {
	// Pre-allocate: 1+8+1+1+20+20+8+8+8+64+64+32 = 235 bytes
	ctx := make([]byte, 0, 235)
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
