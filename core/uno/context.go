package uno

import (
	"encoding/binary"
	"math/big"

	"github.com/tos-network/gtos/common"
)

const (
	unoContextVersion = TranscriptContextVersion
	unoNativeAssetTag = TranscriptNativeAssetTag
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

func chainIDToU64(chainID *big.Int) uint64 {
	if chainID == nil {
		return 0
	}
	if chainID.IsUint64() {
		return chainID.Uint64()
	}
	return ^uint64(0)
}

func buildUNOContextHeader(chainID *big.Int, action byte, from, to common.Address, nonce uint64) []byte {
	ctx := make([]byte, 0, 1+8+1+1+32+32+8)
	ctx = appendU8(ctx, unoContextVersion)
	ctx = appendU64(ctx, chainIDToU64(chainID))
	ctx = appendU8(ctx, action)
	ctx = appendU8(ctx, unoNativeAssetTag)
	ctx = appendAddress(ctx, from)
	ctx = appendAddress(ctx, to)
	ctx = appendU64(ctx, nonce)
	return ctx
}

// BuildUNOTranscriptContext constructs the canonical chain context that is
// committed into every UNO proof's Merlin transcript before verification.
//
// Layout (83 bytes):
//
//	[0:1]   contextVersion
//	[1:9]   chainId, big-endian uint64 (clamped to MaxUint64 on overflow)
//	[9:10]  actionTag (ActionShield / ActionTransfer / ActionUnshield)
//	[10:11] native asset tag (0)
//	[11:43] from address (sender, 32 bytes)
//	[43:75] to address (receiver; zero address if action has no receiver)
//	[75:83] sender nonce (big-endian uint64)
//
// Both the proof prover and verifier must append this context to the Merlin
// transcript under the label "chain-ctx" before the proof-specific domain
// separator, guaranteeing cross-chain and cross-action replay hardening.
func BuildUNOTranscriptContext(chainID *big.Int, action uint8, from, to common.Address, nonce uint64) []byte {
	return buildUNOContextHeader(chainID, action, from, to, nonce)
}

// BuildUNOShieldTranscriptContext extends the base context with state
// transition fields required by UNO_SHIELD verification.
//
// Tail layout:
//
//	[83:91]  amount (uint64)
//	[91:155] sender old ciphertext
//	[155:219] sender shield delta ciphertext
func BuildUNOShieldTranscriptContext(chainID *big.Int, from common.Address, nonce uint64, amount uint64, senderOld, senderDelta Ciphertext) []byte {
	ctx := buildUNOContextHeader(chainID, ActionShield, from, common.Address{}, nonce)
	ctx = appendU64(ctx, amount)
	ctx = appendCiphertext(ctx, senderOld)
	ctx = appendCiphertext(ctx, senderDelta)
	return ctx
}

// BuildUNOTransferTranscriptContext extends the base context with state
// transition fields required by UNO_TRANSFER verification.
//
// Tail layout:
//
//	[83:147]  sender old ciphertext
//	[147:211] sender new ciphertext
//	[211:275] receiver old ciphertext
//	[275:339] receiver delta ciphertext
func BuildUNOTransferTranscriptContext(chainID *big.Int, from, to common.Address, nonce uint64, senderOld, senderNew, receiverOld, receiverDelta Ciphertext) []byte {
	ctx := buildUNOContextHeader(chainID, ActionTransfer, from, to, nonce)
	ctx = appendCiphertext(ctx, senderOld)
	ctx = appendCiphertext(ctx, senderNew)
	ctx = appendCiphertext(ctx, receiverOld)
	ctx = appendCiphertext(ctx, receiverDelta)
	return ctx
}

// BuildUNOUnshieldTranscriptContext extends the base context with state
// transition fields required by UNO_UNSHIELD verification.
//
// Tail layout:
//
//	[83:91]  amount (uint64)
//	[91:155] sender old ciphertext
//	[155:219] sender new ciphertext
func BuildUNOUnshieldTranscriptContext(chainID *big.Int, from, to common.Address, nonce uint64, amount uint64, senderOld, senderNew Ciphertext) []byte {
	ctx := buildUNOContextHeader(chainID, ActionUnshield, from, to, nonce)
	ctx = appendU64(ctx, amount)
	ctx = appendCiphertext(ctx, senderOld)
	ctx = appendCiphertext(ctx, senderNew)
	return ctx
}
