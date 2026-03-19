package priv

import (
	"math/big"

	cryptopriv "github.com/tos-network/gtos/crypto/priv"
)

const (
	privActionDisclosure byte = 0x20
)

// DisclosureClaim bundles a disclosure proof with its public parameters.
type DisclosureClaim struct {
	Pubkey      [32]byte
	Ciphertext  Ciphertext
	Amount      uint64
	Proof       [96]byte
	BlockNumber uint64
}

// BuildDisclosureContext constructs a canonical chain context for disclosure
// proof verification. This context is committed into the Merlin transcript to
// prevent cross-chain replay.
//
// Layout (114 bytes):
//
//	[0:1]     version (1)
//	[1:9]     chainId (BE uint64)
//	[9:10]    actionTag (0x20 = disclosure)
//	[10:42]   pubkey (32 bytes)
//	[42:74]   commitment (32 bytes)
//	[74:106]  handle (32 bytes)
//	[106:114] blockNumber (BE uint64)
func BuildDisclosureContext(
	chainID *big.Int,
	pubkey [32]byte,
	ct Ciphertext,
	blockNum uint64,
) []byte {
	// Pre-allocate: 1+8+1+32+32+32+8 = 114 bytes
	ctx := make([]byte, 0, 114)
	ctx = appendU8(ctx, privContextVersion)
	ctx = appendU64(ctx, chainIDToU64(chainID))
	ctx = appendU8(ctx, privActionDisclosure)
	ctx = appendBytes32(ctx, pubkey)
	ctx = appendBytes32(ctx, ct.Commitment)
	ctx = appendBytes32(ctx, ct.Handle)
	ctx = appendU64(ctx, blockNum)
	return ctx
}

// ProveDisclosure generates a disclosure proof bound to the given chain parameters.
func ProveDisclosure(
	privkey, pubkey [32]byte,
	ct Ciphertext,
	amount uint64,
	chainID *big.Int,
	blockNum uint64,
) ([]byte, error) {
	ctx := BuildDisclosureContext(chainID, pubkey, ct, blockNum)
	ct64 := make([]byte, 64)
	copy(ct64[:32], ct.Commitment[:])
	copy(ct64[32:], ct.Handle[:])
	return cryptopriv.ProveDisclosureExact(privkey[:], pubkey[:], ct64, amount, ctx)
}

// VerifyDisclosure verifies a DisclosureClaim against the given chain ID.
func VerifyDisclosure(claim DisclosureClaim, chainID *big.Int) error {
	ctx := BuildDisclosureContext(chainID, claim.Pubkey, claim.Ciphertext, claim.BlockNumber)
	ct64 := make([]byte, 64)
	copy(ct64[:32], claim.Ciphertext.Commitment[:])
	copy(ct64[32:], claim.Ciphertext.Handle[:])
	return cryptopriv.VerifyDisclosureExact(claim.Pubkey[:], ct64, claim.Amount, claim.Proof[:], ctx)
}
