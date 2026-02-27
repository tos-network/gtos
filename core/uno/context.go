package uno

import (
	"encoding/binary"
	"math/big"

	"github.com/tos-network/gtos/common"
)

// unoContextSize is the byte length of the canonical UNO transcript context.
const unoContextSize = 73 // 8 (chainId) + 1 (action) + 32 (from) + 32 (to)

// BuildUNOTranscriptContext constructs the canonical 73-byte chain context that
// is committed into every UNO proof's Merlin transcript before verification.
//
// Layout (73 bytes):
//
//	[0:8]   chainId, big-endian uint64 (clamped if chainID > MaxUint64)
//	[8:9]   actionTag (ActionShield / ActionTransfer / ActionUnshield)
//	[9:41]  from address (sender, 32 bytes)
//	[41:73] to address (receiver; zero address if action has no receiver)
//
// Both the proof prover and verifier must append this context to the Merlin
// transcript under the label "chain-ctx" before the proof-specific domain
// separator, guaranteeing cross-chain and cross-action replay hardening.
func BuildUNOTranscriptContext(chainID *big.Int, action uint8, from, to common.Address) []byte {
	ctx := make([]byte, unoContextSize)
	var chainIDU64 uint64
	if chainID != nil && chainID.IsUint64() {
		chainIDU64 = chainID.Uint64()
	}
	binary.BigEndian.PutUint64(ctx[0:8], chainIDU64)
	ctx[8] = action
	copy(ctx[9:41], from[:])
	copy(ctx[41:73], to[:])
	return ctx
}
