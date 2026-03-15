//go:build cgo

package types

import (
	"math/big"

	blst "github.com/supranational/blst/bindings/go"
	"github.com/tos-network/gtos/common"
)

func supportsBLS12381GoldenVerify() bool {
	return true
}

func verifyBLS12381GoldenRaw(pub []byte, hash common.Hash, r, s *big.Int) bool {
	sig := rsBytes(r, s, 48)
	var dummy blst.P2Affine
	return dummy.VerifyCompressed(sig, true, pub, true, hash[:], []byte("GTOS_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_"))
}
