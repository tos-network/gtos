//go:build !cgo

package types

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	bls "github.com/tos-network/gtos/crypto/bls12381"
)

func supportsBLS12381GoldenVerify() bool {
	return true
}

func verifyBLS12381GoldenRaw(pub []byte, hash common.Hash, r, s *big.Int) bool {
	sig := rsBytes(r, s, 48)

	g1 := bls.NewG1()
	pk, err := g1.FromCompressed(pub)
	if err != nil || g1.IsZero(pk) {
		return false
	}

	g2 := bls.NewG2()
	sigPoint, err := g2.FromCompressed(sig)
	if err != nil || g2.IsZero(sigPoint) {
		return false
	}

	hashPoint, err := bls.HashToG2(hash[:], []byte("GTOS_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_"))
	if err != nil {
		return false
	}

	engine := bls.NewPairingEngine()
	engine.AddPair(pk, hashPoint)
	engine.AddPairInv(g1.One(), sigPoint)
	return engine.Check()
}
