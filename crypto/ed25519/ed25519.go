package ed25519

import stded25519 "crypto/ed25519"

const (
	PublicKeySize  = stded25519.PublicKeySize
	PrivateKeySize = stded25519.PrivateKeySize
	SignatureSize  = stded25519.SignatureSize
	SeedSize       = stded25519.SeedSize
)

type (
	PublicKey  = stded25519.PublicKey
	PrivateKey = stded25519.PrivateKey
)

// checkSLessThanL returns true if the S component of an ed25519 signature is
// strictly less than the group order L, rejecting malleable signatures.
func checkSLessThanL(sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	// L in little-endian
	var l = [32]byte{
		0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
		0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	}
	s := sig[32:64]
	for i := 31; i >= 0; i-- {
		if s[i] < l[i] {
			return true
		}
		if s[i] > l[i] {
			return false
		}
	}
	return false // s == L is not valid
}
