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
