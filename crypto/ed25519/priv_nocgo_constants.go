package ed25519

import (
	"sync"

	"github.com/tos-network/gtos/crypto/ristretto255"
)

// Pedersen H generator (blinding generator from bulletproofs crate)
var pedersenHCompressed = [32]byte{
	0x8c, 0x92, 0x40, 0xb4, 0x56, 0xa9, 0xe6, 0xdc,
	0x65, 0xc3, 0x77, 0xa1, 0x04, 0x8d, 0x74, 0x5f,
	0x94, 0xa0, 0x8c, 0xdb, 0x7f, 0x44, 0xcb, 0xcd,
	0x7b, 0x46, 0xf3, 0x40, 0x48, 0x87, 0x11, 0x34,
}

// Ristretto255 basepoint G
var ristrettoBasepointCompressed = [32]byte{
	0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71,
	0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
	0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d,
	0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
}

// Ristretto255 identity (compressed zero point)
var ristrettoIdentityCompressed [32]byte // all zeros

var (
	pedersenHOnce sync.Once
	pedersenHElem *ristretto255.Element

	basepointGOnce sync.Once
	basepointGElem *ristretto255.Element
)

func getPedersenH() *ristretto255.Element {
	pedersenHOnce.Do(func() {
		pedersenHElem = ristretto255.NewElement()
		if _, err := pedersenHElem.SetCanonicalBytes(pedersenHCompressed[:]); err != nil {
			panic("ed25519: invalid Pedersen H constant: " + err.Error())
		}
	})
	return pedersenHElem
}

func getBasepointG() *ristretto255.Element {
	basepointGOnce.Do(func() {
		basepointGElem = ristretto255.NewElement()
		if _, err := basepointGElem.SetCanonicalBytes(ristrettoBasepointCompressed[:]); err != nil {
			panic("ed25519: invalid basepoint G constant: " + err.Error())
		}
	})
	return basepointGElem
}
