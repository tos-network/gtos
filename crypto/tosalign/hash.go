package tosalign

import "github.com/tos-network/gtos/crypto/blake3"

const HashSize = 32

type Hash [HashSize]byte

func HashBytes(value []byte) Hash {
	sum := blake3.Sum256(value)
	return Hash(sum)
}

func (h Hash) Bytes() []byte {
	out := make([]byte, HashSize)
	copy(out, h[:])
	return out
}
