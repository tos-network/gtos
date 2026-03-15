//go:build !cgo || !ed25519c

package ed25519

import (
	"encoding/binary"
	"math/bits"

	"github.com/tos-network/gtos/crypto/ristretto255"
)

// ---------------------------------------------------------------------------
// STROBE-128 core (STROBE protocol framework over Keccak-f[1600])
// ---------------------------------------------------------------------------

const strobeR = 166 // rate for STROBE-128: (1600 - 2*128) / 8 - 2 = 166

// STROBE operation flags
const (
	flagI byte = 1
	flagA byte = 2
	flagC byte = 4
	flagT byte = 8  //nolint:unused
	flagM byte = 16
	flagK byte = 32
)

type strobe128 struct {
	state    [25]uint64
	pos      byte
	posBegin byte
	curFlags byte
}

// --- Keccak-f[1600] permutation (24 rounds) ---

var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// rho rotation offsets for indices 1..24 (applied after pi reordering)
var keccakRot = [24]uint{
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
	27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
}

// pi permutation: destination index for lane i+1
var keccakPi = [24]int{
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
}

func keccakF1600(state *[25]uint64) {
	var bc [5]uint64
	for round := 0; round < 24; round++ {
		// θ (theta)
		for i := 0; i < 5; i++ {
			bc[i] = state[i] ^ state[i+5] ^ state[i+10] ^ state[i+15] ^ state[i+20]
		}
		for i := 0; i < 5; i++ {
			t := bc[(i+4)%5] ^ bits.RotateLeft64(bc[(i+1)%5], 1)
			for j := 0; j < 25; j += 5 {
				state[j+i] ^= t
			}
		}

		// ρ (rho) and π (pi)
		last := state[1]
		for i := 0; i < 24; i++ {
			j := keccakPi[i]
			tmp := state[j]
			state[j] = bits.RotateLeft64(last, int(keccakRot[i]))
			last = tmp
		}

		// χ (chi)
		for j := 0; j < 25; j += 5 {
			bc[0] = state[j+0]
			bc[1] = state[j+1]
			bc[2] = state[j+2]
			bc[3] = state[j+3]
			bc[4] = state[j+4]
			for i := 0; i < 5; i++ {
				state[j+i] = bc[i] ^ (^bc[(i+1)%5] & bc[(i+2)%5])
			}
		}

		// ι (iota)
		state[0] ^= keccakRC[round]
	}
}

// --- byte-level accessors for the uint64 state ---

func (s *strobe128) getByte(idx int) byte {
	return byte(s.state[idx/8] >> (uint(idx%8) * 8))
}

func (s *strobe128) setByte(idx int, v byte) {
	shift := uint(idx%8) * 8
	s.state[idx/8] = (s.state[idx/8] &^ (0xFF << shift)) | (uint64(v) << shift)
}

func (s *strobe128) xorByte(idx int, v byte) {
	s.state[idx/8] ^= uint64(v) << (uint(idx%8) * 8)
}

// --- STROBE-128 operations ---

func (s *strobe128) runF() {
	s.xorByte(int(s.pos), s.posBegin)
	s.xorByte(int(s.pos)+1, 0x04)
	s.xorByte(strobeR+1, 0x80)
	keccakF1600(&s.state)
	s.pos = 0
	s.posBegin = 0
}

func (s *strobe128) absorb(data []byte) {
	for _, d := range data {
		s.xorByte(int(s.pos), d)
		s.pos++
		if s.pos == strobeR {
			s.runF()
		}
	}
}

func (s *strobe128) squeeze(n int) []byte {
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = s.getByte(int(s.pos))
		s.setByte(int(s.pos), 0)
		s.pos++
		if s.pos == strobeR {
			s.runF()
		}
	}
	return out
}

func (s *strobe128) beginOp(flags byte) {
	old := s.posBegin
	s.posBegin = s.pos + 1
	s.curFlags = flags
	s.absorb([]byte{old, flags})
	if flags&(flagC|flagK) != 0 && s.pos != 0 {
		s.runF()
	}
}

func (s *strobe128) metaAD(data []byte, more bool) {
	if !more {
		s.beginOp(flagM | flagA)
	}
	s.absorb(data)
}

func (s *strobe128) ad(data []byte, more bool) {
	if !more {
		s.beginOp(flagA)
	}
	s.absorb(data)
}

func (s *strobe128) prf(n int, more bool) []byte {
	if !more {
		s.beginOp(flagI | flagA | flagC)
	}
	return s.squeeze(n)
}

func (s *strobe128) init(label []byte) {
	s.state = [25]uint64{}
	// Initial domain-separation bytes for STROBE-128:
	// {1, R+2, 1, 0, 1, 96, 'S','T','R','O','B','E','v','1','.','0','.','2'}
	initBytes := [18]byte{
		1, 168, 1, 0, 1, 96,
		'S', 'T', 'R', 'O', 'B', 'E', 'v', '1', '.', '0', '.', '2',
	}
	for i, b := range initBytes {
		s.setByte(i, b)
	}
	keccakF1600(&s.state)
	s.pos = 0
	s.posBegin = 0
	s.curFlags = 0
	s.metaAD(label, false)
}

// ---------------------------------------------------------------------------
// Merlin transcript layer
// ---------------------------------------------------------------------------

type merlinTranscript struct {
	strobe strobe128
}

func newMerlinTranscript(label string) *merlinTranscript {
	t := &merlinTranscript{}
	t.strobe.init([]byte("Merlin v1.0"))
	t.appendMessage("dom-sep", []byte(label))
	return t
}

func le32(n int) []byte {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(n))
	return buf[:]
}

func (t *merlinTranscript) appendMessage(label string, data []byte) {
	t.strobe.metaAD([]byte(label), false)
	t.strobe.metaAD(le32(len(data)), true)
	t.strobe.ad(data, false)
}

func (t *merlinTranscript) appendU64(label string, val uint64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], val)
	t.appendMessage(label, buf[:])
}

func (t *merlinTranscript) challengeBytes(label string, n int) []byte {
	t.strobe.metaAD([]byte(label), false)
	t.strobe.metaAD(le32(n), true)
	return t.strobe.prf(n, false)
}

func (t *merlinTranscript) challengeScalar(label string) *ristretto255.Scalar {
	buf := t.challengeBytes(label, 64)
	s := ristretto255.NewScalar()
	if _, err := s.SetUniformBytes(buf); err != nil {
		panic("merlin: challengeScalar: " + err.Error())
	}
	return s
}
