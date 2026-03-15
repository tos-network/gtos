//go:build cgo

package bls12381

import (
	"bytes"
	"math/big"
	"testing"

	blst "github.com/supranational/blst/bindings/go"
)

func secretKeyFromBytes(t *testing.T, raw []byte) *blst.SecretKey {
	t.Helper()
	sk := new(blst.SecretKey).Deserialize(raw)
	if sk == nil {
		t.Fatalf("invalid secret key bytes: %x", raw)
	}
	return sk
}

func TestHashToG2MatchesBlst(t *testing.T) {
	t.Parallel()

	dst := []byte("GTOS_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_")
	msgs := [][]byte{
		[]byte(""),
		[]byte("hello"),
		[]byte("GTOS"),
		bytes.Repeat([]byte{0x42}, 32),
		bytes.Repeat([]byte{0x99}, 128),
	}

	g2 := NewG2()
	for _, msg := range msgs {
		want := blst.HashToG2(msg, dst).ToAffine().Serialize()
		gotPoint, err := HashToG2(msg, dst)
		if err != nil {
			t.Fatalf("HashToG2 failed for %q: %v", msg, err)
		}
		got := g2.ToBytes(gotPoint)
		if !bytes.Equal(got, want) {
			t.Fatalf("HashToG2 mismatch for %q", msg)
		}
	}
}

func TestG1CompressionMatchesBlst(t *testing.T) {
	t.Parallel()

	g1 := NewG1()
	scalars := [][]byte{
		append(make([]byte, 31), 0x01),
		append(make([]byte, 31), 0x02),
		append(make([]byte, 31), 0x03),
		append(make([]byte, 31), 0x11),
		bytes.Repeat([]byte{0x0f}, 32),
	}

	for _, scalarBytes := range scalars {
		scalar := new(big.Int).SetBytes(scalarBytes)
		point := g1.New()
		g1.MulScalar(point, g1.One(), scalar)
		got := g1.ToCompressed(point)

		sk := secretKeyFromBytes(t, scalarBytes)
		want := new(blst.P1Affine).From(sk).Compress()
		if !bytes.Equal(got, want) {
			t.Fatalf("compressed G1 mismatch for %x", scalarBytes)
		}

		roundTrip, err := g1.FromCompressed(got)
		if err != nil {
			t.Fatalf("round-trip G1 decompress failed for %x: %v", scalarBytes, err)
		}
		if !bytes.Equal(g1.ToBytes(roundTrip), new(blst.P1Affine).Uncompress(got).Serialize()) {
			t.Fatalf("round-trip G1 uncompressed mismatch for %x", scalarBytes)
		}
	}
}

func TestG2CompressionMatchesBlst(t *testing.T) {
	t.Parallel()

	dst := []byte("GTOS_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_")
	msgs := [][]byte{
		[]byte("hello"),
		bytes.Repeat([]byte{0x24}, 32),
	}

	g2 := NewG2()
	for _, msg := range msgs {
		point, err := HashToG2(msg, dst)
		if err != nil {
			t.Fatalf("HashToG2 failed: %v", err)
		}
		got := g2.ToCompressed(point)
		want := blst.HashToG2(msg, dst).ToAffine().Compress()
		if !bytes.Equal(got, want) {
			t.Fatalf("compressed G2 mismatch for %x", msg)
		}

		roundTrip, err := g2.FromCompressed(got)
		if err != nil {
			t.Fatalf("round-trip G2 decompress failed for %x: %v", msg, err)
		}
		if !bytes.Equal(g2.ToBytes(roundTrip), new(blst.P2Affine).Uncompress(got).Serialize()) {
			t.Fatalf("round-trip G2 uncompressed mismatch for %x", msg)
		}
	}
}
