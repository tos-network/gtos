//go:build cgo

package accountsigner

import (
	"bytes"
	"testing"

	blst "github.com/supranational/blst/bindings/go"
	"github.com/tos-network/gtos/common"
)

func TestPureBLS12381KeyGenMatchesBlst(t *testing.T) {
	t.Parallel()

	ikm := bytes.Repeat([]byte{0x42}, 32)
	got, err := pureBLS12381KeyGenFromIKM(ikm, nil)
	if err != nil {
		t.Fatalf("pure keygen failed: %v", err)
	}
	want := blst.KeyGen(ikm).Serialize()
	if !bytes.Equal(got, want) {
		t.Fatalf("pure keygen mismatch")
	}
}

func TestPureBLS12381SignMatchesBlst(t *testing.T) {
	t.Parallel()

	ikm := bytes.Repeat([]byte{0x37}, 32)
	priv, err := pureBLS12381KeyGenFromIKM(ikm, nil)
	if err != nil {
		t.Fatalf("pure keygen failed: %v", err)
	}
	hash := common.HexToHash("0x1234567890abcdef")

	gotPub, err := purePublicKeyFromBLS12381Private(priv)
	if err != nil {
		t.Fatalf("pure pubkey failed: %v", err)
	}
	gotSig, err := pureSignBLS12381Hash(priv, hash)
	if err != nil {
		t.Fatalf("pure sign failed: %v", err)
	}

	sk := blst.KeyGen(ikm)
	wantPub := new(blst.P1Affine).From(sk).Compress()
	wantSig := new(blst.P2Affine).Sign(sk, hash[:], bls12381SignDst).Compress()

	if !bytes.Equal(gotPub, wantPub) {
		t.Fatalf("pure pubkey mismatch")
	}
	if !bytes.Equal(gotSig, wantSig) {
		t.Fatalf("pure signature mismatch")
	}
	if !pureVerifyBLS12381Signature(gotPub, gotSig, hash) {
		t.Fatalf("pure signature verification failed")
	}
}

func TestPureBLS12381AggregateMatchesBlst(t *testing.T) {
	t.Parallel()

	hash := common.HexToHash("0xabcdef")
	ikms := [][]byte{
		bytes.Repeat([]byte{0x11}, 32),
		bytes.Repeat([]byte{0x22}, 32),
		bytes.Repeat([]byte{0x33}, 32),
	}

	var (
		pubs [][]byte
		sigs [][]byte
	)
	for _, ikm := range ikms {
		priv, err := pureBLS12381KeyGenFromIKM(ikm, nil)
		if err != nil {
			t.Fatalf("pure keygen failed: %v", err)
		}
		pub, err := purePublicKeyFromBLS12381Private(priv)
		if err != nil {
			t.Fatalf("pure pubkey failed: %v", err)
		}
		sig, err := pureSignBLS12381Hash(priv, hash)
		if err != nil {
			t.Fatalf("pure sign failed: %v", err)
		}
		pubs = append(pubs, pub)
		sigs = append(sigs, sig)
	}

	gotPub, err := pureAggregateBLS12381PublicKeys(pubs)
	if err != nil {
		t.Fatalf("pure aggregate pubkeys failed: %v", err)
	}
	gotSig, err := pureAggregateBLS12381Signatures(sigs)
	if err != nil {
		t.Fatalf("pure aggregate sigs failed: %v", err)
	}

	aggPub := new(blst.P1Aggregate)
	if !aggPub.AggregateCompressed(pubs, true) {
		t.Fatalf("blst aggregate pubkeys failed")
	}
	wantPub := aggPub.ToAffine().Compress()

	aggSig := new(blst.P2Aggregate)
	if !aggSig.AggregateCompressed(sigs, true) {
		t.Fatalf("blst aggregate signatures failed")
	}
	wantSig := aggSig.ToAffine().Compress()

	if !bytes.Equal(gotPub, wantPub) {
		t.Fatalf("aggregate pubkey mismatch")
	}
	if !bytes.Equal(gotSig, wantSig) {
		t.Fatalf("aggregate signature mismatch")
	}
	if !pureVerifyBLS12381FastAggregate(pubs, gotSig, hash) {
		t.Fatalf("pure fast aggregate verification failed")
	}
}
