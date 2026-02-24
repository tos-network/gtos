package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"testing"
)

func TestNewKeyFromSeedCompatibility(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, SeedSize)
	got := NewKeyFromSeed(seed)
	want := stded25519.NewKeyFromSeed(seed)
	if !bytes.Equal(got, want) {
		t.Fatalf("private key mismatch\nwant=%x\n got=%x", want, got)
	}
}

func TestSignVerifyCompatibility(t *testing.T) {
	seed := bytes.Repeat([]byte{0x11}, SeedSize)
	msg := []byte("gtos-ed25519-compatibility")

	priv := NewKeyFromSeed(seed)
	pub := PublicFromPrivate(priv)
	sig := Sign(priv, msg)

	wantSig := stded25519.Sign(stded25519.PrivateKey(priv), msg)
	if !bytes.Equal(sig, wantSig) {
		t.Fatalf("signature mismatch\nwant=%x\n got=%x", wantSig, sig)
	}
	if !Verify(pub, msg, sig) {
		t.Fatal("Verify returned false")
	}
	if !stded25519.Verify(stded25519.PublicKey(pub), msg, sig) {
		t.Fatal("stdlib Verify returned false")
	}

	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 0x80
	if Verify(pub, msg, badSig) {
		t.Fatal("Verify accepted a tampered signature")
	}
}
