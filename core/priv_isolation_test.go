package core

import (
	"crypto/rand"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/priv"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/crypto/ristretto255"
	"math/big"
)

func TestPrivAddressesAreDisjoint(t *testing.T) {
	// Derive addresses from random ElGamal pubkeys and random ed25519 pubkeys.
	// They should (almost surely) never collide since Keccak256 of different
	// inputs produces different outputs.
	const iterations = 100
	seen := make(map[common.Address]string, iterations*2)

	for i := 0; i < iterations; i++ {
		// Random ElGamal pubkey (32 bytes — Ristretto255 point).
		var elgamalPub [32]byte
		if _, err := rand.Read(elgamalPub[:]); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		privAddr := common.BytesToAddress(crypto.Keccak256(elgamalPub[:]))

		// Random ed25519-style pubkey (32 bytes).
		var ed25519Pub [32]byte
		if _, err := rand.Read(ed25519Pub[:]); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		pubAddr := common.BytesToAddress(crypto.Keccak256(ed25519Pub[:]))

		if privAddr == pubAddr {
			t.Fatalf("iteration %d: priv address == public address (collision)", i)
		}

		key := privAddr.Hex()
		if prev, ok := seen[privAddr]; ok {
			t.Fatalf("iteration %d: priv address collision with %s", i, prev)
		}
		seen[privAddr] = "elgamal-" + key

		key = pubAddr.Hex()
		if prev, ok := seen[pubAddr]; ok {
			t.Fatalf("iteration %d: public address collision with %s", i, prev)
		}
		seen[pubAddr] = "ed25519-" + key
	}
}

func TestPrivNonceIndependentOfPublicNonce(t *testing.T) {
	st := newTTLDeterminismState(t)
	addr := common.HexToAddress("0xABCD")

	// Set public nonce to 10.
	st.SetNonce(addr, 10)
	// Set PrivNonce to 0 (already default, but be explicit).
	priv.SetAccountState(st, addr, priv.AccountState{Nonce: 0})

	if got := st.GetNonce(addr); got != 10 {
		t.Fatalf("public nonce: expected 10, got %d", got)
	}
	if got := priv.GetPrivNonce(st, addr); got != 0 {
		t.Fatalf("priv nonce: expected 0, got %d", got)
	}

	// Increment PrivNonce to 5.
	for i := 0; i < 5; i++ {
		priv.IncrementPrivNonce(st, addr)
	}
	if got := st.GetNonce(addr); got != 10 {
		t.Fatalf("public nonce should still be 10 after priv nonce increments, got %d", got)
	}
	if got := priv.GetPrivNonce(st, addr); got != 5 {
		t.Fatalf("priv nonce: expected 5, got %d", got)
	}

	// Increment public nonce to 15.
	st.SetNonce(addr, 15)
	if got := priv.GetPrivNonce(st, addr); got != 5 {
		t.Fatalf("priv nonce should still be 5 after public nonce change, got %d", got)
	}
	if got := st.GetNonce(addr); got != 15 {
		t.Fatalf("public nonce: expected 15, got %d", got)
	}
}

func TestPrivBalanceIndependentOfPublicBalance(t *testing.T) {
	st := newTTLDeterminismState(t)
	addr := common.HexToAddress("0xBEEF")

	// Set public balance to 1000.
	st.SetBalance(addr, big.NewInt(1000))

	// Set priv balance to a known ciphertext (generator point for commitment,
	// identity for handle).
	gen := ristretto255.NewGeneratorElement().Bytes()
	id := ristretto255.NewIdentityElement().Bytes()
	var genBytes, idBytes [32]byte
	copy(genBytes[:], gen)
	copy(idBytes[:], id)

	knownCt := priv.Ciphertext{
		Commitment: genBytes,
		Handle:     idBytes,
	}
	priv.SetAccountState(st, addr, priv.AccountState{
		Ciphertext: knownCt,
		Version:    1,
	})

	// Verify public balance.
	if got := st.GetBalance(addr); got.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("public balance: expected 1000, got %v", got)
	}
	// Verify priv balance.
	gotState := priv.GetAccountState(st, addr)
	if gotState.Ciphertext != knownCt {
		t.Fatalf("priv ciphertext mismatch: got %+v, want %+v", gotState.Ciphertext, knownCt)
	}

	// Modify public balance to 500.
	st.SetBalance(addr, big.NewInt(500))
	// Priv balance should be unchanged.
	gotState = priv.GetAccountState(st, addr)
	if gotState.Ciphertext != knownCt {
		t.Fatalf("priv ciphertext changed after public balance modification")
	}

	// Modify priv balance.
	newCt := priv.Ciphertext{
		Commitment: idBytes,
		Handle:     genBytes,
	}
	priv.SetAccountState(st, addr, priv.AccountState{
		Ciphertext: newCt,
		Version:    2,
	})
	// Public balance should still be 500.
	if got := st.GetBalance(addr); got.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("public balance changed after priv balance modification: got %v, want 500", got)
	}
	// Priv balance should reflect update.
	gotState = priv.GetAccountState(st, addr)
	if gotState.Ciphertext != newCt {
		t.Fatalf("priv ciphertext not updated: got %+v, want %+v", gotState.Ciphertext, newCt)
	}
}

func TestPrivZeroCiphertextAsInitialBalance(t *testing.T) {
	st := newTTLDeterminismState(t)
	addr := common.HexToAddress("0xFRESH")

	// Read AccountState for a fresh (never-touched) address.
	gotState := priv.GetAccountState(st, addr)

	// All fields should be zero.
	zeroCt := priv.Ciphertext{}
	if gotState.Ciphertext != zeroCt {
		t.Fatalf("fresh address ciphertext is not zero: commitment=%x handle=%x",
			gotState.Ciphertext.Commitment, gotState.Ciphertext.Handle)
	}
	if gotState.Version != 0 {
		t.Fatalf("fresh address version: expected 0, got %d", gotState.Version)
	}
	if gotState.Nonce != 0 {
		t.Fatalf("fresh address nonce: expected 0, got %d", gotState.Nonce)
	}
}
