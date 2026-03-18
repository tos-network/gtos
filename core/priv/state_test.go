package priv

import (
	"math"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/crypto/ristretto255"
)

func newTestState(t *testing.T) *state.StateDB {
	t.Helper()
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	s, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	return s
}

// testCiphertext builds a deterministic ciphertext from a seed byte.
// The bytes are not valid ristretto255 points, so only use for storage
// round-trip tests, not for arithmetic.
func testCiphertext(seed byte) Ciphertext {
	var ct Ciphertext
	for i := 0; i < CiphertextSize; i++ {
		ct.Commitment[i] = seed + byte(i)
		ct.Handle[i] = seed + 0x40 + byte(i)
	}
	return ct
}

func TestGetSetAccountState(t *testing.T) {
	st := newTestState(t)
	addr := common.HexToAddress("0xBEEF")
	in := AccountState{
		Ciphertext: testCiphertext(0x33),
		Version:    42,
		Nonce:      7,
	}
	SetAccountState(st, addr, in)
	out := GetAccountState(st, addr)

	if out.Ciphertext.Commitment != in.Ciphertext.Commitment {
		t.Fatal("Commitment mismatch")
	}
	if out.Ciphertext.Handle != in.Ciphertext.Handle {
		t.Fatal("Handle mismatch")
	}
	if out.Version != in.Version {
		t.Fatalf("Version mismatch: got %d want %d", out.Version, in.Version)
	}
	if out.Nonce != in.Nonce {
		t.Fatalf("Nonce mismatch: got %d want %d", out.Nonce, in.Nonce)
	}
}

func TestGetSetPrivNonce(t *testing.T) {
	st := newTestState(t)
	addr := common.HexToAddress("0xAAAA")

	// Initial state: nonce should be 0.
	SetAccountState(st, addr, AccountState{Nonce: 0})
	if got := GetPrivNonce(st, addr); got != 0 {
		t.Fatalf("initial nonce: got %d want 0", got)
	}

	// Increment twice.
	if _, err := IncrementPrivNonce(st, addr); err != nil {
		t.Fatal(err)
	}
	if _, err := IncrementPrivNonce(st, addr); err != nil {
		t.Fatal(err)
	}
	if got := GetPrivNonce(st, addr); got != 2 {
		t.Fatalf("after two increments: got %d want 2", got)
	}
}

func TestIncrementVersion(t *testing.T) {
	st := newTestState(t)
	addr := common.HexToAddress("0xB00B")

	SetAccountState(st, addr, AccountState{Version: 0})
	next, err := IncrementVersion(st, addr)
	if err != nil {
		t.Fatalf("IncrementVersion: %v", err)
	}
	if next != 1 {
		t.Fatalf("expected version 1, got %d", next)
	}
}

func TestIncrementVersionOverflow(t *testing.T) {
	st := newTestState(t)
	addr := common.HexToAddress("0xDEAD")

	SetAccountState(st, addr, AccountState{Version: math.MaxUint64})
	_, err := IncrementVersion(st, addr)
	if err == nil {
		t.Fatal("expected overflow error")
	}
	if err != ErrVersionOverflow {
		t.Fatalf("expected ErrVersionOverflow, got %v", err)
	}
}

func TestIncrementPrivNonceOverflow(t *testing.T) {
	st := newTestState(t)
	addr := common.HexToAddress("0xDEAD")

	SetAccountState(st, addr, AccountState{Nonce: math.MaxUint64})
	_, err := IncrementPrivNonce(st, addr)
	if err == nil {
		t.Fatal("expected overflow error")
	}
	if err != ErrNonceOverflow {
		t.Fatalf("expected ErrNonceOverflow, got %v", err)
	}
}

func TestPrivNonceDoesNotAffectPublicNonce(t *testing.T) {
	st := newTestState(t)
	addr := common.HexToAddress("0xCAFE")

	// Set a public nonce via StateDB.
	st.SetNonce(addr, 100)

	// Set priv state with nonce=0, then increment priv nonce.
	SetAccountState(st, addr, AccountState{Nonce: 0})
	if _, err := IncrementPrivNonce(st, addr); err != nil {
		t.Fatal(err)
	}
	if _, err := IncrementPrivNonce(st, addr); err != nil {
		t.Fatal(err)
	}

	// Public nonce should be unchanged.
	if pubNonce := st.GetNonce(addr); pubNonce != 100 {
		t.Fatalf("public nonce changed: got %d want 100", pubNonce)
	}
	// Priv nonce should be 2.
	if privNonce := GetPrivNonce(st, addr); privNonce != 2 {
		t.Fatalf("priv nonce: got %d want 2", privNonce)
	}
}

func TestAddSubCiphertexts(t *testing.T) {
	gen := ristretto255.NewGeneratorElement().Bytes()
	id := ristretto255.NewIdentityElement().Bytes()
	var genWord, idWord [32]byte
	copy(genWord[:], gen)
	copy(idWord[:], id)

	a := Ciphertext{Commitment: genWord, Handle: idWord}
	b := Ciphertext{Commitment: genWord, Handle: idWord}

	// Add: a + b
	sum, err := AddCiphertexts(a, b)
	if err != nil {
		t.Fatalf("AddCiphertexts: %v", err)
	}

	// Sub: (a + b) - b == a
	diff, err := SubCiphertexts(sum, b)
	if err != nil {
		t.Fatalf("SubCiphertexts: %v", err)
	}
	if diff != a {
		t.Fatal("expected (a + b) - b == a")
	}
}

func TestAddScalarToCiphertext(t *testing.T) {
	zero := ZeroCiphertext()

	// Adding scalar 0 to zero ciphertext should yield zero.
	result, err := AddScalarToCiphertext(zero, 0)
	if err != nil {
		t.Fatalf("AddScalarToCiphertext(zero, 0): %v", err)
	}
	if result.Commitment != zero.Commitment {
		t.Fatal("adding 0 scalar should not change commitment")
	}
	if result.Handle != zero.Handle {
		t.Fatal("adding scalar should not change handle")
	}

	// Adding non-zero scalar: the handle should remain unchanged.
	result2, err := AddScalarToCiphertext(zero, 42)
	if err != nil {
		t.Fatalf("AddScalarToCiphertext(zero, 42): %v", err)
	}
	if result2.Handle != zero.Handle {
		t.Fatal("handle should be unchanged after scalar add")
	}
	// Commitment should have changed (no longer identity).
	if result2.Commitment == zero.Commitment {
		t.Fatal("commitment should differ after adding non-zero scalar")
	}
}
