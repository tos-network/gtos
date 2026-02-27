package uno

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

func TestAccountStateRoundtrip(t *testing.T) {
	st := newTestState(t)
	addr := common.HexToAddress("0xBEEF")
	in := AccountState{
		Ciphertext: testCiphertext(0x33),
		Version:    9,
	}
	SetAccountState(st, addr, in)
	out := GetAccountState(st, addr)
	if out.Version != in.Version {
		t.Fatalf("version mismatch: got %d want %d", out.Version, in.Version)
	}
	if out.Ciphertext != in.Ciphertext {
		t.Fatalf("ciphertext mismatch")
	}
}

func TestIncrementVersion(t *testing.T) {
	st := newTestState(t)
	addr := common.HexToAddress("0xB00B")
	SetAccountState(st, addr, AccountState{Version: 1})
	next, err := IncrementVersion(st, addr)
	if err != nil {
		t.Fatalf("IncrementVersion: %v", err)
	}
	if next != 2 {
		t.Fatalf("unexpected next version: %d", next)
	}
}

func TestIncrementVersionOverflow(t *testing.T) {
	st := newTestState(t)
	addr := common.HexToAddress("0xDEAD")
	SetAccountState(st, addr, AccountState{Version: math.MaxUint64})
	if _, err := IncrementVersion(st, addr); err == nil {
		t.Fatal("expected overflow error")
	}
}

func TestCiphertextAddSub(t *testing.T) {
	gen := ristretto255.NewGeneratorElement().Bytes()
	id := ristretto255.NewIdentityElement().Bytes()
	var genWord, idWord [32]byte
	copy(genWord[:], gen)
	copy(idWord[:], id)
	a := Ciphertext{Commitment: genWord, Handle: idWord}
	b := Ciphertext{Commitment: genWord, Handle: idWord}

	sum, err := AddCiphertexts(a, b)
	if err != nil {
		t.Fatalf("AddCiphertexts: %v", err)
	}
	diff, err := SubCiphertexts(sum, b)
	if err != nil {
		t.Fatalf("SubCiphertexts: %v", err)
	}
	if diff != a {
		t.Fatalf("unexpected subtract result")
	}
}

func TestAddCiphertextToAccount(t *testing.T) {
	st := newTestState(t)
	addr := common.HexToAddress("0xABCD")
	gen := ristretto255.NewGeneratorElement().Bytes()
	id := ristretto255.NewIdentityElement().Bytes()
	var genWord, idWord [32]byte
	copy(genWord[:], gen)
	copy(idWord[:], id)
	delta := Ciphertext{Commitment: genWord, Handle: idWord}

	if err := AddCiphertextToAccount(st, addr, delta); err != nil {
		t.Fatalf("AddCiphertextToAccount: %v", err)
	}
	got := GetAccountState(st, addr)
	if got.Version != 1 {
		t.Fatalf("version mismatch: got %d want 1", got.Version)
	}
	if got.Ciphertext != delta {
		t.Fatalf("ciphertext mismatch")
	}
}

func TestSetCiphertextForAccount(t *testing.T) {
	st := newTestState(t)
	addr := common.HexToAddress("0xAAAA")
	initial := testCiphertext(0x10)
	next := testCiphertext(0x20)

	SetAccountState(st, addr, AccountState{Ciphertext: initial, Version: 3})
	if err := SetCiphertextForAccount(st, addr, next); err != nil {
		t.Fatalf("SetCiphertextForAccount: %v", err)
	}
	got := GetAccountState(st, addr)
	if got.Version != 4 {
		t.Fatalf("version mismatch: got %d want 4", got.Version)
	}
	if !CiphertextEqual(got.Ciphertext, next) {
		t.Fatalf("ciphertext mismatch")
	}
}
