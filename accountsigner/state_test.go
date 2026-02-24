package accountsigner

import (
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
)

func newTestState(t *testing.T) *state.StateDB {
	t.Helper()
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	s, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	return s
}

func TestGetMissing(t *testing.T) {
	st := newTestState(t)
	addr := common.HexToAddress("0xf81c536380b2dd5ef5c4ae95e1fae9b4fab2f5726677ecfa912d96b0b683e6a9")
	_, _, ok := Get(st, addr)
	if ok {
		t.Fatalf("expected no signer metadata")
	}
}

func TestSetGetRoundTrip(t *testing.T) {
	st := newTestState(t)
	addr := common.HexToAddress("0xf81c536380b2dd5ef5c4ae95e1fae9b4fab2f5726677ecfa912d96b0b683e6a9")
	Set(st, addr, "ed25519", testEd25519PubHex)

	signerType, signerValue, ok := Get(st, addr)
	if !ok {
		t.Fatalf("expected signer metadata")
	}
	if signerType != "ed25519" || signerValue != testEd25519PubHex {
		t.Fatalf("unexpected signer metadata type=%q value=%q", signerType, signerValue)
	}
}

func TestSetOverwriteTruncatesPreviousValue(t *testing.T) {
	st := newTestState(t)
	addr := common.HexToAddress("0xb422a2991bf0212aae4f7493ff06ad5d076fa274b49c297f3fe9e29b5ba9aadc")
	Set(st, addr, "ed25519", "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789")
	Set(st, addr, "secp256k1", "short")

	signerType, signerValue, ok := Get(st, addr)
	if !ok {
		t.Fatalf("expected signer metadata")
	}
	if signerType != "secp256k1" || signerValue != "short" {
		t.Fatalf("unexpected signer metadata type=%q value=%q", signerType, signerValue)
	}
}
