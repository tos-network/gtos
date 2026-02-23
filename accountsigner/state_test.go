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
	addr := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	_, _, ok := Get(st, addr)
	if ok {
		t.Fatalf("expected no signer metadata")
	}
}

func TestSetGetRoundTrip(t *testing.T) {
	st := newTestState(t)
	addr := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	Set(st, addr, "ed25519", "z6MkiSignerValue")

	signerType, signerValue, ok := Get(st, addr)
	if !ok {
		t.Fatalf("expected signer metadata")
	}
	if signerType != "ed25519" || signerValue != "z6MkiSignerValue" {
		t.Fatalf("unexpected signer metadata type=%q value=%q", signerType, signerValue)
	}
}

func TestSetOverwriteTruncatesPreviousValue(t *testing.T) {
	st := newTestState(t)
	addr := common.HexToAddress("0x00000000000000000000000000000000000000bb")
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
