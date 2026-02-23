package kvstore

import (
	"bytes"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/params"
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

func TestPutPayloadCodecRoundTrip(t *testing.T) {
	enc, err := EncodePutPayload("app:tx", []byte("k"), []byte("v"), 10)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	dec, err := DecodePutPayload(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec.Namespace != "app:tx" || dec.TTL != 10 || !bytes.Equal(dec.Key, []byte("k")) || !bytes.Equal(dec.Value, []byte("v")) {
		t.Fatalf("decoded payload mismatch: %+v", dec)
	}
}

func TestPutPayloadCodecRejectsInvalid(t *testing.T) {
	if _, err := EncodePutPayload("", []byte("k"), []byte("v"), 10); err == nil {
		t.Fatalf("expected namespace error")
	}
	if _, err := EncodePutPayload("ns", []byte("k"), []byte("v"), 0); err == nil {
		t.Fatalf("expected ttl error")
	}
	if _, err := DecodePutPayload([]byte("bad")); err == nil {
		t.Fatalf("expected decode failure")
	}
}

func TestEstimatePutPayloadGasIncludesTTLSurcharge(t *testing.T) {
	payload, err := EncodePutPayload("ns", []byte("key"), []byte("value"), 7)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	gas, err := EstimatePutPayloadGas(payload, 7)
	if err != nil {
		t.Fatalf("estimate failed: %v", err)
	}
	base, err := intrinsicDataGas(payload)
	if err != nil {
		t.Fatalf("intrinsic failed: %v", err)
	}
	want := base + 7*params.KVTTLBlockGas
	if gas != want {
		t.Fatalf("gas mismatch: have %d want %d", gas, want)
	}
}

func TestPutGetRoundTrip(t *testing.T) {
	st := newTestState(t)
	owner := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	ns := "app:user-profile"
	key := []byte("user:42")
	value := []byte("alice")

	Put(st, owner, ns, key, value, 100, 140)

	got, meta, ok := Get(st, owner, ns, key)
	if !ok {
		t.Fatalf("expected key to exist")
	}
	if !bytes.Equal(got, value) {
		t.Fatalf("unexpected value: have %x want %x", got, value)
	}
	if !meta.Exists || meta.CreatedAt != 100 || meta.ExpireAt != 140 {
		t.Fatalf("unexpected meta: %+v", meta)
	}
}

func TestPutOverwriteTruncatesPreviousValue(t *testing.T) {
	st := newTestState(t)
	owner := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	ns := "app:data"
	key := []byte("k")
	oldValue := bytes.Repeat([]byte{0xaa}, 70)
	newValue := []byte{0x01, 0x02, 0x03}

	Put(st, owner, ns, key, oldValue, 10, 30)
	Put(st, owner, ns, key, newValue, 20, 40)

	got, meta, ok := Get(st, owner, ns, key)
	if !ok {
		t.Fatalf("expected key to exist")
	}
	if !bytes.Equal(got, newValue) {
		t.Fatalf("unexpected overwritten value: have %x want %x", got, newValue)
	}
	if meta.CreatedAt != 20 || meta.ExpireAt != 40 {
		t.Fatalf("unexpected overwritten meta: %+v", meta)
	}
}
