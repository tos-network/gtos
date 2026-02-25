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
	owner := common.HexToAddress("0xf81c536380b2dd5ef5c4ae95e1fae9b4fab2f5726677ecfa912d96b0b683e6a9")
	ns := "app:user-profile"
	key := []byte("user:42")
	value := []byte("alice")

	Put(st, owner, ns, key, value, 100, 140)

	got, meta, ok := Get(st, owner, ns, key, 99) // currentBlock 99 < expireAt 140
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
	owner := common.HexToAddress("0xb422a2991bf0212aae4f7493ff06ad5d076fa274b49c297f3fe9e29b5ba9aadc")
	ns := "app:data"
	key := []byte("k")
	oldValue := bytes.Repeat([]byte{0xaa}, 70)
	newValue := []byte{0x01, 0x02, 0x03}

	Put(st, owner, ns, key, oldValue, 10, 30)
	Put(st, owner, ns, key, newValue, 20, 40)

	got, meta, ok := Get(st, owner, ns, key, 39) // currentBlock 39 < expireAt 40
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

func TestLazyExpiryHidesExpiredRecords(t *testing.T) {
	st := newTestState(t)
	owner := common.HexToAddress("0xe8b0087eec10090b15f4fc4bc96aaa54e2d44c299564da76e1cd3184a2386b8d")

	Put(st, owner, "ns", []byte("k1"), []byte("v1"), 10, 50)
	Put(st, owner, "ns", []byte("k2"), []byte("v2"), 11, 60)

	// Before expiry: both records visible.
	if _, _, ok := Get(st, owner, "ns", []byte("k1"), 49); !ok {
		t.Fatalf("k1 should be visible at block 49")
	}
	if _, _, ok := Get(st, owner, "ns", []byte("k2"), 49); !ok {
		t.Fatalf("k2 should be visible at block 49")
	}

	// At expireAt: record treated as not found (expireAt <= currentBlock).
	if _, _, ok := Get(st, owner, "ns", []byte("k1"), 50); ok {
		t.Fatalf("k1 should be expired at block 50")
	}
	// k2 still live at block 50.
	if got, meta, ok := Get(st, owner, "ns", []byte("k2"), 50); !ok || !bytes.Equal(got, []byte("v2")) || meta.ExpireAt != 60 {
		t.Fatalf("unexpected k2 at block 50: ok=%v meta=%+v", ok, meta)
	}

	// After expiry: k2 also hidden.
	if _, _, ok := Get(st, owner, "ns", []byte("k2"), 60); ok {
		t.Fatalf("k2 should be expired at block 60")
	}

	// Overwrite k1 with a new record (simulates lazy renewal after expiry).
	Put(st, owner, "ns", []byte("k1"), []byte("v1-new"), 50, 100)
	if got, meta, ok := Get(st, owner, "ns", []byte("k1"), 50); !ok || !bytes.Equal(got, []byte("v1-new")) || meta.ExpireAt != 100 {
		t.Fatalf("k1 renewal failed: ok=%v meta=%+v", ok, meta)
	}
}
