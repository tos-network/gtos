package core

import (
	"bytes"
	"testing"

	"github.com/tos-network/gtos/params"
)

func TestSetCodePayloadCodec(t *testing.T) {
	code := []byte{0x60, 0x00, 0x60, 0x01}
	enc, err := EncodeSetCodePayload(128, code)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	dec, err := DecodeSetCodePayload(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec.TTL != 128 {
		t.Fatalf("ttl mismatch: have %d want %d", dec.TTL, 128)
	}
	if !bytes.Equal(dec.Code, code) {
		t.Fatalf("code mismatch: have %x want %x", dec.Code, code)
	}
}

func TestSetCodePayloadRejectsInvalid(t *testing.T) {
	if _, err := EncodeSetCodePayload(0, []byte{0x01}); err == nil {
		t.Fatalf("expected encode error for ttl=0")
	}
	if _, err := DecodeSetCodePayload(nil); err == nil {
		t.Fatalf("expected decode error for empty payload")
	}
}

func TestEstimateSetCodePayloadGasIncludesTTLSurcharge(t *testing.T) {
	code := []byte{0x00, 0x01}
	ttl := uint64(9)
	payload, err := EncodeSetCodePayload(ttl, code)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	base, err := IntrinsicGas(payload, nil, true, true, true)
	if err != nil {
		t.Fatalf("intrinsic gas failed: %v", err)
	}
	total, err := EstimateSetCodePayloadGas(payload, ttl)
	if err != nil {
		t.Fatalf("estimate failed: %v", err)
	}
	want := base + ttl*params.SetCodeTTLBlockGas
	if total != want {
		t.Fatalf("unexpected gas: have %d want %d", total, want)
	}
}
