package tosv1

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	input := [][]byte{
		{},
		{0x01, 0x02, 0x03},
		[]byte("abc"),
	}
	encoded, err := Encode(input)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(decoded) != len(input) {
		t.Fatalf("unexpected tx count: got %d want %d", len(decoded), len(input))
	}
	for i := range input {
		if !bytes.Equal(decoded[i], input[i]) {
			t.Fatalf("tx[%d] mismatch: got %x want %x", i, decoded[i], input[i])
		}
	}
}

func TestEmptyPayloadBytesDecodesToZeroTransactions(t *testing.T) {
	decoded, err := Decode(EmptyPayloadBytes())
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(decoded) != 0 {
		t.Fatalf("unexpected tx count: got %d want 0", len(decoded))
	}
}

func TestDecodeRejectsShortPayload(t *testing.T) {
	if _, err := Decode([]byte{Version, 0x00}); err == nil {
		t.Fatalf("expected short payload error")
	}
}

func TestDecodeRejectsUnsupportedVersion(t *testing.T) {
	payload := append([]byte{0x02, 0x00, 0x00, 0x00, 0x00}, []byte{}...)
	if _, err := Decode(payload); err == nil {
		t.Fatalf("expected unsupported version error")
	}
}

func TestDecodeRejectsTruncatedTxBytes(t *testing.T) {
	// version=1, tx_count=1, tx_len=4, bytes=2
	payload := []byte{Version, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0xaa, 0xbb}
	if _, err := Decode(payload); err == nil {
		t.Fatalf("expected truncated tx bytes error")
	}
}

func TestDecodeRejectsTrailingBytes(t *testing.T) {
	// version=1, tx_count=0, plus trailing bytes.
	payload := []byte{Version, 0x00, 0x00, 0x00, 0x00, 0xaa}
	if _, err := Decode(payload); err == nil {
		t.Fatalf("expected trailing bytes error")
	}
}
