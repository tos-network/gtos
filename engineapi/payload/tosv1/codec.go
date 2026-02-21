package tosv1

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const (
	// Version is the supported tos_v1 payload format version.
	Version byte = 1

	headerSize     = 1 + 4 // version + tx_count(u32)
	txLengthPrefix = 4     // tx_len(u32)
)

var (
	ErrPayloadTooShort   = errors.New("tos_v1 payload too short")
	ErrUnsupportedFormat = errors.New("unsupported tos_v1 payload version")
	ErrPayloadMalformed  = errors.New("malformed tos_v1 payload")
)

// EmptyPayloadBytes returns a canonical encoded empty tos_v1 payload.
func EmptyPayloadBytes() []byte {
	return []byte{Version, 0, 0, 0, 0}
}

// Encode serializes tx blobs as a tos_v1 payload.
func Encode(txBlobs [][]byte) ([]byte, error) {
	if len(txBlobs) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: tx count exceeds u32", ErrPayloadMalformed)
	}
	total := uint64(headerSize)
	for i, blob := range txBlobs {
		if len(blob) > math.MaxUint32 {
			return nil, fmt.Errorf("%w: tx[%d] size exceeds u32", ErrPayloadMalformed, i)
		}
		total += uint64(txLengthPrefix + len(blob))
		if total > math.MaxInt {
			return nil, fmt.Errorf("%w: payload exceeds max int", ErrPayloadMalformed)
		}
	}

	out := make([]byte, total)
	out[0] = Version
	binary.BigEndian.PutUint32(out[1:5], uint32(len(txBlobs)))
	offset := headerSize
	for _, blob := range txBlobs {
		binary.BigEndian.PutUint32(out[offset:offset+txLengthPrefix], uint32(len(blob)))
		offset += txLengthPrefix
		copy(out[offset:offset+len(blob)], blob)
		offset += len(blob)
	}
	return out, nil
}

// Decode parses a tos_v1 payload into tx blobs.
func Decode(payload []byte) ([][]byte, error) {
	if len(payload) < headerSize {
		return nil, ErrPayloadTooShort
	}
	if payload[0] != Version {
		return nil, fmt.Errorf("%w: got %d", ErrUnsupportedFormat, payload[0])
	}

	txCount := int(binary.BigEndian.Uint32(payload[1:5]))
	out := make([][]byte, 0, txCount)
	offset := headerSize
	for i := 0; i < txCount; i++ {
		if len(payload)-offset < txLengthPrefix {
			return nil, fmt.Errorf("%w: missing tx[%d] length", ErrPayloadMalformed, i)
		}
		size := int(binary.BigEndian.Uint32(payload[offset : offset+txLengthPrefix]))
		offset += txLengthPrefix
		if size < 0 || len(payload)-offset < size {
			return nil, fmt.Errorf("%w: truncated tx[%d] bytes", ErrPayloadMalformed, i)
		}
		tx := make([]byte, size)
		copy(tx, payload[offset:offset+size])
		out = append(out, tx)
		offset += size
	}
	if offset != len(payload) {
		return nil, fmt.Errorf("%w: trailing bytes", ErrPayloadMalformed)
	}
	return out, nil
}
