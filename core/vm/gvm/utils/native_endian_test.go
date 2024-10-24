package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPutUint64(t *testing.T) {
	b := make([]byte, 8)
	// Writing using NativeEndian
	NativeEndian.PutUint64(b, 0x0102030405060708)
	// Reading using NativeEndian
	val := NativeEndian.Uint64(b)
	require.Equal(t, uint64(0x0102030405060708), val)
}
