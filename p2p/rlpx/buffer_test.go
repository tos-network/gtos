package rlpx

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tos-network/gtos/common/hexutil"
)

func TestReadBufferReset(t *testing.T) {
	reader := bytes.NewReader(hexutil.MustDecode("0x010202030303040505"))
	var b readBuffer

	s1, _ := b.read(reader, 1)
	s2, _ := b.read(reader, 2)
	s3, _ := b.read(reader, 3)

	assert.Equal(t, []byte{1}, s1)
	assert.Equal(t, []byte{2, 2}, s2)
	assert.Equal(t, []byte{3, 3, 3}, s3)

	b.reset()

	s4, _ := b.read(reader, 1)
	s5, _ := b.read(reader, 2)

	assert.Equal(t, []byte{4}, s4)
	assert.Equal(t, []byte{5, 5}, s5)

	s6, err := b.read(reader, 2)

	assert.EqualError(t, err, "EOF")
	assert.Nil(t, s6)
}
