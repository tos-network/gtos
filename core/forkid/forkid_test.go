package forkid

import (
	"bytes"
	"hash/crc32"
	"math"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/rlp"
)

// TestCreation tests that different genesis and fork rule combinations result in
// the correct fork ID.
func TestCreation(t *testing.T) {
	baseHash := checksumToBytes(crc32.ChecksumIEEE(params.MainnetGenesisHash[:]))
	type testcase struct {
		head uint64
		want ID
	}
	tests := []struct {
		config  *params.ChainConfig
		genesis common.Hash
		cases   []testcase
	}{
		{
			params.MainnetChainConfig,
			params.MainnetGenesisHash,
			[]testcase{
				{0, ID{Hash: baseHash, Next: 0}},
				{15050000, ID{Hash: baseHash, Next: 0}},
				{20000000, ID{Hash: baseHash, Next: 0}},
			},
		},
	}
	for i, tt := range tests {
		for j, ttt := range tt.cases {
			if have := NewID(tt.config, tt.genesis, ttt.head); have != ttt.want {
				t.Errorf("test %d, case %d: fork ID mismatch: have %x, want %x", i, j, have, ttt.want)
			}
		}
	}
}

// TestValidation tests that a local peer correctly validates and accepts a remote
// fork ID.
func TestValidation(t *testing.T) {
	baseConfig := *params.MainnetChainConfig

	baseHash := NewID(&baseConfig, params.MainnetGenesisHash, 0).Hash

	tests := []struct {
		config *params.ChainConfig
		head   uint64
		id     ID
		err    error
	}{
		{&baseConfig, 100, ID{Hash: baseHash, Next: 0}, nil},
		{&baseConfig, 100, ID{Hash: baseHash, Next: math.MaxUint64}, nil},
		{&baseConfig, 100, ID{Hash: baseHash, Next: 50}, ErrLocalIncompatibleOrStale},
		{&baseConfig, 100, ID{Hash: checksumToBytes(0xdeadbeef), Next: 0}, ErrLocalIncompatibleOrStale},
	}
	for i, tt := range tests {
		filter := newFilter(tt.config, params.MainnetGenesisHash, func() uint64 { return tt.head })
		if err := filter(tt.id); err != tt.err {
			t.Errorf("test %d: validation error mismatch: have %v, want %v", i, err, tt.err)
		}
	}
}

// Tests that IDs are properly RLP encoded (specifically important because we
// use uint32 to store the hash, but we need to encode it as [4]byte).
func TestEncoding(t *testing.T) {
	tests := []struct {
		id   ID
		want []byte
	}{
		{ID{Hash: checksumToBytes(0), Next: 0}, common.Hex2Bytes("c6840000000080")},
		{ID{Hash: checksumToBytes(0xdeadbeef), Next: 0xBADDCAFE}, common.Hex2Bytes("ca84deadbeef84baddcafe,")},
		{ID{Hash: checksumToBytes(math.MaxUint32), Next: math.MaxUint64}, common.Hex2Bytes("ce84ffffffff88ffffffffffffffff")},
	}
	for i, tt := range tests {
		have, err := rlp.EncodeToBytes(tt.id)
		if err != nil {
			t.Errorf("test %d: failed to encode forkid: %v", i, err)
			continue
		}
		if !bytes.Equal(have, tt.want) {
			t.Errorf("test %d: RLP mismatch: have %x, want %x", i, have, tt.want)
		}
	}
}
