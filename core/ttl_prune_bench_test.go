package core

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/kvstore"
)

func newPruneBenchState(b *testing.B) *state.StateDB {
	b.Helper()
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		b.Fatalf("create statedb: %v", err)
	}
	return st
}

func benchAddress(i int) common.Address {
	var out common.Address
	binary.BigEndian.PutUint64(out[12:], uint64(i+1))
	return out
}

func seedCodeExpiryBenchRecords(st *state.StateDB, records int, expireAt uint64) {
	for i := 0; i < records; i++ {
		owner := benchAddress(i)
		st.SetCode(owner, []byte{0x60, 0x00})
		st.SetState(owner, SetCodeCreatedAtSlot, uint64ToStateWord(expireAt-1))
		st.SetState(owner, SetCodeExpireAtSlot, uint64ToStateWord(expireAt))
		appendSetCodeExpiryIndex(st, owner, expireAt)
	}
}

func seedKVExpiryBenchRecords(st *state.StateDB, owner common.Address, records int, expireAt uint64) {
	value := []byte("bench-value")
	key := make([]byte, 8)
	for i := 0; i < records; i++ {
		binary.BigEndian.PutUint64(key, uint64(i))
		kvstore.Put(st, owner, "bench", key, value, expireAt-1, expireAt)
	}
}

func BenchmarkPruneExpiredCodeAt(b *testing.B) {
	for _, size := range []int{128, 1024, 4096} {
		size := size
		b.Run(fmt.Sprintf("records_%d", size), func(b *testing.B) {
			const expireAt = uint64(1000)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				st := newPruneBenchState(b)
				seedCodeExpiryBenchRecords(st, size, expireAt)
				if pruned := pruneExpiredCodeAt(st, expireAt); pruned != uint64(size) {
					b.Fatalf("unexpected code pruned count: have %d want %d", pruned, size)
				}
			}
		})
	}
}

func BenchmarkPruneExpiredKVAt(b *testing.B) {
	for _, size := range []int{128, 1024, 4096} {
		size := size
		b.Run(fmt.Sprintf("records_%d", size), func(b *testing.B) {
			const expireAt = uint64(1000)
			owner := common.HexToAddress("0x3ac976f9d2acd22c761751d7ae72a48c1a36bd18af168541c53037965d26e4a8")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				st := newPruneBenchState(b)
				st.SetBalance(owner, big.NewInt(1))
				seedKVExpiryBenchRecords(st, owner, size, expireAt)
				if pruned := kvstore.PruneExpiredAt(st, expireAt); pruned != uint64(size) {
					b.Fatalf("unexpected kv pruned count: have %d want %d", pruned, size)
				}
			}
		})
	}
}
