package tosapi

import (
	"math/big"
	"testing"
	"testing/quick"
)

func TestOldestAvailableBlockQuickProperties(t *testing.T) {
	prop := func(head uint64, retain uint64) bool {
		got := oldestAvailableBlock(head, retain)

		var want uint64
		if retain == 0 || head < retain {
			want = 0
		} else {
			want = head - retain + 1
		}
		if got != want {
			return false
		}
		return got <= head
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 2000}); err != nil {
		t.Fatalf("oldestAvailableBlock property failed: %v", err)
	}
}

func TestOldestAvailableBlockNoOverflowAtMaxUint64(t *testing.T) {
	const max = ^uint64(0)
	if got, want := oldestAvailableBlock(max, max), uint64(1); got != want {
		t.Fatalf("unexpected oldest at max/max: have %d want %d", got, want)
	}
	if got := oldestAvailableBlock(max, 0); got != 0 {
		t.Fatalf("unexpected oldest at max/0: have %d want 0", got)
	}
}

func TestEnforceHistoryRetentionBoundaryQuick(t *testing.T) {
	prop := func(head uint32) bool {
		backend := newBackendMock()
		backend.current.Number = new(big.Int).SetUint64(uint64(head))

		oldest := oldestAvailableBlock(uint64(head), rpcDefaultRetainBlocks)
		if oldest > 0 {
			err := enforceHistoryRetentionByBlockNumber(backend, oldest-1)
			rpcErr, ok := err.(*rpcAPIError)
			if !ok || rpcErr.code != rpcErrHistoryPruned {
				return false
			}
		}
		if err := enforceHistoryRetentionByBlockNumber(backend, oldest); err != nil {
			return false
		}
		if err := enforceHistoryRetentionByBlockNumber(backend, uint64(head)); err != nil {
			return false
		}
		return true
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 2000}); err != nil {
		t.Fatalf("retention boundary property failed: %v", err)
	}
}
