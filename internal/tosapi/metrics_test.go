package tosapi

import (
	"testing"

	"github.com/tos-network/gtos/metrics"
)

func TestHistoryPrunedMeterIncrements(t *testing.T) {
	m := metrics.NewMeterForced()
	defer m.Stop()

	prev := rpcHistoryPrunedMeter
	rpcHistoryPrunedMeter = m
	defer func() {
		rpcHistoryPrunedMeter = prev
	}()

	backend := newBackendMock() // head=1100, retain=200 -> oldest available=901
	before := m.Count()
	err := enforceHistoryRetentionByBlockNumber(backend, 900)
	if err == nil {
		t.Fatalf("expected history pruned error")
	}
	after := m.Count()
	if after != before+1 {
		t.Fatalf("history_pruned meter mismatch: before=%d after=%d", before, after)
	}

	// In-window request should not increment the pruned meter.
	before = after
	if err := enforceHistoryRetentionByBlockNumber(backend, 901); err != nil {
		t.Fatalf("unexpected in-window error: %v", err)
	}
	after = m.Count()
	if after != before {
		t.Fatalf("history_pruned meter changed for in-window query: before=%d after=%d", before, after)
	}
}
