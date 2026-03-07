package tosapi

import (
	"math/big"
	"testing"
)

func TestRetentionWatermarkTracksHead(t *testing.T) {
	backend := newBackendMock()
	api := NewTOSAPI(backend)
	retain := rpcDefaultRetainBlocks

	policy := api.GetRetentionPolicy()
	if uint64(policy.RetainBlocks) != retain {
		t.Fatalf("unexpected retainBlocks: have %d want %d", policy.RetainBlocks, retain)
	}
	if uint64(policy.SnapshotInterval) != 1000 {
		t.Fatalf("unexpected snapshotInterval: have %d want 1000", policy.SnapshotInterval)
	}
	if uint64(policy.HeadBlock) != 1100 || uint64(policy.OldestAvailableBlock) != oldestAvailableBlock(1100, retain) {
		t.Fatalf("unexpected policy at head 1100: %+v", policy)
	}

	watermark := api.GetPruneWatermark()
	if uint64(watermark.HeadBlock) != 1100 || uint64(watermark.OldestAvailableBlock) != oldestAvailableBlock(1100, retain) {
		t.Fatalf("unexpected watermark at head 1100: %+v", watermark)
	}

	nextHead := retain + 100
	backend.current.Number = new(big.Int).SetUint64(nextHead)
	policy = api.GetRetentionPolicy()
	if uint64(policy.HeadBlock) != nextHead || uint64(policy.OldestAvailableBlock) != oldestAvailableBlock(nextHead, retain) {
		t.Fatalf("unexpected policy at head %d: %+v", nextHead, policy)
	}
	watermark = api.GetPruneWatermark()
	if uint64(watermark.HeadBlock) != nextHead || uint64(watermark.OldestAvailableBlock) != oldestAvailableBlock(nextHead, retain) {
		t.Fatalf("unexpected watermark at head %d: %+v", nextHead, watermark)
	}

	backend.current.Number = big.NewInt(150)
	policy = api.GetRetentionPolicy()
	if uint64(policy.HeadBlock) != 150 || uint64(policy.OldestAvailableBlock) != 0 {
		t.Fatalf("unexpected policy at head 150: %+v", policy)
	}
	watermark = api.GetPruneWatermark()
	if uint64(watermark.HeadBlock) != 150 || uint64(watermark.OldestAvailableBlock) != 0 {
		t.Fatalf("unexpected watermark at head 150: %+v", watermark)
	}
}
