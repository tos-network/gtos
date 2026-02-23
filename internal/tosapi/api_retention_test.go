package tosapi

import (
	"math/big"
	"testing"
)

func TestRetentionWatermarkTracksHead(t *testing.T) {
	backend := newBackendMock()
	api := NewTOSAPI(backend)

	policy := api.GetRetentionPolicy()
	if uint64(policy.RetainBlocks) != 200 {
		t.Fatalf("unexpected retainBlocks: have %d want 200", policy.RetainBlocks)
	}
	if uint64(policy.SnapshotInterval) != 1000 {
		t.Fatalf("unexpected snapshotInterval: have %d want 1000", policy.SnapshotInterval)
	}
	if uint64(policy.HeadBlock) != 1100 || uint64(policy.OldestAvailableBlock) != 901 {
		t.Fatalf("unexpected policy at head 1100: %+v", policy)
	}

	watermark := api.GetPruneWatermark()
	if uint64(watermark.HeadBlock) != 1100 || uint64(watermark.OldestAvailableBlock) != 901 {
		t.Fatalf("unexpected watermark at head 1100: %+v", watermark)
	}

	backend.current.Number = big.NewInt(1200)
	policy = api.GetRetentionPolicy()
	if uint64(policy.HeadBlock) != 1200 || uint64(policy.OldestAvailableBlock) != 1001 {
		t.Fatalf("unexpected policy at head 1200: %+v", policy)
	}
	watermark = api.GetPruneWatermark()
	if uint64(watermark.HeadBlock) != 1200 || uint64(watermark.OldestAvailableBlock) != 1001 {
		t.Fatalf("unexpected watermark at head 1200: %+v", watermark)
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
