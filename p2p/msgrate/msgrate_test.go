package msgrate

import "testing"

func TestCapacityOverflow(t *testing.T) {
	tracker := NewTracker(nil, 1)
	tracker.Update(1, 1, 100000)
	cap := tracker.Capacity(1, 10000000)
	if int32(cap) < 0 {
		t.Fatalf("Negative: %v", int32(cap))
	}
}
