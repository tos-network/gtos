package bft

import (
	"errors"
	"fmt"
	"testing"

	"github.com/tos-network/gtos/common"
)

func testVote(height, round uint64, block string, validator string, weight uint64) Vote {
	return Vote{
		Height:    height,
		Round:     round,
		BlockHash: common.HexToHash(block),
		Validator: common.HexToAddress(validator),
		Weight:    weight,
		Signature: []byte{0x01},
	}
}

func TestRequiredQuorumWeight(t *testing.T) {
	if got, want := RequiredQuorumWeight(100), uint64(67); got != want {
		t.Fatalf("unexpected quorum weight: have %d want %d", got, want)
	}
	if got, want := RequiredQuorumWeight(3), uint64(3); got != want {
		t.Fatalf("unexpected quorum weight for 3: have %d want %d", got, want)
	}
}

func TestVotePoolBuildQC(t *testing.T) {
	pool := NewVotePool(30) // required = 21
	v1 := testVote(10, 1, "0x100", "0x1001", 10)
	v2 := testVote(10, 1, "0x100", "0x1002", 11)

	if added, err := pool.AddVote(v1); err != nil || !added {
		t.Fatalf("unexpected add result for v1: added=%v err=%v", added, err)
	}
	if qc, ok := pool.BuildQC(10, 1, common.HexToHash("0x100")); ok || qc != nil {
		t.Fatalf("qc should not be ready after one vote")
	}

	if added, err := pool.AddVote(v2); err != nil || !added {
		t.Fatalf("unexpected add result for v2: added=%v err=%v", added, err)
	}
	qc, ok := pool.BuildQC(10, 1, common.HexToHash("0x100"))
	if !ok || qc == nil {
		t.Fatalf("expected qc after quorum")
	}
	if err := qc.Verify(); err != nil {
		t.Fatalf("expected valid qc, got err=%v", err)
	}
	if qc.TotalWeight != 21 {
		t.Fatalf("unexpected qc total weight: have %d want %d", qc.TotalWeight, 21)
	}
}

func TestVotePoolDuplicateAndEquivocation(t *testing.T) {
	pool := NewVotePool(30)
	v := testVote(20, 2, "0x200", "0x2001", 10)
	if _, err := pool.AddVote(v); err != nil {
		t.Fatalf("unexpected err adding vote: %v", err)
	}
	added, err := pool.AddVote(v)
	if err != nil {
		t.Fatalf("duplicate vote should not error: %v", err)
	}
	if added {
		t.Fatalf("duplicate vote should not be marked added")
	}

	equiv := testVote(20, 2, "0x201", "0x2001", 10)
	if _, err := pool.AddVote(equiv); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("expected equivocation error, got: %v", err)
	}
}

type mockBroadcaster struct {
	votes int
	qcs   int
}

func (m *mockBroadcaster) BroadcastVote(Vote) error {
	m.votes++
	return nil
}

func (m *mockBroadcaster) BroadcastQC(*QC) error {
	m.qcs++
	return nil
}

func TestReactorEmitsQC(t *testing.T) {
	pool := NewVotePool(20) // required = 14
	bc := &mockBroadcaster{}
	var qcCount int
	r := NewReactor(pool, bc, func(*QC) { qcCount++ })

	if err := r.ProposeVote(testVote(30, 1, "0x300", "0x3001", 7)); err != nil {
		t.Fatalf("propose vote failed: %v", err)
	}
	if bc.votes != 1 {
		t.Fatalf("unexpected broadcasted votes: have %d want %d", bc.votes, 1)
	}

	if qc, err := r.HandleIncomingVote(testVote(30, 1, "0x300", "0x3002", 7)); err != nil || qc == nil {
		t.Fatalf("expected qc from incoming vote: qc=%v err=%v", qc, err)
	}
	if qcCount != 1 || bc.qcs != 1 {
		t.Fatalf("unexpected qc callbacks/broadcasts: callbacks=%d broadcasts=%d", qcCount, bc.qcs)
	}
}

func TestReactorSkipsDuplicateProposals(t *testing.T) {
	pool := NewVotePool(20) // required = 14
	bc := &mockBroadcaster{}
	r := NewReactor(pool, bc, nil)
	v := testVote(31, 1, "0x301", "0x3011", 7)

	if err := r.ProposeVote(v); err != nil {
		t.Fatalf("first propose vote failed: %v", err)
	}
	if err := r.ProposeVote(v); err != nil {
		t.Fatalf("duplicate propose vote failed: %v", err)
	}
	if bc.votes != 1 {
		t.Fatalf("duplicate proposal should not rebroadcast, have %d want %d", bc.votes, 1)
	}
}

func TestReactorProposeVoteCanEmitQC(t *testing.T) {
	pool := NewVotePool(10) // required = 7
	bc := &mockBroadcaster{}
	var qcCount int
	r := NewReactor(pool, bc, func(*QC) { qcCount++ })

	if err := r.ProposeVote(testVote(32, 1, "0x302", "0x3021", 7)); err != nil {
		t.Fatalf("propose vote failed: %v", err)
	}
	if bc.votes != 1 {
		t.Fatalf("unexpected vote broadcasts: have %d want %d", bc.votes, 1)
	}
	if bc.qcs != 1 || qcCount != 1 {
		t.Fatalf("propose vote should emit qc immediately: callbacks=%d broadcasts=%d", qcCount, bc.qcs)
	}
}

func TestVotePoolSequentialQCsWithPruning(t *testing.T) {
	pool := NewVotePool(30) // required = 21
	validators := []string{"0x4001", "0x4002", "0x4003"}
	const (
		round        = uint64(1)
		voteWeight   = uint64(7)
		totalHeights = 128
	)

	for height := uint64(1); height <= totalHeights; height++ {
		blockHex := fmt.Sprintf("0x%x", 0x5000+height)
		blockHash := common.HexToHash(blockHex)

		for _, validator := range validators {
			v := testVote(height, round, blockHex, validator, voteWeight)
			added, err := pool.AddVote(v)
			if err != nil {
				t.Fatalf("unexpected vote add error at height %d validator %s: %v", height, validator, err)
			}
			if !added {
				t.Fatalf("vote should be newly added at height %d validator %s", height, validator)
			}
		}

		qc, ok := pool.BuildQC(height, round, blockHash)
		if !ok || qc == nil {
			t.Fatalf("expected QC at height %d", height)
		}
		if err := qc.Verify(); err != nil {
			t.Fatalf("qc verify failed at height %d: %v", height, err)
		}
		if qc.Height != height || qc.Round != round || qc.BlockHash != blockHash {
			t.Fatalf(
				"unexpected qc content at height %d: got (height=%d round=%d hash=%s)",
				height,
				qc.Height,
				qc.Round,
				qc.BlockHash,
			)
		}
		if qc.TotalWeight != 21 {
			t.Fatalf("unexpected qc weight at height %d: have %d want %d", height, qc.TotalWeight, 21)
		}

		pool.PruneBelow(height)
		if height > 1 {
			oldBlockHash := common.HexToHash(fmt.Sprintf("0x%x", 0x5000+height-1))
			oldTotal, oldVotes := pool.Tally(height-1, round, oldBlockHash)
			if oldTotal != 0 || oldVotes != 0 {
				t.Fatalf(
					"expected pruned height %d to be removed, got total=%d votes=%d",
					height-1,
					oldTotal,
					oldVotes,
				)
			}
		}
		currentTotal, currentVotes := pool.Tally(height, round, blockHash)
		if currentTotal != 21 || currentVotes != len(validators) {
			t.Fatalf(
				"expected current height tally after prune (total=21 votes=%d), got total=%d votes=%d",
				len(validators),
				currentTotal,
				currentVotes,
			)
		}
	}
}
