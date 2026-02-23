package tosapi

import (
	"math/big"
	"testing"
)

func classifyRetentionErrCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	return rpcErr.code
}

func TestRetentionBoundaryDeterministicAcrossNodes(t *testing.T) {
	heads := []uint64{0, 1, 150, 200, 201, 900, 901, 1100, 1200}
	for _, head := range heads {
		nodes := []*backendMock{newBackendMock(), newBackendMock(), newBackendMock()}
		apis := make([]*TOSAPI, 0, len(nodes))
		for _, node := range nodes {
			node.current.Number = new(big.Int).SetUint64(head)
			apis = append(apis, NewTOSAPI(node))
		}

		refPolicy := apis[0].GetRetentionPolicy()
		refOldest := uint64(refPolicy.OldestAvailableBlock)
		wantOldest := oldestAvailableBlock(head, rpcDefaultRetainBlocks)
		if refOldest != wantOldest {
			t.Fatalf("head=%d policy oldest mismatch: have=%d want=%d", head, refOldest, wantOldest)
		}
		for i := 1; i < len(apis); i++ {
			policy := apis[i].GetRetentionPolicy()
			if uint64(policy.OldestAvailableBlock) != refOldest {
				t.Fatalf("head=%d node=%d oldest mismatch: have=%d want=%d",
					head, i, uint64(policy.OldestAvailableBlock), refOldest)
			}
		}

		// Query outcomes must match across nodes for the same request block.
		requests := []uint64{0, refOldest, head}
		if refOldest > 0 {
			requests = append(requests, refOldest-1)
		}
		for _, req := range requests {
			refCode := classifyRetentionErrCode(t, enforceHistoryRetentionByBlockNumber(nodes[0], req))
			for i := 1; i < len(nodes); i++ {
				code := classifyRetentionErrCode(t, enforceHistoryRetentionByBlockNumber(nodes[i], req))
				if code != refCode {
					t.Fatalf("head=%d req=%d node=%d retention code mismatch: have=%d want=%d", head, req, i, code, refCode)
				}
			}
			if req < refOldest && refCode != rpcErrHistoryPruned {
				t.Fatalf("head=%d req=%d expected history_pruned code=%d have=%d", head, req, rpcErrHistoryPruned, refCode)
			}
			if req >= refOldest && refCode != 0 {
				t.Fatalf("head=%d req=%d expected acceptance but got code=%d", head, req, refCode)
			}
		}
	}
}
