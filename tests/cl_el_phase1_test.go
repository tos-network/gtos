package tests

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tos-network/gtos/common/hexutil"
	engineclient "github.com/tos-network/gtos/engineapi/client"
	"github.com/tos-network/gtos/rpc"
)

type phase1GetPayloadReq struct {
	ParentHash string `json:"parentHash"`
	Height     uint64 `json:"height"`
	Timestamp  uint64 `json:"timestamp"`
}

type phase1GetPayloadResp struct {
	Payload           hexutil.Bytes `json:"payload"`
	PayloadCommitment string `json:"payloadCommitment"`
	StateHash         string `json:"stateHash"`
	ReceiptsHash      string `json:"receiptsHash"`
}

type phase1NewPayloadReq struct {
	Payload    hexutil.Bytes `json:"payload"`
	ParentHash string `json:"parent_hash"`
}

type phase1NewPayloadResp struct {
	Valid     bool   `json:"valid"`
	StateHash string `json:"state_hash"`
}

type phase1ForkchoiceReq struct {
	HeadHash      string `json:"head_hash"`
	SafeHash      string `json:"safe_hash"`
	FinalizedHash string `json:"finalized_hash"`
}

type phase1EngineService struct {
	lastForkchoice phase1ForkchoiceReq
}

func (phase1EngineService) GetPayload(req phase1GetPayloadReq) (*phase1GetPayloadResp, error) {
	if req.ParentHash == "" {
		return nil, errors.New("missing parent hash")
	}
	return &phase1GetPayloadResp{
		Payload:           hexutil.Bytes{0x01, 0x02},
		PayloadCommitment: "0xpc",
		StateHash:         "0xstate",
		ReceiptsHash:      "0xreceipts",
	}, nil
}

func (s *phase1EngineService) New_payload(req phase1NewPayloadReq) (*phase1NewPayloadResp, error) {
	if req.ParentHash == "" {
		return nil, errors.New("missing parent hash")
	}
	return &phase1NewPayloadResp{Valid: true, StateHash: "0xstate"}, nil
}

func (s *phase1EngineService) Forkchoice_updated(req phase1ForkchoiceReq) (struct{}, error) {
	s.lastForkchoice = req
	return struct{}{}, nil
}

func TestCLELPhase1EngineClientSmoke(t *testing.T) {
	server := rpc.NewServer()
	svc := &phase1EngineService{}
	if err := server.RegisterName("engine", svc); err != nil {
		t.Fatalf("register engine service: %v", err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()

	client := engineclient.NewRPCClient(engineclient.Config{
		Enabled:        true,
		Endpoint:       httpServer.URL,
		RequestTimeout: 2 * time.Second,
	})

	getPayloadResp, err := client.GetPayload(context.Background(), &engineclient.GetPayloadRequest{
		ParentHash: "0xabc",
		Height:     10,
		Timestamp:  100,
	})
	if err != nil {
		t.Fatalf("GetPayload failed: %v", err)
	}
	if len(getPayloadResp.Payload) != 2 || getPayloadResp.PayloadCommitment != "0xpc" {
		t.Fatalf("unexpected get payload response: %+v", getPayloadResp)
	}

	newPayloadResp, err := client.NewPayload(context.Background(), &engineclient.NewPayloadRequest{
		Payload:    []byte{0xaa, 0xbb},
		ParentHash: "0xabc",
	})
	if err != nil {
		t.Fatalf("NewPayload failed: %v", err)
	}
	if !newPayloadResp.Valid || newPayloadResp.StateHash != "0xstate" {
		t.Fatalf("unexpected new payload response: %+v", newPayloadResp)
	}

	if err := client.ForkchoiceUpdated(context.Background(), &engineclient.ForkchoiceState{
		HeadHash:      "0x10",
		SafeHash:      "0x09",
		FinalizedHash: "0x08",
	}); err != nil {
		t.Fatalf("ForkchoiceUpdated failed: %v", err)
	}
	if svc.lastForkchoice.HeadHash != "0x10" || svc.lastForkchoice.SafeHash != "0x09" || svc.lastForkchoice.FinalizedHash != "0x08" {
		t.Fatalf("unexpected forkchoice payload: %+v", svc.lastForkchoice)
	}
}
