package tos

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	engineclient "github.com/tos-network/gtos/engineapi/client"
)

type stubEngineClient struct {
	newPayloadResp *engineclient.NewPayloadResponse
	newPayloadErr  error
}

func (s *stubEngineClient) GetPayload(context.Context, *engineclient.GetPayloadRequest) (*engineclient.GetPayloadResponse, error) {
	return nil, engineclient.ErrNotImplemented
}

func (s *stubEngineClient) NewPayload(context.Context, *engineclient.NewPayloadRequest) (*engineclient.NewPayloadResponse, error) {
	if s.newPayloadErr != nil {
		return nil, s.newPayloadErr
	}
	if s.newPayloadResp == nil {
		return &engineclient.NewPayloadResponse{Valid: true}, nil
	}
	return s.newPayloadResp, nil
}

func (s *stubEngineClient) ForkchoiceUpdated(context.Context, *engineclient.ForkchoiceState) error {
	return engineclient.ErrNotImplemented
}

func makeEngineValidationTestBlock(stateRoot common.Hash) *types.Block {
	header := &types.Header{
		ParentHash: common.HexToHash("0x1"),
		Number:     common.Big1,
		Time:       uint64(time.Now().Unix()),
		Root:       stateRoot,
	}
	return types.NewBlockWithHeader(header)
}

func TestValidateImportedBlockWithEngineNoClient(t *testing.T) {
	node := &TOS{}
	block := makeEngineValidationTestBlock(common.HexToHash("0x10"))
	if err := node.validateImportedBlockWithEngine(block); err != nil {
		t.Fatalf("expected nil error without engine client, got %v", err)
	}
}

func TestValidateImportedBlockWithEngineRejectsInvalidFlag(t *testing.T) {
	node := &TOS{
		engineAPIClient: &stubEngineClient{
			newPayloadResp: &engineclient.NewPayloadResponse{Valid: false, StateHash: ""},
		},
	}
	block := makeEngineValidationTestBlock(common.HexToHash("0x20"))
	if err := node.validateImportedBlockWithEngine(block); err == nil {
		t.Fatalf("expected rejection when engine returns valid=false")
	}
}

func TestValidateImportedBlockWithEngineAcceptsNotImplemented(t *testing.T) {
	node := &TOS{
		engineAPIClient: &stubEngineClient{
			newPayloadErr: engineclient.ErrNotImplemented,
		},
	}
	block := makeEngineValidationTestBlock(common.HexToHash("0x30"))
	if err := node.validateImportedBlockWithEngine(block); err != nil {
		t.Fatalf("expected nil error on not implemented, got %v", err)
	}
}

func TestValidateImportedBlockWithEngineAcceptsOtherEngineErrorsAsFallback(t *testing.T) {
	node := &TOS{
		engineAPIClient: &stubEngineClient{
			newPayloadErr: errors.New("temporary engine failure"),
		},
	}
	block := makeEngineValidationTestBlock(common.HexToHash("0x40"))
	if err := node.validateImportedBlockWithEngine(block); err != nil {
		t.Fatalf("expected nil error on engine fallback path, got %v", err)
	}
}

func TestValidateImportedBlockWithEngineRejectsInvalidStateHashText(t *testing.T) {
	node := &TOS{
		engineAPIClient: &stubEngineClient{
			newPayloadResp: &engineclient.NewPayloadResponse{
				Valid:     true,
				StateHash: "not-a-hash",
			},
		},
	}
	block := makeEngineValidationTestBlock(common.HexToHash("0x50"))
	if err := node.validateImportedBlockWithEngine(block); err == nil {
		t.Fatalf("expected error for invalid engine state hash")
	}
}

func TestValidateImportedBlockWithEngineRejectsStateMismatch(t *testing.T) {
	node := &TOS{
		engineAPIClient: &stubEngineClient{
			newPayloadResp: &engineclient.NewPayloadResponse{
				Valid:     true,
				StateHash: common.HexToHash("0xabcd").Hex(),
			},
		},
	}
	block := makeEngineValidationTestBlock(common.HexToHash("0x60"))
	if err := node.validateImportedBlockWithEngine(block); err == nil {
		t.Fatalf("expected mismatch error when engine state differs from block root")
	}
}

func TestValidateImportedBlockWithEngineAcceptsStateMatch(t *testing.T) {
	root := common.HexToHash("0x70")
	node := &TOS{
		engineAPIClient: &stubEngineClient{
			newPayloadResp: &engineclient.NewPayloadResponse{
				Valid:     true,
				StateHash: root.Hex(),
			},
		},
	}
	block := makeEngineValidationTestBlock(root)
	if err := node.validateImportedBlockWithEngine(block); err != nil {
		t.Fatalf("expected nil error for matching engine state hash, got %v", err)
	}
}
