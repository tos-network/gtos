package client

import (
	"context"
	"errors"
	"time"
)

var ErrNotImplemented = errors.New("engine api client method not implemented")

// Config is the local engine API bridge configuration used by gtos.
type Config struct {
	Enabled        bool
	Endpoint       string
	JWTSecretFile  string
	RequestTimeout time.Duration
}

var DefaultConfig = Config{
	Enabled:        false,
	Endpoint:       "http://127.0.0.1:9595",
	JWTSecretFile:  "",
	RequestTimeout: 5 * time.Second,
}

// GetPayloadRequest describes a proposer-side payload request.
type GetPayloadRequest struct {
	ParentHash string
	Height     uint64
	Timestamp  uint64
}

// GetPayloadResponse describes the payload bundle returned by execution.
type GetPayloadResponse struct {
	PayloadCommitment string
	StateHash         string
	ReceiptsHash      string
	Payload           []byte
}

// NewPayloadRequest describes a validator-side payload verification request.
type NewPayloadRequest struct {
	Payload    []byte
	ParentHash string
}

// NewPayloadResponse describes the verification result returned by execution.
type NewPayloadResponse struct {
	Valid     bool
	StateHash string
}

// ForkchoiceState contains finalized/safe/head references.
type ForkchoiceState struct {
	HeadHash      string
	SafeHash      string
	FinalizedHash string
}

// Client is the phase-1 bridge contract used by consensus components.
type Client interface {
	GetPayload(ctx context.Context, req *GetPayloadRequest) (*GetPayloadResponse, error)
	NewPayload(ctx context.Context, req *NewPayloadRequest) (*NewPayloadResponse, error)
	ForkchoiceUpdated(ctx context.Context, state *ForkchoiceState) error
}

// RPCClient is a placeholder implementation for week-1 scaffolding.
type RPCClient struct {
	cfg Config
}

func NewRPCClient(cfg Config) *RPCClient {
	return &RPCClient{cfg: cfg}
}

func (c *RPCClient) Config() Config {
	return c.cfg
}

func (c *RPCClient) GetPayload(_ context.Context, _ *GetPayloadRequest) (*GetPayloadResponse, error) {
	return nil, ErrNotImplemented
}

func (c *RPCClient) NewPayload(_ context.Context, _ *NewPayloadRequest) (*NewPayloadResponse, error) {
	return nil, ErrNotImplemented
}

func (c *RPCClient) ForkchoiceUpdated(_ context.Context, _ *ForkchoiceState) error {
	return ErrNotImplemented
}
