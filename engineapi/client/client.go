package client

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/rpc"
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

// RPCClient implements the local Engine API bridge over JSON-RPC.
type RPCClient struct {
	cfg Config

	mu        sync.Mutex
	rpcClient *rpc.Client
	jwtSecret []byte
}

func NewRPCClient(cfg Config) *RPCClient {
	return &RPCClient{cfg: cfg}
}

func (c *RPCClient) Config() Config {
	return c.cfg
}

func (c *RPCClient) GetPayload(ctx context.Context, req *GetPayloadRequest) (*GetPayloadResponse, error) {
	if req == nil {
		return nil, errors.New("nil get payload request")
	}
	ctx, cancel := c.contextWithTimeout(ctx)
	defer cancel()

	args := getPayloadArgs{
		ParentHash: req.ParentHash,
		Height:     req.Height,
		Timestamp:  req.Timestamp,
	}
	var out getPayloadResult
	if err := c.callWithFallback(ctx, &out, []rpcMethodCall{
		{method: "engine_get_payload", arg: args},
		{method: "engine_getPayload", arg: toCamelGetPayloadArgs(args)},
	}); err != nil {
		return nil, err
	}
	return &GetPayloadResponse{
		PayloadCommitment: firstNonEmpty(out.PayloadCommitment, out.PayloadCommitmentCompat),
		StateHash:         firstNonEmpty(out.StateHash, out.StateHashCompat),
		ReceiptsHash:      firstNonEmpty(out.ReceiptsHash, out.ReceiptsHashCompat),
		Payload:           []byte(out.Payload),
	}, nil
}

func (c *RPCClient) NewPayload(ctx context.Context, req *NewPayloadRequest) (*NewPayloadResponse, error) {
	if req == nil {
		return nil, errors.New("nil new payload request")
	}
	ctx, cancel := c.contextWithTimeout(ctx)
	defer cancel()

	args := newPayloadArgs{
		Payload:    hexutil.Bytes(req.Payload),
		ParentHash: req.ParentHash,
	}
	var out newPayloadResult
	if err := c.callWithFallback(ctx, &out, []rpcMethodCall{
		{method: "engine_new_payload", arg: args},
		{method: "engine_newPayload", arg: toCamelNewPayloadArgs(args)},
	}); err != nil {
		return nil, err
	}
	return &NewPayloadResponse{
		Valid:     out.Valid,
		StateHash: firstNonEmpty(out.StateHash, out.StateHashCompat),
	}, nil
}

func (c *RPCClient) ForkchoiceUpdated(ctx context.Context, state *ForkchoiceState) error {
	if state == nil {
		return errors.New("nil forkchoice state")
	}
	ctx, cancel := c.contextWithTimeout(ctx)
	defer cancel()

	args := forkchoiceStateArgs{
		HeadHash:      state.HeadHash,
		SafeHash:      state.SafeHash,
		FinalizedHash: state.FinalizedHash,
	}
	var out struct{}
	return c.callWithFallback(ctx, &out, []rpcMethodCall{
		{method: "engine_forkchoice_updated", arg: args},
		{method: "engine_forkchoiceUpdated", arg: toCamelForkchoiceArgs(args)},
	})
}

type getPayloadArgs struct {
	ParentHash string `json:"parent_hash"`
	Height     uint64 `json:"height"`
	Timestamp  uint64 `json:"timestamp"`
}

type getPayloadArgsCamel struct {
	ParentHash string `json:"parentHash"`
	Height     uint64 `json:"height"`
	Timestamp  uint64 `json:"timestamp"`
}

type getPayloadResult struct {
	Payload                 hexutil.Bytes `json:"payload"`
	PayloadCommitment       string        `json:"payload_commitment"`
	PayloadCommitmentCompat string        `json:"payloadCommitment"`
	StateHash               string        `json:"state_hash"`
	StateHashCompat         string        `json:"stateHash"`
	ReceiptsHash            string        `json:"receipts_hash"`
	ReceiptsHashCompat      string        `json:"receiptsHash"`
}

type newPayloadArgs struct {
	Payload    hexutil.Bytes `json:"payload"`
	ParentHash string        `json:"parent_hash"`
}

type newPayloadArgsCamel struct {
	Payload    hexutil.Bytes `json:"payload"`
	ParentHash string        `json:"parentHash"`
}

type newPayloadResult struct {
	Valid           bool   `json:"valid"`
	StateHash       string `json:"state_hash"`
	StateHashCompat string `json:"stateHash"`
}

type forkchoiceStateArgs struct {
	HeadHash      string `json:"head_hash"`
	SafeHash      string `json:"safe_hash"`
	FinalizedHash string `json:"finalized_hash"`
}

type forkchoiceStateArgsCamel struct {
	HeadHash      string `json:"headHash"`
	SafeHash      string `json:"safeHash"`
	FinalizedHash string `json:"finalizedHash"`
}

type rpcMethodCall struct {
	method string
	arg    interface{}
}

func (c *RPCClient) callWithFallback(ctx context.Context, result interface{}, calls []rpcMethodCall) error {
	client, err := c.ensureRPCClient(ctx)
	if err != nil {
		return err
	}
	var lastErr error
	for _, call := range calls {
		if err := c.applyAuthHeader(client); err != nil {
			return err
		}
		if err := client.CallContext(ctx, result, call.method, call.arg); err != nil {
			converted := normalizeRPCError(err)
			if errors.Is(converted, ErrNotImplemented) {
				lastErr = converted
				continue
			}
			return converted
		}
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return ErrNotImplemented
}

func (c *RPCClient) ensureRPCClient(ctx context.Context) (*rpc.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.rpcClient != nil {
		return c.rpcClient, nil
	}
	endpoint := strings.TrimSpace(c.cfg.Endpoint)
	if endpoint == "" {
		return nil, errors.New("engine api endpoint is empty")
	}
	client, err := rpc.DialContext(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("dial engine api endpoint %q: %w", endpoint, err)
	}
	c.rpcClient = client
	return c.rpcClient, nil
}

func (c *RPCClient) contextWithTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := c.cfg.RequestTimeout
	if timeout <= 0 {
		timeout = DefaultConfig.RequestTimeout
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

func (c *RPCClient) applyAuthHeader(client *rpc.Client) error {
	if client == nil {
		return errors.New("nil rpc client")
	}
	if strings.TrimSpace(c.cfg.JWTSecretFile) == "" {
		return nil
	}
	secret, err := c.loadJWTSecret()
	if err != nil {
		return err
	}
	token, err := jwtToken(secret)
	if err != nil {
		return err
	}
	client.SetHeader("Authorization", "Bearer "+token)
	return nil
}

func (c *RPCClient) loadJWTSecret() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.jwtSecret) == 32 {
		return append([]byte(nil), c.jwtSecret...), nil
	}
	path := strings.TrimSpace(c.cfg.JWTSecretFile)
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read engine jwt secret %q: %w", path, err)
	}
	secret := common.FromHex(strings.TrimSpace(string(data)))
	if len(secret) != 32 {
		return nil, fmt.Errorf("invalid engine jwt secret length %d", len(secret))
	}
	c.jwtSecret = append([]byte(nil), secret...)
	return append([]byte(nil), c.jwtSecret...), nil
}

func jwtToken(secret []byte) (string, error) {
	claims := jwt.RegisteredClaims{
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("sign jwt token: %w", err)
	}
	return signed, nil
}

func normalizeRPCError(err error) error {
	if err == nil {
		return nil
	}
	var rpcErr rpc.Error
	if errors.As(err, &rpcErr) && rpcErr.ErrorCode() == -32601 {
		return fmt.Errorf("%w: %v", ErrNotImplemented, err)
	}
	return err
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func toCamelGetPayloadArgs(args getPayloadArgs) getPayloadArgsCamel {
	return getPayloadArgsCamel{
		ParentHash: args.ParentHash,
		Height:     args.Height,
		Timestamp:  args.Timestamp,
	}
}

func toCamelNewPayloadArgs(args newPayloadArgs) newPayloadArgsCamel {
	return newPayloadArgsCamel{
		Payload:    args.Payload,
		ParentHash: args.ParentHash,
	}
}

func toCamelForkchoiceArgs(args forkchoiceStateArgs) forkchoiceStateArgsCamel {
	return forkchoiceStateArgsCamel{
		HeadHash:      args.HeadHash,
		SafeHash:      args.SafeHash,
		FinalizedHash: args.FinalizedHash,
	}
}
