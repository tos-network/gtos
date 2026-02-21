package client

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/rpc"
)

type CamelGetPayloadRequest struct {
	ParentHash string `json:"parentHash"`
	Height     uint64 `json:"height"`
	Timestamp  uint64 `json:"timestamp"`
}

type CamelGetPayloadResponse struct {
	Payload           hexutil.Bytes `json:"payload"`
	PayloadEncoding   string        `json:"payloadEncoding"`
	PayloadCommitment string        `json:"payloadCommitment"`
	StateHash         string        `json:"stateHash"`
	ReceiptsHash      string        `json:"receiptsHash"`
}

type CamelEngineService struct{}

func (CamelEngineService) GetPayload(req CamelGetPayloadRequest) (*CamelGetPayloadResponse, error) {
	if req.ParentHash == "" {
		return nil, errors.New("missing parentHash")
	}
	return &CamelGetPayloadResponse{
		Payload:           hexutil.Bytes{0x01, 0x02, 0x03},
		PayloadEncoding:   "tos_v1",
		PayloadCommitment: "pc-camel",
		StateHash:         "state-camel",
		ReceiptsHash:      "receipts-camel",
	}, nil
}

type SnakeNewPayloadRequest struct {
	Payload    hexutil.Bytes `json:"payload"`
	ParentHash string        `json:"parent_hash"`
}

type SnakeNewPayloadResponse struct {
	Valid     bool   `json:"valid"`
	StateHash string `json:"state_hash"`
}

type SnakeForkchoiceRequest struct {
	HeadHash      string `json:"head_hash"`
	SafeHash      string `json:"safe_hash"`
	FinalizedHash string `json:"finalized_hash"`
}

type SnakeEngineService struct {
	lastNewPayloadReq SnakeNewPayloadRequest
	lastForkchoiceReq SnakeForkchoiceRequest
}

func (s *SnakeEngineService) New_payload(req SnakeNewPayloadRequest) (*SnakeNewPayloadResponse, error) {
	s.lastNewPayloadReq = req
	return &SnakeNewPayloadResponse{Valid: true, StateHash: "state-snake"}, nil
}

func (s *SnakeEngineService) Forkchoice_updated(req SnakeForkchoiceRequest) (struct{}, error) {
	s.lastForkchoiceReq = req
	return struct{}{}, nil
}

type JWTProbeService struct{}

func (JWTProbeService) ForkchoiceUpdated(SnakeForkchoiceRequest) (struct{}, error) {
	return struct{}{}, nil
}

func newTestClient(endpoint string) *RPCClient {
	return NewRPCClient(Config{
		Enabled:        true,
		Endpoint:       endpoint,
		RequestTimeout: 2 * time.Second,
	})
}

func TestGetPayloadFallbackToCamelMethod(t *testing.T) {
	server := rpc.NewServer()
	if err := server.RegisterName("engine", CamelEngineService{}); err != nil {
		t.Fatalf("register service: %v", err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()

	client := newTestClient(httpServer.URL)
	resp, err := client.GetPayload(context.Background(), &GetPayloadRequest{
		ParentHash: "0xabc",
		Height:     12,
		Timestamp:  1234,
	})
	if err != nil {
		t.Fatalf("GetPayload failed: %v", err)
	}
	if !bytes.Equal(resp.Payload, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("unexpected payload: %x", resp.Payload)
	}
	if resp.PayloadEncoding != "tos_v1" || resp.PayloadCommitment != "pc-camel" || resp.StateHash != "state-camel" || resp.ReceiptsHash != "receipts-camel" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestSnakeCaseMethods(t *testing.T) {
	server := rpc.NewServer()
	svc := &SnakeEngineService{}
	if err := server.RegisterName("engine", svc); err != nil {
		t.Fatalf("register service: %v", err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()

	client := newTestClient(httpServer.URL)
	npResp, err := client.NewPayload(context.Background(), &NewPayloadRequest{
		Payload:    []byte{0xaa, 0xbb},
		ParentHash: "0xdef",
	})
	if err != nil {
		t.Fatalf("NewPayload failed: %v", err)
	}
	if !npResp.Valid || npResp.StateHash != "state-snake" {
		t.Fatalf("unexpected NewPayload response: %+v", npResp)
	}
	if svc.lastNewPayloadReq.ParentHash != "0xdef" {
		t.Fatalf("unexpected parent hash: %s", svc.lastNewPayloadReq.ParentHash)
	}
	if !bytes.Equal(svc.lastNewPayloadReq.Payload, []byte{0xaa, 0xbb}) {
		t.Fatalf("unexpected payload: %x", svc.lastNewPayloadReq.Payload)
	}

	err = client.ForkchoiceUpdated(context.Background(), &ForkchoiceState{
		HeadHash:      "0x01",
		SafeHash:      "0x02",
		FinalizedHash: "0x03",
	})
	if err != nil {
		t.Fatalf("ForkchoiceUpdated failed: %v", err)
	}
	if svc.lastForkchoiceReq.HeadHash != "0x01" || svc.lastForkchoiceReq.SafeHash != "0x02" || svc.lastForkchoiceReq.FinalizedHash != "0x03" {
		t.Fatalf("unexpected forkchoice request: %+v", svc.lastForkchoiceReq)
	}
}

func TestNotImplementedMapped(t *testing.T) {
	server := rpc.NewServer()
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()

	client := newTestClient(httpServer.URL)
	_, err := client.GetPayload(context.Background(), &GetPayloadRequest{
		ParentHash: "0xabc",
		Height:     1,
		Timestamp:  1,
	})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented, got: %v", err)
	}
}

func TestJWTHeaderInjected(t *testing.T) {
	server := rpc.NewServer()
	if err := server.RegisterName("engine", JWTProbeService{}); err != nil {
		t.Fatalf("register service: %v", err)
	}
	var authHeader string
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		server.ServeHTTP(w, r)
	}))
	defer httpServer.Close()

	secret := bytes.Repeat([]byte{0x11}, 32)
	secretPath := filepath.Join(t.TempDir(), "jwtsecret")
	if err := os.WriteFile(secretPath, []byte(hexutil.Encode(secret)), 0600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	client := NewRPCClient(Config{
		Enabled:        true,
		Endpoint:       httpServer.URL,
		JWTSecretFile:  secretPath,
		RequestTimeout: 2 * time.Second,
	})
	if err := client.ForkchoiceUpdated(context.Background(), &ForkchoiceState{
		HeadHash:      "0x01",
		SafeHash:      "0x01",
		FinalizedHash: "0x01",
	}); err != nil {
		t.Fatalf("ForkchoiceUpdated failed: %v", err)
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		t.Fatalf("missing bearer auth header: %q", authHeader)
	}
	rawToken := strings.TrimPrefix(authHeader, "Bearer ")
	var claims jwt.RegisteredClaims
	token, err := jwt.ParseWithClaims(rawToken, &claims, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithoutClaimsValidation())
	if err != nil {
		t.Fatalf("parse auth token: %v", err)
	}
	if !token.Valid {
		t.Fatalf("token not valid")
	}
	if claims.IssuedAt == nil {
		t.Fatalf("missing iat claim")
	}
}
