package tosapi

import (
	"context"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/rpc"
)

func TestSetSignerValidation(t *testing.T) {
	api := &TOSAPI{}
	ctx := context.Background()

	_, err := api.SetSigner(ctx, RPCSetSignerArgs{})
	if err == nil {
		t.Fatalf("expected validation error")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidSigner {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidSigner)
	}

	_, err = api.SetSigner(ctx, RPCSetSignerArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		SignerType:      "ed25519",
		SignerValue:     "z6Mki...",
	})
	if err == nil {
		t.Fatalf("expected not-implemented error")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrNotImplemented {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrNotImplemented)
	}
}

func TestBuildSetSignerTxValidation(t *testing.T) {
	api := &TOSAPI{}

	_, err := api.BuildSetSignerTx(context.Background(), RPCSetSignerArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		SignerType:      "ed25519",
		SignerValue:     "",
	})
	if err == nil {
		t.Fatalf("expected validation error")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidSigner {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidSigner)
	}
}

func TestPutKVTTLValidation(t *testing.T) {
	api := &TOSAPI{}
	var err error

	_, err = api.PutKVTTL(context.Background(), RPCPutKVTTLArgs{
		Namespace: "ns",
		Key:       hexutil.Bytes("k"),
		Value:     hexutil.Bytes("v"),
		TTL:       1,
	})
	if err == nil {
		t.Fatalf("expected invalid params error for from")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidParams {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidParams)
	}

	_, err = api.PutKVTTL(context.Background(), RPCPutKVTTLArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Namespace:       "   ",
		Key:             hexutil.Bytes("k"),
		Value:           hexutil.Bytes("v"),
		TTL:             1,
	})
	if err == nil {
		t.Fatalf("expected invalid params error for namespace")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidParams {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidParams)
	}

	_, err = api.PutKVTTL(context.Background(), RPCPutKVTTLArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Namespace:       "ns",
		Key:             hexutil.Bytes("k"),
		Value:           hexutil.Bytes("v"),
		TTL:             0,
	})
	if err == nil {
		t.Fatalf("expected invalid ttl error")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidTTL {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidTTL)
	}

	_, err = api.PutKVTTL(context.Background(), RPCPutKVTTLArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Namespace:       "ns",
		Key:             hexutil.Bytes("k"),
		Value:           hexutil.Bytes("v"),
		TTL:             1,
	})
	if err == nil {
		t.Fatalf("expected not-implemented error")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrNotImplemented {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrNotImplemented)
	}
}

func TestPutCodeTTLValidation(t *testing.T) {
	api := &TOSAPI{}
	var err error

	_, err = api.PutCodeTTL(context.Background(), RPCPutCodeTTLArgs{
		Code: hexutil.Bytes{0x60, 0x00},
		TTL:  1,
	})
	if err == nil {
		t.Fatalf("expected invalid params error for from")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidParams {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidParams)
	}

	_, err = api.PutCodeTTL(context.Background(), RPCPutCodeTTLArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Code:            hexutil.Bytes{0x60, 0x00},
		TTL:             0,
	})
	if err == nil {
		t.Fatalf("expected invalid ttl error")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidTTL {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidTTL)
	}
}

func TestValidateAndComputeExpireBlock(t *testing.T) {
	created, expire, err := validateAndComputeExpireBlock(10, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created != 100 || expire != 110 {
		t.Fatalf("unexpected blocks created=%d expire=%d", created, expire)
	}

	_, _, err = validateAndComputeExpireBlock(0, 100)
	if err == nil {
		t.Fatalf("expected invalid ttl error")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidTTL {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidTTL)
	}

	_, _, err = validateAndComputeExpireBlock(2, ^uint64(0)-1)
	if err == nil {
		t.Fatalf("expected overflow ttl error")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidTTL {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidTTL)
	}
}

func TestCodeAndKVReadValidation(t *testing.T) {
	api := &TOSAPI{}
	ctx := context.Background()

	_, err := api.GetCodeObject(ctx, common.Hash{}, nil)
	if err == nil {
		t.Fatalf("expected invalid params error for codeHash")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidParams {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidParams)
	}

	_, err = api.GetCodeObjectMeta(ctx, common.Hash{}, nil)
	if err == nil {
		t.Fatalf("expected invalid params error for codeHash")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidParams {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidParams)
	}

	_, err = api.GetKV(ctx, "   ", hexutil.Bytes("k"), nil)
	if err == nil {
		t.Fatalf("expected invalid params error for namespace")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidParams {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidParams)
	}

	_, err = api.GetKVMeta(ctx, "", hexutil.Bytes("k"), nil)
	if err == nil {
		t.Fatalf("expected invalid params error for namespace")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidParams {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidParams)
	}
}

func TestListKVValidation(t *testing.T) {
	api := &TOSAPI{}
	ctx := context.Background()
	latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)

	_, err := api.ListKV(ctx, "", nil, nil, &latest)
	if err == nil {
		t.Fatalf("expected invalid params error for namespace")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidParams {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidParams)
	}

	emptyCursor := "   "
	_, err = api.ListKV(ctx, "ns", &emptyCursor, nil, nil)
	if err == nil {
		t.Fatalf("expected invalid params error for cursor")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidParams {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidParams)
	}

	limitZero := hexutil.Uint64(0)
	_, err = api.ListKV(ctx, "ns", nil, &limitZero, nil)
	if err == nil {
		t.Fatalf("expected invalid params error for limit")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidParams {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidParams)
	}

	limitOne := hexutil.Uint64(1)
	cursor := "cursor-1"
	_, err = api.ListKV(ctx, "ns", &cursor, &limitOne, nil)
	if err == nil {
		t.Fatalf("expected not-implemented error")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrNotImplemented {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrNotImplemented)
	}
}
