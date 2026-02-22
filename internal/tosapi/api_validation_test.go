package tosapi

import (
	"context"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/params"
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

func TestPutKVValidation(t *testing.T) {
	api := &TOSAPI{}
	var err error

	_, err = api.PutKV(context.Background(), RPCPutKVArgs{
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

	_, err = api.PutKV(context.Background(), RPCPutKVArgs{
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

	_, err = api.PutKV(context.Background(), RPCPutKVArgs{
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

	_, err = api.PutKV(context.Background(), RPCPutKVArgs{
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

func TestSetCodeValidation(t *testing.T) {
	api := &TOSAPI{}
	var err error

	_, err = api.SetCode(context.Background(), RPCSetCodeArgs{
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

	_, err = api.SetCode(context.Background(), RPCSetCodeArgs{
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

func TestEstimateSetCodeGasValidation(t *testing.T) {
	api := &TOSAPI{}

	_, err := api.EstimateSetCodeGas(hexutil.Bytes{0x60, 0x00}, 0)
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

	oversized := make(hexutil.Bytes, int(params.MaxCodeSize)+1)
	_, err = api.EstimateSetCodeGas(oversized, 1)
	if err == nil {
		t.Fatalf("expected oversized code error")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrCodeTooLarge {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrCodeTooLarge)
	}

	gas, err := api.EstimateSetCodeGas(hexutil.Bytes{0x00, 0x01}, 1)
	if err != nil {
		t.Fatalf("unexpected estimate error: %v", err)
	}
	payload, err := core.EncodeSetCodePayload(1, hexutil.Bytes{0x00, 0x01})
	if err != nil {
		t.Fatalf("unexpected payload encode error: %v", err)
	}
	want, err := core.EstimateSetCodePayloadGas(payload, 1)
	if err != nil {
		t.Fatalf("unexpected intrinsic gas error: %v", err)
	}
	if uint64(gas) != want {
		t.Fatalf("unexpected estimated gas %d, want %d", gas, want)
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
