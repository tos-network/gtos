package tosapi

import (
	"context"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/params"
)

func TestSetCodeCodeSizeLimit(t *testing.T) {
	api := &TOSAPI{}

	oversized := make(hexutil.Bytes, int(params.MaxCodeSize)+1)
	_, err := api.SetCode(context.Background(), RPCSetCodeArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Code:            oversized,
		TTL:             1,
	})
	if err == nil {
		t.Fatalf("expected oversized code error")
	}
	rpcErr, ok := err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrCodeTooLarge {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrCodeTooLarge)
	}
	data, ok := rpcErr.data.(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected error data type %T", rpcErr.data)
	}
	if data["maxCodeSize"] != params.MaxCodeSize {
		t.Fatalf("unexpected maxCodeSize in error data: %v", data["maxCodeSize"])
	}
	if data["got"] != len(oversized) {
		t.Fatalf("unexpected got in error data: %v", data["got"])
	}

	atLimit := make(hexutil.Bytes, int(params.MaxCodeSize))
	_, err = api.SetCode(context.Background(), RPCSetCodeArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: common.HexToAddress("0x0000000000000000000000000000000000000001")},
		Code:            atLimit,
		TTL:             1,
	})
	if err == nil {
		t.Fatalf("expected not implemented error at limit")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrNotImplemented {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrNotImplemented)
	}
}
