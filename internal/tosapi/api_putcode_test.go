package tosapi

import (
	"context"
	"testing"

	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/params"
)

func TestPutCodeTTLCodeSizeLimit(t *testing.T) {
	api := &TOSAPI{}

	oversized := make(hexutil.Bytes, int(params.MaxCodeSize)+1)
	_, err := api.PutCodeTTL(context.Background(), RPCPutCodeTTLArgs{Code: oversized})
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

	atLimit := make(hexutil.Bytes, int(params.MaxCodeSize))
	_, err = api.PutCodeTTL(context.Background(), RPCPutCodeTTLArgs{Code: atLimit})
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
