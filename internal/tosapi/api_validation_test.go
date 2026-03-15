package tosapi

import (
	"context"
	crand "crypto/rand"
	"strings"
	"testing"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
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
		RPCTxCommonArgs: RPCTxCommonArgs{From: common.HexToAddress("0x969b0a11b8a56bacf1ac18f219e7e376e7c213b7e7e7e46cc70a5dd086daff2a")},
		SignerType:      "ed25519",
		SignerValue:     testAPIEd25519PubHex,
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

	_, err = api.SetSigner(ctx, RPCSetSignerArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: common.HexToAddress("0x969b0a11b8a56bacf1ac18f219e7e376e7c213b7e7e7e46cc70a5dd086daff2a")},
		SignerType:      accountsigner.SignerTypeBLS12381,
		SignerValue: func() string {
			priv, genErr := accountsigner.GenerateBLS12381PrivateKey(crand.Reader)
			if genErr != nil {
				t.Fatalf("failed to generate bls private key: %v", genErr)
			}
			pub, pubErr := accountsigner.PublicKeyFromBLS12381Private(priv)
			if pubErr != nil {
				t.Fatalf("failed to derive bls public key: %v", pubErr)
			}
			return hexutil.Encode(pub)
		}(),
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

	_, err = api.SetSigner(ctx, RPCSetSignerArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: common.HexToAddress("0x969b0a11b8a56bacf1ac18f219e7e376e7c213b7e7e7e46cc70a5dd086daff2a")},
		SignerType:      strings.Repeat("a", accountsigner.MaxSignerTypeLen+1),
		SignerValue:     testAPIEd25519PubHex,
	})
	if err == nil {
		t.Fatalf("expected validation error for signerType length")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidSigner {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidSigner)
	}

	_, err = api.SetSigner(ctx, RPCSetSignerArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: common.HexToAddress("0x969b0a11b8a56bacf1ac18f219e7e376e7c213b7e7e7e46cc70a5dd086daff2a")},
		SignerType:      "ed25519",
		SignerValue:     "0x" + strings.Repeat("11", accountsigner.MaxSignerValueLen+1),
	})
	if err == nil {
		t.Fatalf("expected validation error for signerValue length")
	}
	rpcErr, ok = err.(*rpcAPIError)
	if !ok {
		t.Fatalf("unexpected error type %T", err)
	}
	if rpcErr.code != rpcErrInvalidSigner {
		t.Fatalf("unexpected error code %d, want %d", rpcErr.code, rpcErrInvalidSigner)
	}
}

func TestBuildSetSignerTxValidation(t *testing.T) {
	api := &TOSAPI{}

	_, err := api.BuildSetSignerTx(context.Background(), RPCSetSignerArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: common.HexToAddress("0x969b0a11b8a56bacf1ac18f219e7e376e7c213b7e7e7e46cc70a5dd086daff2a")},
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

// TestVMEraRPCDeprecationErrors was removed: tos_call, tos_estimateGas, and
// tos_createAccessList are all re-enabled via the LVM execution path.
