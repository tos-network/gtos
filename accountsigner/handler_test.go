package accountsigner

import (
	"errors"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/sysaction"
)

func TestHandlerExecuteWithContext(t *testing.T) {
	st := newTestState(t)
	from := common.HexToAddress("0x00000000000000000000000000000000000000cc")
	data, err := sysaction.MakeSysAction(sysaction.ActionAccountSetSigner, SetSignerPayload{
		SignerType:  "ed25519",
		SignerValue: "z6MkiSigner",
	})
	if err != nil {
		t.Fatalf("failed to encode sysaction: %v", err)
	}
	ctx := &sysaction.Context{
		From:    from,
		Value:   big.NewInt(0),
		StateDB: st,
	}
	if err := sysaction.ExecuteWithContext(ctx, data); err != nil {
		t.Fatalf("unexpected execute error: %v", err)
	}
	signerType, signerValue, ok := Get(st, from)
	if !ok {
		t.Fatalf("expected signer metadata")
	}
	if signerType != "ed25519" || signerValue != "z6MkiSigner" {
		t.Fatalf("unexpected signer metadata type=%q value=%q", signerType, signerValue)
	}
}

func TestHandlerRejectsNonZeroValue(t *testing.T) {
	st := newTestState(t)
	from := common.HexToAddress("0x00000000000000000000000000000000000000dd")
	data, err := sysaction.MakeSysAction(sysaction.ActionAccountSetSigner, SetSignerPayload{
		SignerType:  "ed25519",
		SignerValue: "z6MkiSigner",
	})
	if err != nil {
		t.Fatalf("failed to encode sysaction: %v", err)
	}
	ctx := &sysaction.Context{
		From:    from,
		Value:   big.NewInt(1),
		StateDB: st,
	}
	err = sysaction.ExecuteWithContext(ctx, data)
	if !errors.Is(err, ErrNonZeroValue) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandlerRejectsInvalidPayload(t *testing.T) {
	st := newTestState(t)
	from := common.HexToAddress("0x00000000000000000000000000000000000000ee")
	data, err := sysaction.MakeSysAction(sysaction.ActionAccountSetSigner, SetSignerPayload{
		SignerType:  "ed25519",
		SignerValue: "",
	})
	if err != nil {
		t.Fatalf("failed to encode sysaction: %v", err)
	}
	ctx := &sysaction.Context{
		From:    from,
		Value:   big.NewInt(0),
		StateDB: st,
	}
	err = sysaction.ExecuteWithContext(ctx, data)
	if !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("unexpected error: %v", err)
	}
}
