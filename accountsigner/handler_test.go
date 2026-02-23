package accountsigner

import (
	"errors"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/sysaction"
)

const testEd25519PubHex = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

func TestHandlerExecuteWithContext(t *testing.T) {
	st := newTestState(t)
	from := common.HexToAddress("0x00000000000000000000000000000000000000cc")
	data, err := sysaction.MakeSysAction(sysaction.ActionAccountSetSigner, SetSignerPayload{
		SignerType:  "ed25519",
		SignerValue: testEd25519PubHex,
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
	if signerType != "ed25519" || signerValue != testEd25519PubHex {
		t.Fatalf("unexpected signer metadata type=%q value=%q", signerType, signerValue)
	}
}

func TestHandlerRejectsNonZeroValue(t *testing.T) {
	st := newTestState(t)
	from := common.HexToAddress("0x00000000000000000000000000000000000000dd")
	data, err := sysaction.MakeSysAction(sysaction.ActionAccountSetSigner, SetSignerPayload{
		SignerType:  "ed25519",
		SignerValue: testEd25519PubHex,
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
