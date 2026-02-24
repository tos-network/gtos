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
	from := common.HexToAddress("0xe8b0087eec10090b15f4fc4bc96aaa54e2d44c299564da76e1cd3184a2386b8d")
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
	from := common.HexToAddress("0xd0c8d1bb01b01528cd7fa3145d46ac553a974ef992a08eeef0a05990802f01f6")
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
	from := common.HexToAddress("0xbb0b8ebfca3f41857d18ed477357589f8e367c2c31f51242fb77b350a11830f3")
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
