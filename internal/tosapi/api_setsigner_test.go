package tosapi

import (
	"context"
	"testing"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

const testAPIEd25519PubHex = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

func TestBuildSetSignerTxBuildsSystemActionTx(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	from := common.HexToAddress("0x85b1F044Bab6D30F3A19c1501563915E194D8CFBa1943570603f7606a3115508")
	res, err := api.BuildSetSignerTx(context.Background(), RPCSetSignerArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: from},
		SignerType:      "ed25519",
		SignerValue:     testAPIEd25519PubHex,
	})
	if err != nil {
		t.Fatalf("unexpected build error: %v", err)
	}
	if len(res.Raw) == 0 {
		t.Fatalf("expected raw tx bytes")
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(res.Raw); err != nil {
		t.Fatalf("failed to decode raw tx: %v", err)
	}
	if tx.To() == nil || *tx.To() != params.SystemActionAddress {
		t.Fatalf("unexpected tx to: %v", tx.To())
	}
	if tx.Value().Sign() != 0 {
		t.Fatalf("expected zero value tx, got %s", tx.Value())
	}
	if tx.GasPrice().Cmp(params.GTOSPrice()) != 0 {
		t.Fatalf("unexpected gas price: %s", tx.GasPrice())
	}
	wantGas, err := estimateSystemActionGas(tx.Data())
	if err != nil {
		t.Fatalf("failed to estimate expected gas: %v", err)
	}
	if tx.Gas() != wantGas {
		t.Fatalf("unexpected gas: have %d want %d", tx.Gas(), wantGas)
	}
	sa, err := sysaction.Decode(tx.Data())
	if err != nil {
		t.Fatalf("failed to decode sysaction: %v", err)
	}
	if sa.Action != sysaction.ActionAccountSetSigner {
		t.Fatalf("unexpected action: %s", sa.Action)
	}
	var payload accountsigner.SetSignerPayload
	if err := sysaction.DecodePayload(sa, &payload); err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	if payload.SignerType != "ed25519" || payload.SignerValue != testAPIEd25519PubHex {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	if to, ok := res.Tx["to"].(common.Address); !ok || to != params.SystemActionAddress {
		t.Fatalf("unexpected tx object to: %T %v", res.Tx["to"], res.Tx["to"])
	}
}

func TestBuildSetSignerTxHonorsExplicitGas(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	from := common.HexToAddress("0xAe6856AAc48989adf1E084945CbDD86a2fa8dc4bddD8a8f69DBa48572Eec07FB")
	gas := hexutil.Uint64(77777)
	res, err := api.BuildSetSignerTx(context.Background(), RPCSetSignerArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: from, Gas: &gas},
		SignerType:      "ed25519",
		SignerValue:     testAPIEd25519PubHex,
	})
	if err != nil {
		t.Fatalf("unexpected build error: %v", err)
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(res.Raw); err != nil {
		t.Fatalf("failed to decode raw tx: %v", err)
	}
	if tx.Gas() != uint64(gas) {
		t.Fatalf("unexpected gas: have %d want %d", tx.Gas(), uint64(gas))
	}
}
