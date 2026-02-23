package tosapi

import (
	"context"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

func TestBuildSetSignerTxBuildsSystemActionTx(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	from := common.HexToAddress("0x0000000000000000000000000000000000000001")
	res, err := api.BuildSetSignerTx(context.Background(), RPCSetSignerArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: from},
		SignerType:      "ed25519",
		SignerValue:     "z6MkiSignerValue",
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
	if tx.GasPrice().Cmp(big.NewInt(42)) != 0 {
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
	if payload.SignerType != "ed25519" || payload.SignerValue != "z6MkiSignerValue" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	if to, ok := res.Tx["to"].(common.Address); !ok || to != params.SystemActionAddress {
		t.Fatalf("unexpected tx object to: %T %v", res.Tx["to"], res.Tx["to"])
	}
}

func TestBuildSetSignerTxHonorsExplicitGas(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	from := common.HexToAddress("0x0000000000000000000000000000000000000002")
	gas := hexutil.Uint64(77777)
	res, err := api.BuildSetSignerTx(context.Background(), RPCSetSignerArgs{
		RPCTxCommonArgs: RPCTxCommonArgs{From: from, Gas: &gas},
		SignerType:      "ed25519",
		SignerValue:     "z6MkiSignerValue",
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
