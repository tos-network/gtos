package vm

import (
	"math/big"
	"strings"
	"testing"

	"github.com/tos-network/gtos/common"
)

// TestHostTransferSuccess sets balance 1000, transfers 500 via tos.host_transfer,
// then verifies sender has 500 and recipient has 500.
func TestHostTransferSuccess(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x01}
	recipientAddr := common.Address{0x02}

	st.CreateAccount(contractAddr)
	st.AddBalance(contractAddr, big.NewInt(1000))

	src := `tos.host_transfer("` + recipientAddr.Hex() + `", "500")`

	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("host_transfer: %v", err)
	}

	senderBal := st.GetBalance(contractAddr)
	recipientBal := st.GetBalance(recipientAddr)

	if senderBal.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("sender balance: want 500, got %v", senderBal)
	}
	if recipientBal.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("recipient balance: want 500, got %v", recipientBal)
	}
}

func TestHostTransferSuccessWithNumericLiteral(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x07}
	recipientAddr := common.Address{0x08}

	st.CreateAccount(contractAddr)
	st.AddBalance(contractAddr, big.NewInt(1000))

	src := `tos.host_transfer("` + recipientAddr.Hex() + `", 500)`

	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("host_transfer numeric literal: %v", err)
	}

	if got := st.GetBalance(contractAddr); got.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("sender balance: want 500, got %v", got)
	}
	if got := st.GetBalance(recipientAddr); got.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("recipient balance: want 500, got %v", got)
	}
}

// TestHostTransferInsufficientBalance sets balance 100 and tries to transfer 500.
func TestHostTransferInsufficientBalance(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x03}
	recipientAddr := common.Address{0x04}

	st.CreateAccount(contractAddr)
	st.AddBalance(contractAddr, big.NewInt(100))

	src := `tos.host_transfer("` + recipientAddr.Hex() + `", "500")`

	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err == nil {
		t.Fatal("expected error for insufficient balance")
	}
	if !strings.Contains(err.Error(), "insufficient balance") {
		t.Fatalf("expected 'insufficient balance' error, got: %v", err)
	}
}

// TestHostTransferInStaticCall verifies that host_transfer is rejected in readonly context.
func TestHostTransferInStaticCall(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x05}
	recipientAddr := common.Address{0x06}

	st.CreateAccount(contractAddr)
	st.AddBalance(contractAddr, big.NewInt(1000))

	src := `tos.host_transfer("` + recipientAddr.Hex() + `", "500")`

	ctx := CallCtx{
		From:     common.Address{0xFF},
		To:       contractAddr,
		Value:    big.NewInt(0),
		Data:     []byte{},
		TxOrigin: common.Address{0xFF},
		TxPrice:  big.NewInt(1),
		Readonly: true,
	}
	_, _, _, err := Execute(st, newBlockCtx(), testChainConfig, ctx, []byte(src), 1_000_000)
	if err == nil {
		t.Fatal("expected error for staticcall context")
	}
	if !strings.Contains(err.Error(), "staticcall") {
		t.Fatalf("expected 'staticcall' error, got: %v", err)
	}
}
