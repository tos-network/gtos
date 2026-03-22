package vm

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/tos-network/gtos/common"
	cryptopriv "github.com/tos-network/gtos/crypto/priv"
	"github.com/tos-network/gtos/settlement"
)

func TestSettlementBusPublicTransferAutoFinalize(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0xE1}
	recipientAddr := common.Address{0xE2}
	st.AddBalance(contractAddr, big.NewInt(1000))

	receiptRef := common.HexToHash("0x1000000000000000000000000000000000000000000000000000000000000001")
	proofRef := common.HexToHash("0x2000000000000000000000000000000000000000000000000000000000000002")

	src := `
local r = "` + receiptRef.Hex() + `"
tos.receipt_open(r, 1)
local s = tos.settle("PUBLIC_TRANSFER", "` + recipientAddr.Hex() + `", "500", r, { proof_ref = "` + proofRef.Hex() + `" })
local ri = tos.receipt_info(r)
if ri == nil or ri.status ~= "success" then error("expected success receipt") end
if ri.recipient ~= "` + recipientAddr.Hex() + `" then error("recipient mismatch") end
if ri.settlement_ref ~= s then error("settlement_ref mismatch") end
local si = tos.settlement_info(s)
if si == nil or si.mode_name ~= "PUBLIC_TRANSFER" then error("expected public settlement info") end
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("settlement public transfer: %v", err)
	}
	if got := st.GetBalance(contractAddr); got.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("contract balance=%s want 500", got)
	}
	if got := st.GetBalance(recipientAddr); got.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("recipient balance=%s want 500", got)
	}
	receipt, err := settlement.ReadRuntimeReceipt(st, receiptRef)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != settlement.ReceiptStatusSuccess {
		t.Fatalf("receipt status=%d want success", receipt.Status)
	}
	if receipt.ProofRef != proofRef {
		t.Fatalf("proof_ref=%s want %s", receipt.ProofRef.Hex(), proofRef.Hex())
	}
}

func TestSettlementBusSplitPhaseReceiptSuccess(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0xE3}
	recipientAddr := common.Address{0xE4}
	st.AddBalance(contractAddr, big.NewInt(700))

	receiptRef := common.HexToHash("0x3000000000000000000000000000000000000000000000000000000000000003")
	proofRef := common.HexToHash("0x4000000000000000000000000000000000000000000000000000000000000004")

	src := `
local r = "` + receiptRef.Hex() + `"
tos.receipt_open(r, 2)
local s = tos.settle("PUBLIC_TRANSFER", "` + recipientAddr.Hex() + `", "250", r, { auto_finalize = false })
local ri = tos.receipt_info(r)
if ri == nil or ri.status ~= "open" then error("expected open receipt after split-phase settle") end
tos.receipt_success(r, s, "` + proofRef.Hex() + `")
ri = tos.receipt_info(r)
if ri.status ~= "success" then error("expected success after receipt_success") end
if ri.proof_ref ~= "` + proofRef.Hex() + `" then error("proof mismatch") end
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("split-phase settlement: %v", err)
	}
}

func TestSettlementBusMissingReceiptRollsBack(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0xE5}
	recipientAddr := common.Address{0xE6}
	st.AddBalance(contractAddr, big.NewInt(1000))

	receiptRef := common.HexToHash("0x5000000000000000000000000000000000000000000000000000000000000005")
	src := `tos.settle("PUBLIC_TRANSFER", "` + recipientAddr.Hex() + `", "500", "` + receiptRef.Hex() + `")`

	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err == nil {
		t.Fatal("expected missing receipt failure")
	}
	if !strings.Contains(err.Error(), "receipt not found") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := st.GetBalance(contractAddr); got.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("contract balance leaked to %s", got)
	}
	if got := st.GetBalance(recipientAddr); got.Sign() != 0 {
		t.Fatalf("recipient balance leaked to %s", got)
	}
}

func TestSettlementBusEscrowReleasePublic(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0xE7}
	recipientAddr := common.Address{0xE8}
	st.AddBalance(contractAddr, big.NewInt(1000))

	receiptRef := common.HexToHash("0x6000000000000000000000000000000000000000000000000000000000000006")
	src := `
tos.escrow("` + recipientAddr.Hex() + `", "600", 0)
tos.receipt_open("` + receiptRef.Hex() + `", 3)
local s = tos.settle_escrow("ESCROW_RELEASE_PUBLIC", "` + recipientAddr.Hex() + `", "400", "` + receiptRef.Hex() + `", { purpose = "0" })
local ri = tos.receipt_info("` + receiptRef.Hex() + `")
if ri.status ~= "success" then error("expected escrow receipt success") end
local bal = tos.escrowbalanceof("` + recipientAddr.Hex() + `", 0)
if tostring(bal) ~= "200" then error("unexpected escrow remainder: " .. tostring(bal)) end
local si = tos.settlement_info(s)
if si == nil or si.mode_name ~= "ESCROW_RELEASE_PUBLIC" then error("expected escrow settlement info") end
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("escrow settlement: %v", err)
	}
	if got := st.GetBalance(contractAddr); got.Cmp(big.NewInt(400)) != 0 {
		t.Fatalf("contract balance=%s want 400", got)
	}
	if got := st.GetBalance(recipientAddr); got.Cmp(big.NewInt(400)) != 0 {
		t.Fatalf("recipient balance=%s want 400", got)
	}
}

func TestSettlementBusUnoTransferAutoFinalize(t *testing.T) {
	pub, priv := testKeypair(t)
	st := newAgentTestState()
	contractAddr := common.Address{0xE9}
	recipientAddr := common.Address{0xEA}

	deposit, err := cryptopriv.Encrypt(pub[:], 55)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	depositHex := "0x" + hex.EncodeToString(deposit)
	receiptRef := common.HexToHash("0x7000000000000000000000000000000000000000000000000000000000000007")

	src := `
tos.receipt_open("` + receiptRef.Hex() + `", 4)
local s = tos.settle("UNO_TRANSFER", "` + recipientAddr.Hex() + `", "` + depositHex + `", "` + receiptRef.Hex() + `")
local ri = tos.receipt_info("` + receiptRef.Hex() + `")
if ri.status ~= "success" then error("expected uno receipt success") end
local si = tos.settlement_info(s)
if si == nil or si.mode_name ~= "UNO_TRANSFER" then error("expected uno settlement info") end
`
	_, _, _, err = runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("uno settlement: %v", err)
	}

	commit := st.GetState(recipientAddr, privCommitmentSlot)
	handle := st.GetState(recipientAddr, privHandleSlot)
	var finalCt [64]byte
	copy(finalCt[:32], commit[:])
	copy(finalCt[32:], handle[:])
	msgPoint, err := cryptopriv.DecryptToPoint(priv[:], finalCt[:])
	if err != nil {
		t.Fatalf("DecryptToPoint: %v", err)
	}
	plaintext, ok, err := cryptopriv.SolveDiscreteLog(msgPoint, 1<<20)
	if err != nil {
		t.Fatalf("SolveDiscreteLog: %v", err)
	}
	if !ok || plaintext != 55 {
		t.Fatalf("unexpected plaintext=%d ok=%v", plaintext, ok)
	}
}

