package settlement

import (
	"testing"

	"github.com/tos-network/gtos/common"
)

// mockStateDB and newMockStateDB are defined in settlement_test.go.

func newTestSettlementAPI(db *mockStateDB) *PublicSettlementAPI {
	return NewPublicSettlementAPI(func() stateDB { return db })
}

func TestAPIGetCallback(t *testing.T) {
	db := newMockStateDB()
	cbID := common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	txHash := common.HexToHash("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	target := common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")
	creator := common.HexToAddress("0x473302ca547d5f9877e272cffe58d4def43198b66ba35cff4b2e584be19efa05")

	WriteCallbackExists(db, cbID)
	WriteCallbackTxHash(db, cbID, txHash)
	WriteCallbackType(db, cbID, CallbackOnSettle)
	WriteCallbackTarget(db, cbID, target)
	WriteCallbackMaxGas(db, cbID, 100000)
	WriteCallbackCreatedAt(db, cbID, 10)
	WriteCallbackExpiresAt(db, cbID, 1000)
	WriteCallbackStatus(db, cbID, StatusPending)
	WriteCallbackCreator(db, cbID, creator)

	api := newTestSettlementAPI(db)
	result, err := api.GetCallback(cbID)
	if err != nil {
		t.Fatal(err)
	}
	if result.CallbackID != cbID {
		t.Errorf("CallbackID = %s, want %s", result.CallbackID.Hex(), cbID.Hex())
	}
	if result.TxHash != txHash {
		t.Errorf("TxHash = %s, want %s", result.TxHash.Hex(), txHash.Hex())
	}
	if result.CallbackType != string(CallbackOnSettle) {
		t.Errorf("CallbackType = %s, want %s", result.CallbackType, CallbackOnSettle)
	}
	if result.TargetAddress != target {
		t.Errorf("TargetAddress = %s, want %s", result.TargetAddress.Hex(), target.Hex())
	}
	if result.MaxGas != 100000 {
		t.Errorf("MaxGas = %d, want 100000", result.MaxGas)
	}
	if result.CreatedAt != 10 {
		t.Errorf("CreatedAt = %d, want 10", result.CreatedAt)
	}
	if result.ExpiresAt != 1000 {
		t.Errorf("ExpiresAt = %d, want 1000", result.ExpiresAt)
	}
	if result.Status != StatusPending {
		t.Errorf("Status = %s, want %s", result.Status, StatusPending)
	}
	if result.Creator != creator {
		t.Errorf("Creator = %s, want %s", result.Creator.Hex(), creator.Hex())
	}
}

func TestAPIGetCallbackNotFound(t *testing.T) {
	db := newMockStateDB()
	cbID := common.HexToHash("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")

	api := newTestSettlementAPI(db)
	_, err := api.GetCallback(cbID)
	if err != ErrCallbackNotFound {
		t.Errorf("err = %v, want ErrCallbackNotFound", err)
	}
}

func TestAPIGetFulfillment(t *testing.T) {
	db := newMockStateDB()
	ffID := common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	origTx := common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
	fulfiller := common.HexToAddress("0xdf96edbc954f43d46dc80e0180291bb781ac0a8a3a69c785631d4193e9a9d5e7")

	WriteFulfillmentExists(db, ffID)
	WriteFulfillmentOriginalTxHash(db, ffID, origTx)
	WriteFulfillmentFulfiller(db, ffID, fulfiller)
	WriteFulfillmentPolicyCheck(db, ffID, true)
	WriteFulfillmentFulfilledAt(db, ffID, 500)

	api := newTestSettlementAPI(db)
	result, err := api.GetFulfillment(ffID)
	if err != nil {
		t.Fatal(err)
	}
	if result.FulfillmentID != ffID {
		t.Errorf("FulfillmentID = %s, want %s", result.FulfillmentID.Hex(), ffID.Hex())
	}
	if result.OriginalTxHash != origTx {
		t.Errorf("OriginalTxHash = %s, want %s", result.OriginalTxHash.Hex(), origTx.Hex())
	}
	if result.FulfillerAddress != fulfiller {
		t.Errorf("FulfillerAddress = %s, want %s", result.FulfillerAddress.Hex(), fulfiller.Hex())
	}
	if !result.PolicyCheck {
		t.Error("PolicyCheck = false, want true")
	}
	if result.FulfilledAt != 500 {
		t.Errorf("FulfilledAt = %d, want 500", result.FulfilledAt)
	}
}

func TestAPIGetFulfillmentNotFound(t *testing.T) {
	db := newMockStateDB()
	ffID := common.HexToHash("0x9999999999999999999999999999999999999999999999999999999999999999")

	api := newTestSettlementAPI(db)
	_, err := api.GetFulfillment(ffID)
	if err != ErrCallbackNotFound {
		t.Errorf("err = %v, want ErrCallbackNotFound", err)
	}
}

func TestAPIGetRuntimeReceipt(t *testing.T) {
	db := newMockStateDB()
	receiptRef := common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa11")
	settlementRef := common.HexToHash("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb22")
	sender := common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")
	recipient := common.HexToAddress("0x473302ca547d5f9877e272cffe58d4def43198b66ba35cff4b2e584be19efa05")
	sponsor := common.HexToAddress("0xdf96edbc954f43d46dc80e0180291bb781ac0a8a3a69c785631d4193e9a9d5e7")

	WriteRuntimeReceiptExists(db, receiptRef)
	WriteRuntimeReceiptKind(db, receiptRef, 7)
	WriteRuntimeReceiptStatus(db, receiptRef, ReceiptStatusSuccess)
	WriteRuntimeReceiptMode(db, receiptRef, ModePublicTransfer)
	WriteRuntimeReceiptSender(db, receiptRef, sender)
	WriteRuntimeReceiptRecipient(db, receiptRef, recipient)
	WriteRuntimeReceiptSponsor(db, receiptRef, sponsor)
	WriteRuntimeReceiptSettlementRef(db, receiptRef, settlementRef)
	WriteRuntimeReceiptOpenedAt(db, receiptRef, 10)
	WriteRuntimeReceiptFinalizedAt(db, receiptRef, 20)

	api := newTestSettlementAPI(db)
	got, err := api.GetRuntimeReceipt(receiptRef)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "success" {
		t.Fatalf("status=%q want success", got.Status)
	}
	if got.ModeName != "PUBLIC_TRANSFER" {
		t.Fatalf("mode_name=%q want PUBLIC_TRANSFER", got.ModeName)
	}
	if got.Sender != sender || got.Recipient != recipient {
		t.Fatalf("unexpected sender/recipient: %+v", got)
	}
	if got.Sponsor != sponsor {
		t.Fatalf("unexpected sponsor: %+v", got)
	}
}

func TestAPIGetSettlementEffect(t *testing.T) {
	db := newMockStateDB()
	settlementRef := common.HexToHash("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	receiptRef := common.HexToHash("0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	sender := common.HexToAddress("0xdf96edbc954f43d46dc80e0180291bb781ac0a8a3a69c785631d4193e9a9d5e7")
	recipient := common.HexToAddress("0xf4897a85e6ac20f6b7b22e2c3a8fac52fb6c36430b80655354e5aa4f5e1a3533")
	sponsor := common.HexToAddress("0x1111111111111111111111111111111111111111111111111111111111111111")

	WriteSettlementEffectExists(db, settlementRef)
	WriteSettlementEffectReceiptRef(db, settlementRef, receiptRef)
	WriteSettlementEffectMode(db, settlementRef, ModeRefundPublic)
	WriteSettlementEffectSender(db, settlementRef, sender)
	WriteSettlementEffectRecipient(db, settlementRef, recipient)
	WriteSettlementEffectSponsor(db, settlementRef, sponsor)
	WriteSettlementEffectCreatedAt(db, settlementRef, 77)

	api := newTestSettlementAPI(db)
	got, err := api.GetSettlementEffect(settlementRef)
	if err != nil {
		t.Fatal(err)
	}
	if got.ModeName != "REFUND_PUBLIC" {
		t.Fatalf("mode_name=%q want REFUND_PUBLIC", got.ModeName)
	}
	if got.CreatedAt != 77 {
		t.Fatalf("created_at=%d want 77", got.CreatedAt)
	}
	if got.Sponsor != sponsor {
		t.Fatalf("unexpected sponsor: %+v", got)
	}
}
