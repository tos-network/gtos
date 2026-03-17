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
	target := common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	creator := common.HexToAddress("0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")

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
	fulfiller := common.HexToAddress("0x3333333333333333333333333333333333333333")

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
