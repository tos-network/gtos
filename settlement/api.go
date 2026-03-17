package settlement

import (
	"github.com/tos-network/gtos/common"
)

// SettlementCallbackResult is the JSON-friendly result for GetCallback.
type SettlementCallbackResult struct {
	CallbackID    common.Hash    `json:"callback_id"`
	TxHash        common.Hash    `json:"tx_hash"`
	CallbackType  string         `json:"callback_type"`
	TargetAddress common.Address `json:"target_address"`
	CallbackData  common.Hash    `json:"callback_data"`
	PolicyHash    common.Hash    `json:"policy_hash"`
	MaxGas        uint64         `json:"max_gas"`
	CreatedAt     uint64         `json:"created_at"`
	ExpiresAt     uint64         `json:"expires_at"`
	ExecutedAt    uint64         `json:"executed_at"`
	Status        string         `json:"status"`
	Creator       common.Address `json:"creator"`
}

// AsyncFulfillmentResult is the JSON-friendly result for GetFulfillment.
type AsyncFulfillmentResult struct {
	FulfillmentID    common.Hash    `json:"fulfillment_id"`
	OriginalTxHash   common.Hash    `json:"original_tx_hash"`
	FulfillerAddress common.Address `json:"fulfiller_address"`
	ResultData       common.Hash    `json:"result_data"`
	PolicyCheck      bool           `json:"policy_check"`
	FulfilledAt      uint64         `json:"fulfilled_at"`
	ReceiptRef       common.Hash    `json:"receipt_ref"`
}

// PublicSettlementAPI provides RPC methods for querying settlement state.
type PublicSettlementAPI struct {
	stateReader func() stateDB
}

// NewPublicSettlementAPI creates a new settlement API instance.
func NewPublicSettlementAPI(stateReader func() stateDB) *PublicSettlementAPI {
	return &PublicSettlementAPI{stateReader: stateReader}
}

// GetCallback returns a settlement callback by ID.
func (api *PublicSettlementAPI) GetCallback(callbackID common.Hash) (*SettlementCallbackResult, error) {
	db := api.stateReader()
	if !ReadCallbackExists(db, callbackID) {
		return nil, ErrCallbackNotFound
	}
	return &SettlementCallbackResult{
		CallbackID:    callbackID,
		TxHash:        ReadCallbackTxHash(db, callbackID),
		CallbackType:  string(ReadCallbackType(db, callbackID)),
		TargetAddress: ReadCallbackTarget(db, callbackID),
		CallbackData:  ReadCallbackData(db, callbackID),
		PolicyHash:    ReadCallbackPolicyHash(db, callbackID),
		MaxGas:        ReadCallbackMaxGas(db, callbackID),
		CreatedAt:     ReadCallbackCreatedAt(db, callbackID),
		ExpiresAt:     ReadCallbackExpiresAt(db, callbackID),
		ExecutedAt:    ReadCallbackExecutedAt(db, callbackID),
		Status:        ReadCallbackStatus(db, callbackID),
		Creator:       ReadCallbackCreator(db, callbackID),
	}, nil
}

// GetFulfillment returns an async fulfillment by ID.
func (api *PublicSettlementAPI) GetFulfillment(fulfillmentID common.Hash) (*AsyncFulfillmentResult, error) {
	db := api.stateReader()
	if !ReadFulfillmentExists(db, fulfillmentID) {
		return nil, ErrCallbackNotFound
	}
	return &AsyncFulfillmentResult{
		FulfillmentID:    fulfillmentID,
		OriginalTxHash:   ReadFulfillmentOriginalTxHash(db, fulfillmentID),
		FulfillerAddress: ReadFulfillmentFulfiller(db, fulfillmentID),
		ResultData:       ReadFulfillmentResultData(db, fulfillmentID),
		PolicyCheck:      ReadFulfillmentPolicyCheck(db, fulfillmentID),
		FulfilledAt:      ReadFulfillmentFulfilledAt(db, fulfillmentID),
		ReceiptRef:       ReadFulfillmentReceiptRef(db, fulfillmentID),
	}, nil
}
