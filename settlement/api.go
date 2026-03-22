package settlement

import (
	"github.com/tos-network/gtos/boundary"
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

// RuntimeReceiptResult is the JSON-friendly result for GetRuntimeReceipt.
type RuntimeReceiptResult struct {
	ReceiptRef    common.Hash    `json:"receipt_ref"`
	ReceiptKind   uint16         `json:"receipt_kind"`
	Status        string         `json:"status"`
	Mode          uint16         `json:"mode"`
	ModeName      string         `json:"mode_name"`
	Sender        common.Address `json:"sender"`
	Recipient     common.Address `json:"recipient"`
	SettlementRef common.Hash    `json:"settlement_ref"`
	ProofRef      common.Hash    `json:"proof_ref"`
	FailureRef    common.Hash    `json:"failure_ref"`
	PolicyRef     common.Hash    `json:"policy_ref"`
	ArtifactRef   common.Hash    `json:"artifact_ref"`
	AmountRef     common.Hash    `json:"amount_ref"`
	OpenedAt      uint64         `json:"opened_at"`
	FinalizedAt   uint64         `json:"finalized_at"`
}

// SettlementEffectResult is the JSON-friendly result for GetSettlementEffect.
type SettlementEffectResult struct {
	SettlementRef common.Hash    `json:"settlement_ref"`
	ReceiptRef    common.Hash    `json:"receipt_ref"`
	Mode          uint16         `json:"mode"`
	ModeName      string         `json:"mode_name"`
	Sender        common.Address `json:"sender"`
	Recipient     common.Address `json:"recipient"`
	AmountRef     common.Hash    `json:"amount_ref"`
	PolicyRef     common.Hash    `json:"policy_ref"`
	ArtifactRef   common.Hash    `json:"artifact_ref"`
	CreatedAt     uint64         `json:"created_at"`
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

// GetRuntimeReceipt returns a settlement-bus runtime receipt by ref.
func (api *PublicSettlementAPI) GetRuntimeReceipt(receiptRef common.Hash) (*RuntimeReceiptResult, error) {
	db := api.stateReader()
	receipt, err := ReadRuntimeReceipt(db, receiptRef)
	if err != nil {
		return nil, err
	}
	return &RuntimeReceiptResult{
		ReceiptRef:    receipt.ReceiptRef,
		ReceiptKind:   receipt.ReceiptKind,
		Status:        ReceiptStatusName(receipt.Status),
		Mode:          receipt.Mode,
		ModeName:      SettlementModeName(receipt.Mode),
		Sender:        receipt.Sender,
		Recipient:     receipt.Recipient,
		SettlementRef: receipt.SettlementRef,
		ProofRef:      receipt.ProofRef,
		FailureRef:    receipt.FailureRef,
		PolicyRef:     receipt.PolicyRef,
		ArtifactRef:   receipt.ArtifactRef,
		AmountRef:     receipt.AmountRef,
		OpenedAt:      receipt.OpenedAt,
		FinalizedAt:   receipt.FinalizedAt,
	}, nil
}

// GetSettlementEffect returns a settlement-bus effect by settlement ref.
func (api *PublicSettlementAPI) GetSettlementEffect(settlementRef common.Hash) (*SettlementEffectResult, error) {
	db := api.stateReader()
	effect, err := ReadSettlementEffect(db, settlementRef)
	if err != nil {
		return nil, err
	}
	return &SettlementEffectResult{
		SettlementRef: effect.SettlementRef,
		ReceiptRef:    effect.ReceiptRef,
		Mode:          effect.Mode,
		ModeName:      SettlementModeName(effect.Mode),
		Sender:        effect.Sender,
		Recipient:     effect.Recipient,
		AmountRef:     effect.AmountRef,
		PolicyRef:     effect.PolicyRef,
		ArtifactRef:   effect.ArtifactRef,
		CreatedAt:     effect.CreatedAt,
	}, nil
}

// GetBoundaryVersion returns the boundary schema version used by this node.
func (api *PublicSettlementAPI) GetBoundaryVersion() string {
	return boundary.SchemaVersion
}

// GetSchemaVersion returns the boundary schema version and negotiation info.
func (api *PublicSettlementAPI) GetSchemaVersion() map[string]interface{} {
	return map[string]interface{}{
		"schema_version": boundary.SchemaVersion,
		"namespace":      "settlement",
	}
}
