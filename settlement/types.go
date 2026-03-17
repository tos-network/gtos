// Package settlement implements composable settlement callbacks and asynchronous
// fulfillment for the GTOS protocol.
//
// Settlement callbacks allow contracts to register async fulfillment callbacks
// that are composable with account policy and receipts. This enables complex
// multi-step settlement flows where the final resolution of an intent or
// transaction can trigger policy-checked callbacks and generate audit receipts.
package settlement

import (
	"errors"

	"github.com/tos-network/gtos/common"
)

// CallbackType identifies when a callback fires.
type CallbackType string

const (
	CallbackOnSettle  CallbackType = "on_settle"
	CallbackOnFail    CallbackType = "on_fail"
	CallbackOnTimeout CallbackType = "on_timeout"
	CallbackOnRefund  CallbackType = "on_refund"
)

// CallbackStatus tracks the lifecycle of a callback.
const (
	StatusPending  = "pending"
	StatusExecuted = "executed"
	StatusExpired  = "expired"
	StatusFailed   = "failed"
)

// System action constants.
const (
	ActionRegisterCallback = "SETTLEMENT_REGISTER_CALLBACK"
	ActionExecuteCallback  = "SETTLEMENT_EXECUTE_CALLBACK"
	ActionFulfillAsync     = "SETTLEMENT_FULFILL_ASYNC"
)

// SettlementCallback holds the on-chain state for a registered callback.
type SettlementCallback struct {
	CallbackID    common.Hash    `json:"callback_id"`
	TxHash        common.Hash    `json:"tx_hash"`
	IntentID      string         `json:"intent_id,omitempty"`
	CallbackType  CallbackType   `json:"callback_type"`
	TargetAddress common.Address `json:"target_address"`
	CallbackData  common.Hash    `json:"callback_data,omitempty"`
	PolicyHash    common.Hash    `json:"policy_hash,omitempty"`
	MaxGas        uint64         `json:"max_gas"`
	CreatedAt     uint64         `json:"created_at"`
	ExpiresAt     uint64         `json:"expires_at"`
	ExecutedAt    uint64         `json:"executed_at,omitempty"`
	Status        string         `json:"status"`
	Creator       common.Address `json:"creator"`
}

// AsyncFulfillment holds the on-chain state for an async fulfillment record.
type AsyncFulfillment struct {
	FulfillmentID    common.Hash    `json:"fulfillment_id"`
	OriginalTxHash   common.Hash    `json:"original_tx_hash"`
	IntentID         string         `json:"intent_id,omitempty"`
	FulfillerAddress common.Address `json:"fulfiller_address"`
	ResultData       common.Hash    `json:"result_data,omitempty"`
	PolicyCheck      bool           `json:"policy_check"`
	FulfilledAt      uint64         `json:"fulfilled_at"`
	ReceiptRef       common.Hash    `json:"receipt_ref,omitempty"`
}

// ---------- System action payloads (JSON) ----------

// RegisterCallbackPayload is the payload for SETTLEMENT_REGISTER_CALLBACK.
type RegisterCallbackPayload struct {
	TxHash       string `json:"tx_hash"`
	IntentID     string `json:"intent_id,omitempty"`
	CallbackType string `json:"callback_type"`
	Target       string `json:"target"`
	CallbackData string `json:"callback_data,omitempty"` // hex 32 bytes
	PolicyHash   string `json:"policy_hash,omitempty"`   // hex 32 bytes
	MaxGas       uint64 `json:"max_gas"`
	TTLBlocks    uint64 `json:"ttl_blocks"` // expires at current block + ttl
}

// ExecuteCallbackPayload is the payload for SETTLEMENT_EXECUTE_CALLBACK.
type ExecuteCallbackPayload struct {
	CallbackID string `json:"callback_id"` // hex hash
}

// FulfillAsyncPayload is the payload for SETTLEMENT_FULFILL_ASYNC.
type FulfillAsyncPayload struct {
	OriginalTxHash string `json:"original_tx_hash"`
	IntentID       string `json:"intent_id,omitempty"`
	ResultData     string `json:"result_data,omitempty"` // hex 32 bytes
	PolicyCheck    bool   `json:"policy_check"`
	ReceiptRef     string `json:"receipt_ref,omitempty"` // hex 32 bytes
}

// Sentinel errors returned by settlement handlers.
var (
	ErrCallbackNotFound      = errors.New("settlement: callback not found")
	ErrCallbackNotPending    = errors.New("settlement: callback is not pending")
	ErrCallbackExpired       = errors.New("settlement: callback has expired")
	ErrNotCallbackCreator    = errors.New("settlement: caller is not callback creator")
	ErrInvalidCallbackType   = errors.New("settlement: invalid callback type")
	ErrInvalidTarget         = errors.New("settlement: target address is zero")
	ErrMaxGasZero            = errors.New("settlement: max_gas must be > 0")
	ErrTTLZero               = errors.New("settlement: ttl_blocks must be > 0")
	ErrTTLTooLong            = errors.New("settlement: ttl_blocks exceeds maximum")
	ErrInvalidTxHash         = errors.New("settlement: tx_hash must not be zero")
	ErrFulfillmentNotAllowed = errors.New("settlement: fulfillment not allowed")
)

// Settlement parameter limits.
const (
	MaxTTLBlocks       uint64 = 1_000_000
	MaxCallbackDataLen        = 32
)

// validCallbackTypes contains the valid callback type values.
var validCallbackTypes = map[CallbackType]bool{
	CallbackOnSettle:  true,
	CallbackOnFail:    true,
	CallbackOnTimeout: true,
	CallbackOnRefund:  true,
}
