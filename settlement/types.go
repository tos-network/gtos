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

// Runtime receipt statuses.
const (
	ReceiptStatusOpen uint8 = iota + 1
	ReceiptStatusSuccess
	ReceiptStatusFailure
)

// Settlement modes exposed through the GTOS settlement bus v1.
const (
	ModePublicTransfer uint16 = iota + 1
	ModeUnoTransfer
	ModeEscrowReleasePublic
	ModeRefundPublic
	ModeRefundUno
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
	ErrReceiptNotFound       = errors.New("settlement: receipt not found")
	ErrReceiptAlreadyExists  = errors.New("settlement: receipt already exists")
	ErrReceiptNotOpen        = errors.New("settlement: receipt is not open")
	ErrSettlementNotFound    = errors.New("settlement: settlement not found")
	ErrInvalidSettlementMode = errors.New("settlement: invalid settlement mode")
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

// RuntimeReceipt is the protocol-native receipt shape stored by the settlement bus.
type RuntimeReceipt struct {
	ReceiptRef    common.Hash    `json:"receipt_ref"`
	ReceiptKind   uint16         `json:"receipt_kind"`
	Status        uint8          `json:"status"`
	Mode          uint16         `json:"mode"`
	Sender        common.Address `json:"sender"`
	Recipient     common.Address `json:"recipient"`
	SettlementRef common.Hash    `json:"settlement_ref"`
	ProofRef      common.Hash    `json:"proof_ref,omitempty"`
	FailureRef    common.Hash    `json:"failure_ref,omitempty"`
	PolicyRef     common.Hash    `json:"policy_ref,omitempty"`
	ArtifactRef   common.Hash    `json:"artifact_ref,omitempty"`
	AmountRef     common.Hash    `json:"amount_ref,omitempty"`
	OpenedAt      uint64         `json:"opened_at"`
	FinalizedAt   uint64         `json:"finalized_at,omitempty"`
}

// SettlementEffect is the protocol-native settlement record stored by the settlement bus.
type SettlementEffect struct {
	SettlementRef common.Hash    `json:"settlement_ref"`
	ReceiptRef    common.Hash    `json:"receipt_ref"`
	Mode          uint16         `json:"mode"`
	Sender        common.Address `json:"sender"`
	Recipient     common.Address `json:"recipient"`
	AmountRef     common.Hash    `json:"amount_ref,omitempty"`
	PolicyRef     common.Hash    `json:"policy_ref,omitempty"`
	ArtifactRef   common.Hash    `json:"artifact_ref,omitempty"`
	CreatedAt     uint64         `json:"created_at"`
}

func ReceiptStatusName(status uint8) string {
	switch status {
	case ReceiptStatusOpen:
		return "open"
	case ReceiptStatusSuccess:
		return "success"
	case ReceiptStatusFailure:
		return "failure"
	default:
		return ""
	}
}

func SettlementModeName(mode uint16) string {
	switch mode {
	case ModePublicTransfer:
		return "PUBLIC_TRANSFER"
	case ModeUnoTransfer:
		return "UNO_TRANSFER"
	case ModeEscrowReleasePublic:
		return "ESCROW_RELEASE_PUBLIC"
	case ModeRefundPublic:
		return "REFUND_PUBLIC"
	case ModeRefundUno:
		return "REFUND_UNO"
	default:
		return ""
	}
}

func ParseSettlementMode(mode string) (uint16, error) {
	switch mode {
	case "PUBLIC_TRANSFER":
		return ModePublicTransfer, nil
	case "UNO_TRANSFER":
		return ModeUnoTransfer, nil
	case "ESCROW_RELEASE_PUBLIC":
		return ModeEscrowReleasePublic, nil
	case "REFUND_PUBLIC":
		return ModeRefundPublic, nil
	case "REFUND_UNO":
		return ModeRefundUno, nil
	default:
		return 0, ErrInvalidSettlementMode
	}
}
