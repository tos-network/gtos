package settlement

import (
	"encoding/json"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&settlementHandler{})
}

type settlementHandler struct{}

func (h *settlementHandler) CanHandle(kind sysaction.ActionKind) bool {
	switch kind {
	case sysaction.ActionSettlementRegisterCallback,
		sysaction.ActionSettlementExecuteCallback,
		sysaction.ActionSettlementFulfillAsync:
		return true
	}
	return false
}

func (h *settlementHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	switch sa.Action {
	case sysaction.ActionSettlementRegisterCallback:
		return h.handleRegisterCallback(ctx, sa)
	case sysaction.ActionSettlementExecuteCallback:
		return h.handleExecuteCallback(ctx, sa)
	case sysaction.ActionSettlementFulfillAsync:
		return h.handleFulfillAsync(ctx, sa)
	}
	return nil
}

// mintCallbackID generates a deterministic callback ID from the creator, tx hash,
// callback type, and the current callback count (as a nonce).
func mintCallbackID(creator common.Address, txHash common.Hash, cbType CallbackType, nonce uint64) common.Hash {
	data := make([]byte, 0, common.AddressLength+common.HashLength+len(cbType)+8)
	data = append(data, creator.Bytes()...)
	data = append(data, txHash[:]...)
	data = append(data, []byte(cbType)...)
	var buf [8]byte
	buf[0] = byte(nonce >> 56)
	buf[1] = byte(nonce >> 48)
	buf[2] = byte(nonce >> 40)
	buf[3] = byte(nonce >> 32)
	buf[4] = byte(nonce >> 24)
	buf[5] = byte(nonce >> 16)
	buf[6] = byte(nonce >> 8)
	buf[7] = byte(nonce)
	data = append(data, buf[:]...)
	return common.BytesToHash(crypto.Keccak256(data))
}

// mintFulfillmentID generates a deterministic fulfillment ID.
func mintFulfillmentID(fulfiller common.Address, origTxHash common.Hash, nonce uint64) common.Hash {
	data := make([]byte, 0, common.AddressLength+common.HashLength+8)
	data = append(data, fulfiller.Bytes()...)
	data = append(data, origTxHash[:]...)
	var buf [8]byte
	buf[0] = byte(nonce >> 56)
	buf[1] = byte(nonce >> 48)
	buf[2] = byte(nonce >> 40)
	buf[3] = byte(nonce >> 32)
	buf[4] = byte(nonce >> 24)
	buf[5] = byte(nonce >> 16)
	buf[6] = byte(nonce >> 8)
	buf[7] = byte(nonce)
	data = append(data, buf[:]...)
	return common.BytesToHash(crypto.Keccak256(data))
}

func (h *settlementHandler) handleRegisterCallback(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p RegisterCallbackPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}

	// 1. Validate fields.
	txHash := common.HexToHash(p.TxHash)
	if txHash == (common.Hash{}) {
		return ErrInvalidTxHash
	}
	cbType := CallbackType(p.CallbackType)
	if !validCallbackTypes[cbType] {
		return ErrInvalidCallbackType
	}
	target := common.HexToAddress(p.Target)
	if target == (common.Address{}) {
		return ErrInvalidTarget
	}
	if p.MaxGas == 0 {
		return ErrMaxGasZero
	}
	if p.TTLBlocks == 0 {
		return ErrTTLZero
	}
	if p.TTLBlocks > MaxTTLBlocks {
		return ErrTTLTooLong
	}

	// 2. Mint callback ID.
	nonce := ReadCallbackCount(ctx.StateDB)
	callbackID := mintCallbackID(ctx.From, txHash, cbType, nonce)

	// 3. Parse optional hex fields.
	var cbData common.Hash
	if p.CallbackData != "" {
		cbData = common.HexToHash(p.CallbackData)
	}
	var policyHash common.Hash
	if p.PolicyHash != "" {
		policyHash = common.HexToHash(p.PolicyHash)
	}

	// 4. Write callback state.
	blockNum := ctx.BlockNumber.Uint64()
	WriteCallbackExists(ctx.StateDB, callbackID)
	WriteCallbackTxHash(ctx.StateDB, callbackID, txHash)
	WriteCallbackType(ctx.StateDB, callbackID, cbType)
	WriteCallbackTarget(ctx.StateDB, callbackID, target)
	WriteCallbackData(ctx.StateDB, callbackID, cbData)
	WriteCallbackPolicyHash(ctx.StateDB, callbackID, policyHash)
	WriteCallbackMaxGas(ctx.StateDB, callbackID, p.MaxGas)
	WriteCallbackCreatedAt(ctx.StateDB, callbackID, blockNum)
	WriteCallbackExpiresAt(ctx.StateDB, callbackID, blockNum+p.TTLBlocks)
	WriteCallbackStatus(ctx.StateDB, callbackID, StatusPending)
	WriteCallbackCreator(ctx.StateDB, callbackID, ctx.From)
	IncrementCallbackCount(ctx.StateDB)

	return nil
}

func (h *settlementHandler) handleExecuteCallback(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p ExecuteCallbackPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}

	callbackID := common.HexToHash(p.CallbackID)

	// 1. Verify callback exists.
	if !ReadCallbackExists(ctx.StateDB, callbackID) {
		return ErrCallbackNotFound
	}

	// 2. Verify status is pending.
	status := ReadCallbackStatus(ctx.StateDB, callbackID)
	if status != StatusPending {
		return ErrCallbackNotPending
	}

	// 3. Check expiration.
	blockNum := ctx.BlockNumber.Uint64()
	expiresAt := ReadCallbackExpiresAt(ctx.StateDB, callbackID)
	if blockNum > expiresAt {
		// Mark as expired.
		WriteCallbackStatus(ctx.StateDB, callbackID, StatusExpired)
		return ErrCallbackExpired
	}

	// 4. Only the creator can execute the callback.
	creator := ReadCallbackCreator(ctx.StateDB, callbackID)
	if ctx.From != creator {
		return ErrNotCallbackCreator
	}

	// 5. Mark as executed.
	WriteCallbackStatus(ctx.StateDB, callbackID, StatusExecuted)
	WriteCallbackExecutedAt(ctx.StateDB, callbackID, blockNum)

	return nil
}

func (h *settlementHandler) handleFulfillAsync(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p FulfillAsyncPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}

	// 1. Validate original tx hash.
	origTxHash := common.HexToHash(p.OriginalTxHash)
	if origTxHash == (common.Hash{}) {
		return ErrInvalidTxHash
	}

	// 2. Mint fulfillment ID.
	nonce := ReadFulfillmentCount(ctx.StateDB)
	fulfillmentID := mintFulfillmentID(ctx.From, origTxHash, nonce)

	// 3. Parse optional hex fields.
	var resultData common.Hash
	if p.ResultData != "" {
		resultData = common.HexToHash(p.ResultData)
	}
	var receiptRef common.Hash
	if p.ReceiptRef != "" {
		receiptRef = common.HexToHash(p.ReceiptRef)
	}

	// 4. Write fulfillment state.
	blockNum := ctx.BlockNumber.Uint64()
	WriteFulfillmentExists(ctx.StateDB, fulfillmentID)
	WriteFulfillmentOriginalTxHash(ctx.StateDB, fulfillmentID, origTxHash)
	WriteFulfillmentFulfiller(ctx.StateDB, fulfillmentID, ctx.From)
	WriteFulfillmentResultData(ctx.StateDB, fulfillmentID, resultData)
	WriteFulfillmentPolicyCheck(ctx.StateDB, fulfillmentID, p.PolicyCheck)
	WriteFulfillmentFulfilledAt(ctx.StateDB, fulfillmentID, blockNum)
	WriteFulfillmentReceiptRef(ctx.StateDB, fulfillmentID, receiptRef)
	IncrementFulfillmentCount(ctx.StateDB)

	return nil
}
