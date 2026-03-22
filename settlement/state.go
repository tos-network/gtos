package settlement

import (
	"encoding/binary"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

// StateDB is the minimal storage interface required by this package.
// Exported so that the RPC registration layer can reference it.
type StateDB interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)
}

// stateDB is a package-local alias kept for backward compatibility.
type stateDB = StateDB

// registry is a shorthand for the SettlementRegistryAddress.
var registry = params.SettlementRegistryAddress

// ---------- Slot helpers ----------

// cbSlot returns a storage slot for a per-callback scalar field.
// Key = keccak256("cb\x00" || callbackID[32] || 0x00 || field).
func cbSlot(callbackID common.Hash, field string) common.Hash {
	key := make([]byte, 0, 3+common.HashLength+1+len(field))
	key = append(key, "cb\x00"...)
	key = append(key, callbackID[:]...)
	key = append(key, 0x00)
	key = append(key, field...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// ffSlot returns a storage slot for a per-fulfillment scalar field.
// Key = keccak256("ff\x00" || fulfillmentID[32] || 0x00 || field).
func ffSlot(fulfillmentID common.Hash, field string) common.Hash {
	key := make([]byte, 0, 3+common.HashLength+1+len(field))
	key = append(key, "ff\x00"...)
	key = append(key, fulfillmentID[:]...)
	key = append(key, 0x00)
	key = append(key, field...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// callbackCountSlot stores the total count of registered callbacks (uint64).
var callbackCountSlot = common.BytesToHash(crypto.Keccak256([]byte("cb\x00count")))

// fulfillmentCountSlot stores the total count of fulfillments (uint64).
var fulfillmentCountSlot = common.BytesToHash(crypto.Keccak256([]byte("ff\x00count")))

// ---------- Callback CRUD ----------

// ReadCallbackExists returns true if a callback with the given ID has been registered.
func ReadCallbackExists(db stateDB, id common.Hash) bool {
	raw := db.GetState(registry, cbSlot(id, "exists"))
	return raw[31] != 0
}

// WriteCallbackExists marks a callback as existing.
func WriteCallbackExists(db stateDB, id common.Hash) {
	var val common.Hash
	val[31] = 1
	db.SetState(registry, cbSlot(id, "exists"), val)
}

// ReadCallbackTxHash returns the tx hash associated with a callback.
func ReadCallbackTxHash(db stateDB, id common.Hash) common.Hash {
	return db.GetState(registry, cbSlot(id, "txHash"))
}

// WriteCallbackTxHash writes the tx hash for a callback.
func WriteCallbackTxHash(db stateDB, id common.Hash, txHash common.Hash) {
	db.SetState(registry, cbSlot(id, "txHash"), txHash)
}

// ReadCallbackType returns the callback type (stored as short string in slot).
func ReadCallbackType(db stateDB, id common.Hash) CallbackType {
	raw := db.GetState(registry, cbSlot(id, "cbType"))
	length := int(raw[0])
	if length == 0 || length > 31 {
		return ""
	}
	return CallbackType(raw[1 : 1+length])
}

// WriteCallbackType writes the callback type.
func WriteCallbackType(db stateDB, id common.Hash, cbType CallbackType) {
	var val common.Hash
	s := string(cbType)
	val[0] = byte(len(s))
	copy(val[1:], []byte(s))
	db.SetState(registry, cbSlot(id, "cbType"), val)
}

// ReadCallbackTarget returns the target address for a callback.
func ReadCallbackTarget(db stateDB, id common.Hash) common.Address {
	raw := db.GetState(registry, cbSlot(id, "target"))
	return common.BytesToAddress(raw[:])
}

// WriteCallbackTarget writes the target address.
func WriteCallbackTarget(db stateDB, id common.Hash, target common.Address) {
	var val common.Hash
	copy(val[common.HashLength-common.AddressLength:], target.Bytes())
	db.SetState(registry, cbSlot(id, "target"), val)
}

// ReadCallbackData returns the callback data hash.
func ReadCallbackData(db stateDB, id common.Hash) common.Hash {
	return db.GetState(registry, cbSlot(id, "cbData"))
}

// WriteCallbackData writes the callback data.
func WriteCallbackData(db stateDB, id common.Hash, data common.Hash) {
	db.SetState(registry, cbSlot(id, "cbData"), data)
}

// ReadCallbackPolicyHash returns the policy hash for a callback.
func ReadCallbackPolicyHash(db stateDB, id common.Hash) common.Hash {
	return db.GetState(registry, cbSlot(id, "policyHash"))
}

// WriteCallbackPolicyHash writes the policy hash.
func WriteCallbackPolicyHash(db stateDB, id common.Hash, policyHash common.Hash) {
	db.SetState(registry, cbSlot(id, "policyHash"), policyHash)
}

// ReadCallbackMaxGas returns the max gas for a callback.
func ReadCallbackMaxGas(db stateDB, id common.Hash) uint64 {
	raw := db.GetState(registry, cbSlot(id, "maxGas"))
	return binary.BigEndian.Uint64(raw[24:])
}

// WriteCallbackMaxGas writes the max gas.
func WriteCallbackMaxGas(db stateDB, id common.Hash, maxGas uint64) {
	var val common.Hash
	binary.BigEndian.PutUint64(val[24:], maxGas)
	db.SetState(registry, cbSlot(id, "maxGas"), val)
}

// ReadCallbackCreatedAt returns the block at which the callback was created.
func ReadCallbackCreatedAt(db stateDB, id common.Hash) uint64 {
	raw := db.GetState(registry, cbSlot(id, "createdAt"))
	return binary.BigEndian.Uint64(raw[24:])
}

// WriteCallbackCreatedAt writes the created-at block.
func WriteCallbackCreatedAt(db stateDB, id common.Hash, blockNum uint64) {
	var val common.Hash
	binary.BigEndian.PutUint64(val[24:], blockNum)
	db.SetState(registry, cbSlot(id, "createdAt"), val)
}

// ReadCallbackExpiresAt returns the expiration block for a callback.
func ReadCallbackExpiresAt(db stateDB, id common.Hash) uint64 {
	raw := db.GetState(registry, cbSlot(id, "expiresAt"))
	return binary.BigEndian.Uint64(raw[24:])
}

// WriteCallbackExpiresAt writes the expiration block.
func WriteCallbackExpiresAt(db stateDB, id common.Hash, blockNum uint64) {
	var val common.Hash
	binary.BigEndian.PutUint64(val[24:], blockNum)
	db.SetState(registry, cbSlot(id, "expiresAt"), val)
}

// ReadCallbackExecutedAt returns the block at which the callback was executed.
func ReadCallbackExecutedAt(db stateDB, id common.Hash) uint64 {
	raw := db.GetState(registry, cbSlot(id, "executedAt"))
	return binary.BigEndian.Uint64(raw[24:])
}

// WriteCallbackExecutedAt writes the executed-at block.
func WriteCallbackExecutedAt(db stateDB, id common.Hash, blockNum uint64) {
	var val common.Hash
	binary.BigEndian.PutUint64(val[24:], blockNum)
	db.SetState(registry, cbSlot(id, "executedAt"), val)
}

// ReadCallbackStatus returns the status string for a callback.
func ReadCallbackStatus(db stateDB, id common.Hash) string {
	raw := db.GetState(registry, cbSlot(id, "status"))
	length := int(raw[0])
	if length == 0 || length > 31 {
		return ""
	}
	return string(raw[1 : 1+length])
}

// WriteCallbackStatus writes the status string.
func WriteCallbackStatus(db stateDB, id common.Hash, status string) {
	var val common.Hash
	val[0] = byte(len(status))
	copy(val[1:], []byte(status))
	db.SetState(registry, cbSlot(id, "status"), val)
}

// ReadCallbackCreator returns the creator address for a callback.
func ReadCallbackCreator(db stateDB, id common.Hash) common.Address {
	raw := db.GetState(registry, cbSlot(id, "creator"))
	return common.BytesToAddress(raw[:])
}

// WriteCallbackCreator writes the creator address.
func WriteCallbackCreator(db stateDB, id common.Hash, creator common.Address) {
	var val common.Hash
	copy(val[common.HashLength-common.AddressLength:], creator.Bytes())
	db.SetState(registry, cbSlot(id, "creator"), val)
}

// ---------- Fulfillment CRUD ----------

// ReadFulfillmentExists returns true if a fulfillment record exists.
func ReadFulfillmentExists(db stateDB, id common.Hash) bool {
	raw := db.GetState(registry, ffSlot(id, "exists"))
	return raw[31] != 0
}

// WriteFulfillmentExists marks a fulfillment as existing.
func WriteFulfillmentExists(db stateDB, id common.Hash) {
	var val common.Hash
	val[31] = 1
	db.SetState(registry, ffSlot(id, "exists"), val)
}

// ReadFulfillmentOriginalTxHash returns the original tx hash for a fulfillment.
func ReadFulfillmentOriginalTxHash(db stateDB, id common.Hash) common.Hash {
	return db.GetState(registry, ffSlot(id, "origTxHash"))
}

// WriteFulfillmentOriginalTxHash writes the original tx hash.
func WriteFulfillmentOriginalTxHash(db stateDB, id common.Hash, txHash common.Hash) {
	db.SetState(registry, ffSlot(id, "origTxHash"), txHash)
}

// ReadFulfillmentFulfiller returns the fulfiller address.
func ReadFulfillmentFulfiller(db stateDB, id common.Hash) common.Address {
	raw := db.GetState(registry, ffSlot(id, "fulfiller"))
	return common.BytesToAddress(raw[:])
}

// WriteFulfillmentFulfiller writes the fulfiller address.
func WriteFulfillmentFulfiller(db stateDB, id common.Hash, addr common.Address) {
	var val common.Hash
	copy(val[common.HashLength-common.AddressLength:], addr.Bytes())
	db.SetState(registry, ffSlot(id, "fulfiller"), val)
}

// ReadFulfillmentResultData returns the result data hash.
func ReadFulfillmentResultData(db stateDB, id common.Hash) common.Hash {
	return db.GetState(registry, ffSlot(id, "resultData"))
}

// WriteFulfillmentResultData writes the result data.
func WriteFulfillmentResultData(db stateDB, id common.Hash, data common.Hash) {
	db.SetState(registry, ffSlot(id, "resultData"), data)
}

// ReadFulfillmentPolicyCheck returns the policy check flag.
func ReadFulfillmentPolicyCheck(db stateDB, id common.Hash) bool {
	raw := db.GetState(registry, ffSlot(id, "policyCheck"))
	return raw[31] != 0
}

// WriteFulfillmentPolicyCheck writes the policy check flag.
func WriteFulfillmentPolicyCheck(db stateDB, id common.Hash, check bool) {
	var val common.Hash
	if check {
		val[31] = 1
	}
	db.SetState(registry, ffSlot(id, "policyCheck"), val)
}

// ReadFulfillmentFulfilledAt returns the block at which the fulfillment was recorded.
func ReadFulfillmentFulfilledAt(db stateDB, id common.Hash) uint64 {
	raw := db.GetState(registry, ffSlot(id, "fulfilledAt"))
	return binary.BigEndian.Uint64(raw[24:])
}

// WriteFulfillmentFulfilledAt writes the fulfilled-at block.
func WriteFulfillmentFulfilledAt(db stateDB, id common.Hash, blockNum uint64) {
	var val common.Hash
	binary.BigEndian.PutUint64(val[24:], blockNum)
	db.SetState(registry, ffSlot(id, "fulfilledAt"), val)
}

// ReadFulfillmentReceiptRef returns the receipt reference hash.
func ReadFulfillmentReceiptRef(db stateDB, id common.Hash) common.Hash {
	return db.GetState(registry, ffSlot(id, "receiptRef"))
}

// WriteFulfillmentReceiptRef writes the receipt reference.
func WriteFulfillmentReceiptRef(db stateDB, id common.Hash, ref common.Hash) {
	db.SetState(registry, ffSlot(id, "receiptRef"), ref)
}

// ---------- Counters ----------

// ReadCallbackCount returns the total number of registered callbacks.
func ReadCallbackCount(db stateDB) uint64 {
	raw := db.GetState(registry, callbackCountSlot)
	return raw.Big().Uint64()
}

// IncrementCallbackCount increments the callback count.
func IncrementCallbackCount(db stateDB) {
	n := ReadCallbackCount(db)
	db.SetState(registry, callbackCountSlot, common.BigToHash(new(big.Int).SetUint64(n+1)))
}

// ReadFulfillmentCount returns the total number of fulfillments.
func ReadFulfillmentCount(db stateDB) uint64 {
	raw := db.GetState(registry, fulfillmentCountSlot)
	return raw.Big().Uint64()
}

// IncrementFulfillmentCount increments the fulfillment count.
func IncrementFulfillmentCount(db stateDB) {
	n := ReadFulfillmentCount(db)
	db.SetState(registry, fulfillmentCountSlot, common.BigToHash(new(big.Int).SetUint64(n+1)))
}

// ---------- Runtime receipt + settlement effect CRUD ----------

func rrSlot(receiptRef common.Hash, field string) common.Hash {
	key := make([]byte, 0, 3+common.HashLength+1+len(field))
	key = append(key, "rr\x00"...)
	key = append(key, receiptRef[:]...)
	key = append(key, 0x00)
	key = append(key, field...)
	return common.BytesToHash(crypto.Keccak256(key))
}

func seSlot(settlementRef common.Hash, field string) common.Hash {
	key := make([]byte, 0, 3+common.HashLength+1+len(field))
	key = append(key, "se\x00"...)
	key = append(key, settlementRef[:]...)
	key = append(key, 0x00)
	key = append(key, field...)
	return common.BytesToHash(crypto.Keccak256(key))
}

func readUint64Slot(db stateDB, slot common.Hash) uint64 {
	raw := db.GetState(registry, slot)
	return binary.BigEndian.Uint64(raw[24:])
}

func writeUint64Slot(db stateDB, slot common.Hash, value uint64) {
	var word common.Hash
	binary.BigEndian.PutUint64(word[24:], value)
	db.SetState(registry, slot, word)
}

func readUint16Slot(db stateDB, slot common.Hash) uint16 {
	raw := db.GetState(registry, slot)
	return binary.BigEndian.Uint16(raw[30:])
}

func writeUint16Slot(db stateDB, slot common.Hash, value uint16) {
	var word common.Hash
	binary.BigEndian.PutUint16(word[30:], value)
	db.SetState(registry, slot, word)
}

func readUint8Slot(db stateDB, slot common.Hash) uint8 {
	raw := db.GetState(registry, slot)
	return raw[31]
}

func writeUint8Slot(db stateDB, slot common.Hash, value uint8) {
	var word common.Hash
	word[31] = value
	db.SetState(registry, slot, word)
}

func readAddressSlot(db stateDB, slot common.Hash) common.Address {
	raw := db.GetState(registry, slot)
	return common.BytesToAddress(raw[:])
}

func writeAddressSlot(db stateDB, slot common.Hash, addr common.Address) {
	var word common.Hash
	copy(word[common.HashLength-common.AddressLength:], addr.Bytes())
	db.SetState(registry, slot, word)
}

func ReadRuntimeReceiptExists(db stateDB, receiptRef common.Hash) bool {
	return readUint8Slot(db, rrSlot(receiptRef, "exists")) != 0
}

func WriteRuntimeReceiptExists(db stateDB, receiptRef common.Hash) {
	writeUint8Slot(db, rrSlot(receiptRef, "exists"), 1)
}

func ReadRuntimeReceiptKind(db stateDB, receiptRef common.Hash) uint16 {
	return readUint16Slot(db, rrSlot(receiptRef, "kind"))
}

func WriteRuntimeReceiptKind(db stateDB, receiptRef common.Hash, kind uint16) {
	writeUint16Slot(db, rrSlot(receiptRef, "kind"), kind)
}

func ReadRuntimeReceiptStatus(db stateDB, receiptRef common.Hash) uint8 {
	return readUint8Slot(db, rrSlot(receiptRef, "status"))
}

func WriteRuntimeReceiptStatus(db stateDB, receiptRef common.Hash, status uint8) {
	writeUint8Slot(db, rrSlot(receiptRef, "status"), status)
}

func ReadRuntimeReceiptMode(db stateDB, receiptRef common.Hash) uint16 {
	return readUint16Slot(db, rrSlot(receiptRef, "mode"))
}

func WriteRuntimeReceiptMode(db stateDB, receiptRef common.Hash, mode uint16) {
	writeUint16Slot(db, rrSlot(receiptRef, "mode"), mode)
}

func ReadRuntimeReceiptSender(db stateDB, receiptRef common.Hash) common.Address {
	return readAddressSlot(db, rrSlot(receiptRef, "sender"))
}

func WriteRuntimeReceiptSender(db stateDB, receiptRef common.Hash, sender common.Address) {
	writeAddressSlot(db, rrSlot(receiptRef, "sender"), sender)
}

func ReadRuntimeReceiptRecipient(db stateDB, receiptRef common.Hash) common.Address {
	return readAddressSlot(db, rrSlot(receiptRef, "recipient"))
}

func WriteRuntimeReceiptRecipient(db stateDB, receiptRef common.Hash, recipient common.Address) {
	writeAddressSlot(db, rrSlot(receiptRef, "recipient"), recipient)
}

func ReadRuntimeReceiptSponsor(db stateDB, receiptRef common.Hash) common.Address {
	return readAddressSlot(db, rrSlot(receiptRef, "sponsor"))
}

func WriteRuntimeReceiptSponsor(db stateDB, receiptRef common.Hash, sponsor common.Address) {
	writeAddressSlot(db, rrSlot(receiptRef, "sponsor"), sponsor)
}

func ReadRuntimeReceiptSettlementRef(db stateDB, receiptRef common.Hash) common.Hash {
	return db.GetState(registry, rrSlot(receiptRef, "settlementRef"))
}

func WriteRuntimeReceiptSettlementRef(db stateDB, receiptRef common.Hash, settlementRef common.Hash) {
	db.SetState(registry, rrSlot(receiptRef, "settlementRef"), settlementRef)
}

func ReadRuntimeReceiptProofRef(db stateDB, receiptRef common.Hash) common.Hash {
	return db.GetState(registry, rrSlot(receiptRef, "proofRef"))
}

func WriteRuntimeReceiptProofRef(db stateDB, receiptRef common.Hash, proofRef common.Hash) {
	db.SetState(registry, rrSlot(receiptRef, "proofRef"), proofRef)
}

func ReadRuntimeReceiptFailureRef(db stateDB, receiptRef common.Hash) common.Hash {
	return db.GetState(registry, rrSlot(receiptRef, "failureRef"))
}

func WriteRuntimeReceiptFailureRef(db stateDB, receiptRef common.Hash, failureRef common.Hash) {
	db.SetState(registry, rrSlot(receiptRef, "failureRef"), failureRef)
}

func ReadRuntimeReceiptPolicyRef(db stateDB, receiptRef common.Hash) common.Hash {
	return db.GetState(registry, rrSlot(receiptRef, "policyRef"))
}

func WriteRuntimeReceiptPolicyRef(db stateDB, receiptRef common.Hash, policyRef common.Hash) {
	db.SetState(registry, rrSlot(receiptRef, "policyRef"), policyRef)
}

func ReadRuntimeReceiptArtifactRef(db stateDB, receiptRef common.Hash) common.Hash {
	return db.GetState(registry, rrSlot(receiptRef, "artifactRef"))
}

func WriteRuntimeReceiptArtifactRef(db stateDB, receiptRef common.Hash, artifactRef common.Hash) {
	db.SetState(registry, rrSlot(receiptRef, "artifactRef"), artifactRef)
}

func ReadRuntimeReceiptAmountRef(db stateDB, receiptRef common.Hash) common.Hash {
	return db.GetState(registry, rrSlot(receiptRef, "amountRef"))
}

func WriteRuntimeReceiptAmountRef(db stateDB, receiptRef common.Hash, amountRef common.Hash) {
	db.SetState(registry, rrSlot(receiptRef, "amountRef"), amountRef)
}

func ReadRuntimeReceiptOpenedAt(db stateDB, receiptRef common.Hash) uint64 {
	return readUint64Slot(db, rrSlot(receiptRef, "openedAt"))
}

func WriteRuntimeReceiptOpenedAt(db stateDB, receiptRef common.Hash, openedAt uint64) {
	writeUint64Slot(db, rrSlot(receiptRef, "openedAt"), openedAt)
}

func ReadRuntimeReceiptFinalizedAt(db stateDB, receiptRef common.Hash) uint64 {
	return readUint64Slot(db, rrSlot(receiptRef, "finalizedAt"))
}

func WriteRuntimeReceiptFinalizedAt(db stateDB, receiptRef common.Hash, finalizedAt uint64) {
	writeUint64Slot(db, rrSlot(receiptRef, "finalizedAt"), finalizedAt)
}

func ReadSettlementEffectExists(db stateDB, settlementRef common.Hash) bool {
	return readUint8Slot(db, seSlot(settlementRef, "exists")) != 0
}

func WriteSettlementEffectExists(db stateDB, settlementRef common.Hash) {
	writeUint8Slot(db, seSlot(settlementRef, "exists"), 1)
}

func ReadSettlementEffectReceiptRef(db stateDB, settlementRef common.Hash) common.Hash {
	return db.GetState(registry, seSlot(settlementRef, "receiptRef"))
}

func WriteSettlementEffectReceiptRef(db stateDB, settlementRef common.Hash, receiptRef common.Hash) {
	db.SetState(registry, seSlot(settlementRef, "receiptRef"), receiptRef)
}

func ReadSettlementEffectMode(db stateDB, settlementRef common.Hash) uint16 {
	return readUint16Slot(db, seSlot(settlementRef, "mode"))
}

func WriteSettlementEffectMode(db stateDB, settlementRef common.Hash, mode uint16) {
	writeUint16Slot(db, seSlot(settlementRef, "mode"), mode)
}

func ReadSettlementEffectSender(db stateDB, settlementRef common.Hash) common.Address {
	return readAddressSlot(db, seSlot(settlementRef, "sender"))
}

func WriteSettlementEffectSender(db stateDB, settlementRef common.Hash, sender common.Address) {
	writeAddressSlot(db, seSlot(settlementRef, "sender"), sender)
}

func ReadSettlementEffectRecipient(db stateDB, settlementRef common.Hash) common.Address {
	return readAddressSlot(db, seSlot(settlementRef, "recipient"))
}

func WriteSettlementEffectRecipient(db stateDB, settlementRef common.Hash, recipient common.Address) {
	writeAddressSlot(db, seSlot(settlementRef, "recipient"), recipient)
}

func ReadSettlementEffectSponsor(db stateDB, settlementRef common.Hash) common.Address {
	return readAddressSlot(db, seSlot(settlementRef, "sponsor"))
}

func WriteSettlementEffectSponsor(db stateDB, settlementRef common.Hash, sponsor common.Address) {
	writeAddressSlot(db, seSlot(settlementRef, "sponsor"), sponsor)
}

func ReadSettlementEffectAmountRef(db stateDB, settlementRef common.Hash) common.Hash {
	return db.GetState(registry, seSlot(settlementRef, "amountRef"))
}

func WriteSettlementEffectAmountRef(db stateDB, settlementRef common.Hash, amountRef common.Hash) {
	db.SetState(registry, seSlot(settlementRef, "amountRef"), amountRef)
}

func ReadSettlementEffectPolicyRef(db stateDB, settlementRef common.Hash) common.Hash {
	return db.GetState(registry, seSlot(settlementRef, "policyRef"))
}

func WriteSettlementEffectPolicyRef(db stateDB, settlementRef common.Hash, policyRef common.Hash) {
	db.SetState(registry, seSlot(settlementRef, "policyRef"), policyRef)
}

func ReadSettlementEffectArtifactRef(db stateDB, settlementRef common.Hash) common.Hash {
	return db.GetState(registry, seSlot(settlementRef, "artifactRef"))
}

func WriteSettlementEffectArtifactRef(db stateDB, settlementRef common.Hash, artifactRef common.Hash) {
	db.SetState(registry, seSlot(settlementRef, "artifactRef"), artifactRef)
}

func ReadSettlementEffectCreatedAt(db stateDB, settlementRef common.Hash) uint64 {
	return readUint64Slot(db, seSlot(settlementRef, "createdAt"))
}

func WriteSettlementEffectCreatedAt(db stateDB, settlementRef common.Hash, createdAt uint64) {
	writeUint64Slot(db, seSlot(settlementRef, "createdAt"), createdAt)
}

func ReadRuntimeReceipt(db stateDB, receiptRef common.Hash) (*RuntimeReceipt, error) {
	if !ReadRuntimeReceiptExists(db, receiptRef) {
		return nil, ErrReceiptNotFound
	}
	return &RuntimeReceipt{
		ReceiptRef:    receiptRef,
		ReceiptKind:   ReadRuntimeReceiptKind(db, receiptRef),
		Status:        ReadRuntimeReceiptStatus(db, receiptRef),
		Mode:          ReadRuntimeReceiptMode(db, receiptRef),
		Sender:        ReadRuntimeReceiptSender(db, receiptRef),
		Recipient:     ReadRuntimeReceiptRecipient(db, receiptRef),
		Sponsor:       ReadRuntimeReceiptSponsor(db, receiptRef),
		SettlementRef: ReadRuntimeReceiptSettlementRef(db, receiptRef),
		ProofRef:      ReadRuntimeReceiptProofRef(db, receiptRef),
		FailureRef:    ReadRuntimeReceiptFailureRef(db, receiptRef),
		PolicyRef:     ReadRuntimeReceiptPolicyRef(db, receiptRef),
		ArtifactRef:   ReadRuntimeReceiptArtifactRef(db, receiptRef),
		AmountRef:     ReadRuntimeReceiptAmountRef(db, receiptRef),
		OpenedAt:      ReadRuntimeReceiptOpenedAt(db, receiptRef),
		FinalizedAt:   ReadRuntimeReceiptFinalizedAt(db, receiptRef),
	}, nil
}

func ReadSettlementEffect(db stateDB, settlementRef common.Hash) (*SettlementEffect, error) {
	if !ReadSettlementEffectExists(db, settlementRef) {
		return nil, ErrSettlementNotFound
	}
	return &SettlementEffect{
		SettlementRef: settlementRef,
		ReceiptRef:    ReadSettlementEffectReceiptRef(db, settlementRef),
		Mode:          ReadSettlementEffectMode(db, settlementRef),
		Sender:        ReadSettlementEffectSender(db, settlementRef),
		Recipient:     ReadSettlementEffectRecipient(db, settlementRef),
		Sponsor:       ReadSettlementEffectSponsor(db, settlementRef),
		AmountRef:     ReadSettlementEffectAmountRef(db, settlementRef),
		PolicyRef:     ReadSettlementEffectPolicyRef(db, settlementRef),
		ArtifactRef:   ReadSettlementEffectArtifactRef(db, settlementRef),
		CreatedAt:     ReadSettlementEffectCreatedAt(db, settlementRef),
	}, nil
}
