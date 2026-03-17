package auditreceipt

import (
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

// stateDB is the minimal storage interface required by this package.
// Avoids an import cycle with core/vm (which imports params).
type stateDB interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)
}

// registry is the system contract address for audit receipt metadata.
var registry = params.AuditReceiptRegistryAddress

// ---------- Slot helpers ----------

// auditSlot returns a storage slot for a per-txHash scalar field.
// Key = keccak256(txHash[32] || 0x00 || field).
func auditSlot(txHash common.Hash, field string) common.Hash {
	key := make([]byte, 0, common.HashLength+1+len(field))
	key = append(key, txHash.Bytes()...)
	key = append(key, 0x00)
	key = append(key, field...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// ---------- Audit metadata ----------

// WriteAuditMeta stores audit metadata for a transaction at the
// AuditReceiptRegistryAddress.
func WriteAuditMeta(state stateDB, txHash common.Hash, intentID string, planID string, terminalClass string, trustTier uint8) {
	// Store intentID as a hash (keccak256 of the string).
	if intentID != "" {
		state.SetState(registry, auditSlot(txHash, "intentID"), crypto.Keccak256Hash([]byte(intentID)))
	}
	// Store planID as a hash.
	if planID != "" {
		state.SetState(registry, auditSlot(txHash, "planID"), crypto.Keccak256Hash([]byte(planID)))
	}
	// Store terminalClass as a hash.
	if terminalClass != "" {
		state.SetState(registry, auditSlot(txHash, "terminalClass"), crypto.Keccak256Hash([]byte(terminalClass)))
	}
	// Store trustTier as a single byte in a 32-byte slot.
	var tierVal common.Hash
	tierVal[31] = trustTier
	state.SetState(registry, auditSlot(txHash, "trustTier"), tierVal)
}

// ReadAuditMeta retrieves audit metadata for a transaction. Because intentID,
// planID, and terminalClass are stored as keccak256 hashes (for deterministic
// slot sizing), this function returns their hashes as hex strings. The
// trustTier is returned as the original uint8 value.
func ReadAuditMeta(state stateDB, txHash common.Hash) (intentIDHash string, planIDHash string, terminalClassHash string, trustTier uint8) {
	intentRaw := state.GetState(registry, auditSlot(txHash, "intentID"))
	if intentRaw != (common.Hash{}) {
		intentIDHash = intentRaw.Hex()
	}

	planRaw := state.GetState(registry, auditSlot(txHash, "planID"))
	if planRaw != (common.Hash{}) {
		planIDHash = planRaw.Hex()
	}

	classRaw := state.GetState(registry, auditSlot(txHash, "terminalClass"))
	if classRaw != (common.Hash{}) {
		terminalClassHash = classRaw.Hex()
	}

	tierRaw := state.GetState(registry, auditSlot(txHash, "trustTier"))
	trustTier = tierRaw[31]

	return
}
