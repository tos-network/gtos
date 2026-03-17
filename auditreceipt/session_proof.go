package auditreceipt

import (
	"encoding/binary"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
)

// SessionProof captures terminal session evidence for future ambient access audit.
type SessionProof struct {
	SessionID     string         `json:"session_id"`
	TerminalClass string         `json:"terminal_class"`
	TerminalID    string         `json:"terminal_id"`
	TrustTier     uint8          `json:"trust_tier"`
	TxHash        common.Hash    `json:"tx_hash"`
	AccountAddr   common.Address `json:"account_address"`
	CreatedAt     uint64         `json:"created_at"`
	ExpiresAt     uint64         `json:"expires_at"`
	ProofHash     common.Hash    `json:"proof_hash"`
}

// BuildSessionProof creates a SessionProof and computes its proof hash.
func BuildSessionProof(txHash common.Hash, sessionID, terminalClass, terminalID string, trustTier uint8, account common.Address, timestamp uint64) *SessionProof {
	proof := &SessionProof{
		SessionID:     sessionID,
		TerminalClass: terminalClass,
		TerminalID:    terminalID,
		TrustTier:     trustTier,
		TxHash:        txHash,
		AccountAddr:   account,
		CreatedAt:     timestamp,
		ExpiresAt:     timestamp + 86400, // default 24-hour expiry
	}
	proof.ProofHash = ComputeSessionProofHash(proof)
	return proof
}

// ComputeSessionProofHash derives a deterministic hash over the session proof fields.
func ComputeSessionProofHash(proof *SessionProof) common.Hash {
	// Pack: txHash[32] || account[20] || trustTier[1] || createdAt[8] || sessionID || terminalClass || terminalID
	data := make([]byte, 0, 32+20+1+8+len(proof.SessionID)+len(proof.TerminalClass)+len(proof.TerminalID))
	data = append(data, proof.TxHash.Bytes()...)
	data = append(data, proof.AccountAddr.Bytes()...)
	data = append(data, proof.TrustTier)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], proof.CreatedAt)
	data = append(data, ts[:]...)
	data = append(data, []byte(proof.SessionID)...)
	data = append(data, []byte(proof.TerminalClass)...)
	data = append(data, []byte(proof.TerminalID)...)
	return crypto.Keccak256Hash(data)
}

// ---------- State storage ----------

// sessionProofSlot returns a storage slot for a session proof field keyed by txHash.
func sessionProofSlot(txHash common.Hash, field string) common.Hash {
	key := make([]byte, 0, common.HashLength+1+len("sessionProof")+1+len(field))
	key = append(key, txHash.Bytes()...)
	key = append(key, 0x00)
	key = append(key, []byte("sessionProof")...)
	key = append(key, 0x00)
	key = append(key, []byte(field)...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// WriteSessionProof persists a session proof to state storage.
func WriteSessionProof(state stateDB, proof *SessionProof) {
	// Store proofHash.
	state.SetState(registry, sessionProofSlot(proof.TxHash, "proofHash"), proof.ProofHash)

	// Store account address.
	var addrVal common.Hash
	copy(addrVal[common.HashLength-common.AddressLength:], proof.AccountAddr.Bytes())
	state.SetState(registry, sessionProofSlot(proof.TxHash, "account"), addrVal)

	// Store trustTier.
	var tierVal common.Hash
	tierVal[31] = proof.TrustTier
	state.SetState(registry, sessionProofSlot(proof.TxHash, "trustTier"), tierVal)

	// Store timestamps (createdAt and expiresAt packed into one slot).
	var timing common.Hash
	binary.BigEndian.PutUint64(timing[16:24], proof.CreatedAt)
	binary.BigEndian.PutUint64(timing[24:32], proof.ExpiresAt)
	state.SetState(registry, sessionProofSlot(proof.TxHash, "timing"), timing)

	// Store sessionID as a hash.
	if proof.SessionID != "" {
		state.SetState(registry, sessionProofSlot(proof.TxHash, "sessionID"), crypto.Keccak256Hash([]byte(proof.SessionID)))
	}

	// Store terminalClass as a hash.
	if proof.TerminalClass != "" {
		state.SetState(registry, sessionProofSlot(proof.TxHash, "terminalClass"), crypto.Keccak256Hash([]byte(proof.TerminalClass)))
	}

	// Store terminalID as a hash.
	if proof.TerminalID != "" {
		state.SetState(registry, sessionProofSlot(proof.TxHash, "terminalID"), crypto.Keccak256Hash([]byte(proof.TerminalID)))
	}
}

// ReadSessionProof reads a session proof from state storage. Returns nil if
// no proof is stored for the given txHash.
func ReadSessionProof(state stateDB, txHash common.Hash) *SessionProof {
	proofHash := state.GetState(registry, sessionProofSlot(txHash, "proofHash"))
	if proofHash == (common.Hash{}) {
		return nil
	}

	addrRaw := state.GetState(registry, sessionProofSlot(txHash, "account"))
	tierRaw := state.GetState(registry, sessionProofSlot(txHash, "trustTier"))
	timing := state.GetState(registry, sessionProofSlot(txHash, "timing"))

	return &SessionProof{
		TxHash:      txHash,
		AccountAddr: common.BytesToAddress(addrRaw[:]),
		TrustTier:   tierRaw[31],
		CreatedAt:   binary.BigEndian.Uint64(timing[16:24]),
		ExpiresAt:   binary.BigEndian.Uint64(timing[24:32]),
		ProofHash:   proofHash,
	}
}
