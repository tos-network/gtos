package auditreceipt

import (
	"encoding/json"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/rlp"
)

// BuildFromReceipt creates an AuditReceipt from a chain Receipt and transaction.
// The block header provides the block-level context (number, hash, timestamp).
func BuildFromReceipt(receipt *types.Receipt, tx *types.Transaction, header *types.Header) *AuditReceipt {
	ar := &AuditReceipt{
		TxHash:  receipt.TxHash,
		Status:  receipt.Status,
		GasUsed: receipt.GasUsed,
		Value:   new(big.Int).Set(tx.Value()),
	}

	// Block-level context from header.
	if header != nil {
		if header.Number != nil {
			ar.BlockNumber = header.Number.Uint64()
		}
		ar.BlockHash = header.Hash()
		ar.SettledAt = header.Time
	}

	// Actor attribution from the transaction envelope.
	if from, ok := tx.SignerFrom(); ok {
		ar.From = from
	}
	if to := tx.To(); to != nil {
		ar.To = *to
	}
	if signerType, ok := tx.SignerType(); ok {
		ar.SignerType = signerType
	}

	// Sponsor attribution.
	if tx.IsSponsored() {
		if sponsor, ok := tx.SponsorFrom(); ok {
			ar.Sponsor = sponsor
		}
		if policyHash, ok := tx.SponsorPolicyHash(); ok {
			ar.SponsorPolicyHash = policyHash
		}
	}

	// Compute canonical receipt hash.
	ar.ReceiptHash = ComputeReceiptHash(ar)

	return ar
}

// BuildSponsorAttribution extracts sponsor attribution from a sponsored transaction.
// Returns nil if the transaction is not sponsored.
func BuildSponsorAttribution(tx *types.Transaction, receipt *types.Receipt, timestamp uint64) *SponsorAttributionRecord {
	if !tx.IsSponsored() {
		return nil
	}

	sar := &SponsorAttributionRecord{
		TxHash:       receipt.TxHash,
		GasSponsored: receipt.GasUsed,
		Timestamp:    timestamp,
	}

	if sponsor, ok := tx.SponsorFrom(); ok {
		sar.SponsorAddress = sponsor
	}
	if signerType, ok := tx.SponsorSignerType(); ok {
		sar.SponsorSignerType = signerType
	}
	if nonce, ok := tx.SponsorNonce(); ok {
		sar.SponsorNonce = nonce
	}
	if expiry, ok := tx.SponsorExpiry(); ok {
		sar.SponsorExpiry = expiry
	}
	if policyHash, ok := tx.SponsorPolicyHash(); ok {
		sar.PolicyHash = policyHash
	}

	return sar
}

// BuildSettlementTrace creates a settlement trace from receipt data.
func BuildSettlementTrace(receipt *types.Receipt, tx *types.Transaction, header *types.Header) *SettlementTrace {
	st := &SettlementTrace{
		TxHash:   receipt.TxHash,
		Value:    new(big.Int).Set(tx.Value()),
		Success:  receipt.Status == types.ReceiptStatusSuccessful,
		LogCount: uint(len(receipt.Logs)),
	}

	if from, ok := tx.SignerFrom(); ok {
		st.From = from
	}
	if to := tx.To(); to != nil {
		st.To = *to
	}

	st.ContractAddr = receipt.ContractAddress

	if header != nil {
		if header.Number != nil {
			st.BlockNumber = header.Number.Uint64()
		}
		st.Timestamp = header.Time
	}

	return st
}

// ComputeReceiptHash computes a canonical hash of the audit receipt for proof
// references. The hash is deterministic: same inputs always produce the same
// hash regardless of platform or encoding order.
func ComputeReceiptHash(ar *AuditReceipt) common.Hash {
	// Use RLP encoding of the key fields for deterministic hashing.
	type hashInput struct {
		TxHash      common.Hash
		BlockNumber uint64
		Status      uint64
		GasUsed     uint64
		From        common.Address
		To          common.Address
		Sponsor     common.Address
		Value       *big.Int
		SettledAt   uint64
	}

	input := hashInput{
		TxHash:      ar.TxHash,
		BlockNumber: ar.BlockNumber,
		Status:      ar.Status,
		GasUsed:     ar.GasUsed,
		From:        ar.From,
		To:          ar.To,
		Sponsor:     ar.Sponsor,
		Value:       ar.Value,
		SettledAt:   ar.SettledAt,
	}

	encoded, err := rlp.EncodeToBytes(input)
	if err != nil {
		// Fallback: use JSON encoding if RLP fails (should not happen for
		// these types, but be defensive).
		encoded, _ = json.Marshal(ar)
	}

	return crypto.Keccak256Hash(encoded)
}
