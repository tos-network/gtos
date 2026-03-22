package auditreceipt

import (
	"testing"

	"github.com/tos-network/gtos/common"
)

// mockStateDB and newMockStateDB are defined in auditreceipt_test.go.

func newTestAuditReceiptAPI(db *mockStateDB) *PublicAuditReceiptAPI {
	return NewPublicAuditReceiptAPI(func() stateDB { return db })
}

func TestAPIGetAuditMeta(t *testing.T) {
	db := newMockStateDB()
	txHash := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

	WriteAuditMeta(db, txHash, "intent-1", "plan-1", "POS", 3)

	api := newTestAuditReceiptAPI(db)
	result, err := api.GetAuditMeta(txHash)
	if err != nil {
		t.Fatal(err)
	}
	if result.IntentIDHash == "" {
		t.Error("IntentIDHash is empty")
	}
	if result.PlanIDHash == "" {
		t.Error("PlanIDHash is empty")
	}
	if result.TerminalClassHash == "" {
		t.Error("TerminalClassHash is empty")
	}
	if result.TrustTier != 3 {
		t.Errorf("TrustTier = %d, want 3", result.TrustTier)
	}
}

func TestAPIGetAuditMetaEmpty(t *testing.T) {
	db := newMockStateDB()
	txHash := common.HexToHash("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

	api := newTestAuditReceiptAPI(db)
	result, err := api.GetAuditMeta(txHash)
	if err != nil {
		t.Fatal(err)
	}
	if result.IntentIDHash != "" {
		t.Errorf("IntentIDHash = %s, want empty", result.IntentIDHash)
	}
	if result.TrustTier != 0 {
		t.Errorf("TrustTier = %d, want 0", result.TrustTier)
	}
}

func TestAPIGetSessionProof(t *testing.T) {
	db := newMockStateDB()
	txHash := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	account := common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")

	proof := BuildSessionProof(txHash, "sess-1", "POS", "term-42", 2, account, 5000)
	WriteSessionProof(db, proof)

	api := newTestAuditReceiptAPI(db)
	result, err := api.GetSessionProof(txHash)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.TxHash != txHash {
		t.Errorf("TxHash = %s, want %s", result.TxHash.Hex(), txHash.Hex())
	}
	if result.AccountAddr != account {
		t.Errorf("AccountAddr = %s, want %s", result.AccountAddr.Hex(), account.Hex())
	}
	if result.TrustTier != 2 {
		t.Errorf("TrustTier = %d, want 2", result.TrustTier)
	}
	if result.CreatedAt != 5000 {
		t.Errorf("CreatedAt = %d, want 5000", result.CreatedAt)
	}
	if result.ExpiresAt != 5000+86400 {
		t.Errorf("ExpiresAt = %d, want %d", result.ExpiresAt, 5000+86400)
	}
	if result.ProofHash == (common.Hash{}) {
		t.Error("ProofHash is zero")
	}
}

func TestAPIGetSessionProofNotFound(t *testing.T) {
	db := newMockStateDB()
	txHash := common.HexToHash("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

	api := newTestAuditReceiptAPI(db)
	result, err := api.GetSessionProof(txHash)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected nil result for non-existent session proof")
	}
}
