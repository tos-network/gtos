package auditreceipt

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/internal/testfixtures"
)

// ---------- helpers ----------

var (
	testFromAddr      = testfixtures.Secp256k1AddrA
	testSponsorAddr   = testfixtures.Secp256k1AddrB
	testRecipientAddr = testfixtures.Secp256k1AddrC
)

func makeTestHeader() *types.Header {
	return &types.Header{
		Number: big.NewInt(42),
		Time:   1700000000,
	}
}

func makeTestReceipt(txHash common.Hash) *types.Receipt {
	return &types.Receipt{
		Type:              types.SignerTxType,
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: 21000,
		GasUsed:           21000,
		TxHash:            txHash,
	}
}

func makeTestTx(to common.Address) *types.Transaction {
	return types.NewTx(&types.SignerTx{
		ChainID:    big.NewInt(1),
		Nonce:      0,
		Gas:        21000,
		To:         &to,
		Value:      big.NewInt(1000),
		Data:       nil,
		From:       testFromAddr,
		SignerType: "secp256k1",
		V:          big.NewInt(0),
		R:          big.NewInt(0),
		S:          big.NewInt(0),
		SponsorV:   big.NewInt(0),
		SponsorR:   big.NewInt(0),
		SponsorS:   big.NewInt(0),
	})
}

func makeSponsoredTx(to common.Address) *types.Transaction {
	return types.NewTx(&types.SignerTx{
		ChainID:           big.NewInt(1),
		Nonce:             5,
		Gas:               50000,
		To:                &to,
		Value:             big.NewInt(2000),
		Data:              nil,
		From:              testFromAddr,
		SignerType:        "secp256k1",
		Sponsor:           testSponsorAddr,
		SponsorSignerType: "secp256k1",
		SponsorNonce:      10,
		SponsorExpiry:     1700001000,
		SponsorPolicyHash: common.HexToHash("0xaaaa"),
		V:                 big.NewInt(0),
		R:                 big.NewInt(0),
		S:                 big.NewInt(0),
		SponsorV:          big.NewInt(0),
		SponsorR:          big.NewInt(0),
		SponsorS:          big.NewInt(0),
	})
}

// ---------- Tests ----------

func TestBuildFromReceipt(t *testing.T) {
	to := testRecipientAddr
	tx := makeTestTx(to)
	txHash := tx.Hash()
	receipt := makeTestReceipt(txHash)
	header := makeTestHeader()

	ar := BuildFromReceipt(receipt, tx, header)

	if ar.TxHash != txHash {
		t.Errorf("TxHash mismatch: got %s, want %s", ar.TxHash.Hex(), txHash.Hex())
	}
	if ar.Status != types.ReceiptStatusSuccessful {
		t.Errorf("Status mismatch: got %d, want %d", ar.Status, types.ReceiptStatusSuccessful)
	}
	if ar.GasUsed != 21000 {
		t.Errorf("GasUsed mismatch: got %d, want 21000", ar.GasUsed)
	}
	if ar.BlockNumber != 42 {
		t.Errorf("BlockNumber mismatch: got %d, want 42", ar.BlockNumber)
	}
	if ar.SettledAt != 1700000000 {
		t.Errorf("SettledAt mismatch: got %d, want 1700000000", ar.SettledAt)
	}
	if ar.From != testFromAddr {
		t.Errorf("From mismatch: got %s", ar.From.Hex())
	}
	if ar.To != to {
		t.Errorf("To mismatch: got %s, want %s", ar.To.Hex(), to.Hex())
	}
	if ar.SignerType != "secp256k1" {
		t.Errorf("SignerType mismatch: got %s, want secp256k1", ar.SignerType)
	}
	if ar.Value.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("Value mismatch: got %s, want 1000", ar.Value.String())
	}
	if ar.ReceiptHash == (common.Hash{}) {
		t.Error("ReceiptHash should not be zero")
	}
	// Non-sponsored tx should have zero sponsor.
	if ar.Sponsor != (common.Address{}) {
		t.Errorf("Sponsor should be zero for non-sponsored tx, got %s", ar.Sponsor.Hex())
	}
}

func TestBuildFromReceipt_Sponsored(t *testing.T) {
	to := testRecipientAddr
	tx := makeSponsoredTx(to)
	txHash := tx.Hash()
	receipt := makeTestReceipt(txHash)
	header := makeTestHeader()

	ar := BuildFromReceipt(receipt, tx, header)

	expectedSponsor := testSponsorAddr
	if ar.Sponsor != expectedSponsor {
		t.Errorf("Sponsor mismatch: got %s, want %s", ar.Sponsor.Hex(), expectedSponsor.Hex())
	}
	if ar.SponsorPolicyHash != common.HexToHash("0xaaaa") {
		t.Errorf("SponsorPolicyHash mismatch: got %s", ar.SponsorPolicyHash.Hex())
	}
}

func TestComputeReceiptHash_Determinism(t *testing.T) {
	ar := &AuditReceipt{
		TxHash:      common.HexToHash("0xdeadbeef"),
		BlockNumber: 100,
		Status:      1,
		GasUsed:     21000,
		From:        testFromAddr,
		To:          testSponsorAddr,
		Value:       big.NewInt(500),
		SettledAt:   1700000000,
	}

	hash1 := ComputeReceiptHash(ar)
	hash2 := ComputeReceiptHash(ar)

	if hash1 != hash2 {
		t.Errorf("ComputeReceiptHash is not deterministic: %s != %s", hash1.Hex(), hash2.Hex())
	}

	if hash1 == (common.Hash{}) {
		t.Error("ComputeReceiptHash should not return zero hash")
	}

	// Changing a field should produce a different hash.
	ar2 := *ar
	ar2.GasUsed = 42000
	hash3 := ComputeReceiptHash(&ar2)
	if hash1 == hash3 {
		t.Error("ComputeReceiptHash should produce different hash for different inputs")
	}
}

func TestBuildSponsorAttribution(t *testing.T) {
	to := testRecipientAddr
	tx := makeSponsoredTx(to)
	txHash := tx.Hash()
	receipt := makeTestReceipt(txHash)

	sar := BuildSponsorAttribution(tx, receipt, 1700000000)

	if sar == nil {
		t.Fatal("BuildSponsorAttribution returned nil for sponsored tx")
	}
	if sar.TxHash != txHash {
		t.Errorf("TxHash mismatch: got %s, want %s", sar.TxHash.Hex(), txHash.Hex())
	}
	if sar.SponsorAddress != testSponsorAddr {
		t.Errorf("SponsorAddress mismatch: got %s", sar.SponsorAddress.Hex())
	}
	if sar.SponsorSignerType != "secp256k1" {
		t.Errorf("SponsorSignerType mismatch: got %s", sar.SponsorSignerType)
	}
	if sar.SponsorNonce != 10 {
		t.Errorf("SponsorNonce mismatch: got %d, want 10", sar.SponsorNonce)
	}
	if sar.SponsorExpiry != 1700001000 {
		t.Errorf("SponsorExpiry mismatch: got %d, want 1700001000", sar.SponsorExpiry)
	}
	if sar.PolicyHash != common.HexToHash("0xaaaa") {
		t.Errorf("PolicyHash mismatch: got %s", sar.PolicyHash.Hex())
	}
	if sar.GasSponsored != 21000 {
		t.Errorf("GasSponsored mismatch: got %d, want 21000", sar.GasSponsored)
	}
	if sar.Timestamp != 1700000000 {
		t.Errorf("Timestamp mismatch: got %d, want 1700000000", sar.Timestamp)
	}
}

func TestBuildSponsorAttribution_NonSponsored(t *testing.T) {
	to := testRecipientAddr
	tx := makeTestTx(to)
	receipt := makeTestReceipt(tx.Hash())

	sar := BuildSponsorAttribution(tx, receipt, 1700000000)
	if sar != nil {
		t.Error("BuildSponsorAttribution should return nil for non-sponsored tx")
	}
}

func TestBuildSettlementTrace(t *testing.T) {
	to := testRecipientAddr
	tx := makeTestTx(to)
	txHash := tx.Hash()
	receipt := makeTestReceipt(txHash)
	header := makeTestHeader()

	st := BuildSettlementTrace(receipt, tx, header)

	if st.TxHash != txHash {
		t.Errorf("TxHash mismatch: got %s, want %s", st.TxHash.Hex(), txHash.Hex())
	}
	if !st.Success {
		t.Error("Success should be true for successful receipt")
	}
	if st.From != testFromAddr {
		t.Errorf("From mismatch: got %s", st.From.Hex())
	}
	if st.To != to {
		t.Errorf("To mismatch: got %s, want %s", st.To.Hex(), to.Hex())
	}
	if st.Value.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("Value mismatch: got %s, want 1000", st.Value.String())
	}
	if st.BlockNumber != 42 {
		t.Errorf("BlockNumber mismatch: got %d, want 42", st.BlockNumber)
	}
	if st.Timestamp != 1700000000 {
		t.Errorf("Timestamp mismatch: got %d, want 1700000000", st.Timestamp)
	}
}

// ---------- State tests ----------

// mockStateDB is a simple in-memory state database for testing.
type mockStateDB struct {
	storage map[common.Address]map[common.Hash]common.Hash
}

func newMockStateDB() *mockStateDB {
	return &mockStateDB{
		storage: make(map[common.Address]map[common.Hash]common.Hash),
	}
}

func (m *mockStateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	if slots, ok := m.storage[addr]; ok {
		return slots[key]
	}
	return common.Hash{}
}

func (m *mockStateDB) SetState(addr common.Address, key common.Hash, val common.Hash) {
	if _, ok := m.storage[addr]; !ok {
		m.storage[addr] = make(map[common.Hash]common.Hash)
	}
	m.storage[addr][key] = val
}

func TestWriteReadAuditMeta(t *testing.T) {
	db := newMockStateDB()
	txHash := common.HexToHash("0xdeadbeef")

	WriteAuditMeta(db, txHash, "intent-123", "plan-456", "app", 3)

	intentHash, planHash, classHash, trustTier := ReadAuditMeta(db, txHash)

	if intentHash == "" {
		t.Error("intentIDHash should not be empty")
	}
	if planHash == "" {
		t.Error("planIDHash should not be empty")
	}
	if classHash == "" {
		t.Error("terminalClassHash should not be empty")
	}
	if trustTier != 3 {
		t.Errorf("trustTier mismatch: got %d, want 3", trustTier)
	}
}

func TestReadAuditMeta_Empty(t *testing.T) {
	db := newMockStateDB()
	txHash := common.HexToHash("0xdeadbeef")

	intentHash, planHash, classHash, trustTier := ReadAuditMeta(db, txHash)

	if intentHash != "" {
		t.Errorf("intentIDHash should be empty, got %s", intentHash)
	}
	if planHash != "" {
		t.Errorf("planIDHash should be empty, got %s", planHash)
	}
	if classHash != "" {
		t.Errorf("terminalClassHash should be empty, got %s", classHash)
	}
	if trustTier != 0 {
		t.Errorf("trustTier should be 0, got %d", trustTier)
	}
}
