package gateway

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
)

// ---------- mock StateDB ----------

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

// ---------- test addresses ----------

var (
	gwAddrA = common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")
	gwAddrB = common.HexToAddress("0x473302ca547d5f9877e272cffe58d4def43198b66ba35cff4b2e584be19efa05")
)

// ---------- Active flag ----------

func TestWriteReadActive(t *testing.T) {
	db := newMockStateDB()

	if ReadActive(db, gwAddrA) {
		t.Fatal("gateway should not be active by default")
	}

	WriteActive(db, gwAddrA, true)
	if !ReadActive(db, gwAddrA) {
		t.Fatal("gateway should be active after write")
	}

	WriteActive(db, gwAddrA, false)
	if ReadActive(db, gwAddrA) {
		t.Fatal("gateway should be inactive after deactivation")
	}
}

// ---------- RegisteredAt ----------

func TestWriteReadRegisteredAt(t *testing.T) {
	db := newMockStateDB()

	if ReadRegisteredAt(db, gwAddrA) != 0 {
		t.Fatal("registered_at should be 0 by default")
	}

	WriteRegisteredAt(db, gwAddrA, 12345)
	got := ReadRegisteredAt(db, gwAddrA)
	if got != 12345 {
		t.Fatalf("registered_at mismatch: got %d, want 12345", got)
	}
}

// ---------- MaxRelayGas ----------

func TestWriteReadMaxRelayGas(t *testing.T) {
	db := newMockStateDB()

	WriteMaxRelayGas(db, gwAddrA, 500_000)
	got := ReadMaxRelayGas(db, gwAddrA)
	if got != 500_000 {
		t.Fatalf("max_relay_gas mismatch: got %d, want 500000", got)
	}
}

// ---------- FeePolicy ----------

func TestWriteReadFeePolicy(t *testing.T) {
	db := newMockStateDB()

	if ReadFeePolicy(db, gwAddrA) != "" {
		t.Fatal("fee_policy should be empty by default")
	}

	for _, policy := range []string{"free", "fixed", "percent"} {
		WriteFeePolicy(db, gwAddrA, policy)
		got := ReadFeePolicy(db, gwAddrA)
		if got != policy {
			t.Fatalf("fee_policy mismatch: got %q, want %q", got, policy)
		}
	}
}

// ---------- FeeAmount ----------

func TestWriteReadFeeAmount(t *testing.T) {
	db := newMockStateDB()

	amount := big.NewInt(1_000_000)
	WriteFeeAmount(db, gwAddrA, amount)
	got := ReadFeeAmount(db, gwAddrA)
	if got.Cmp(amount) != 0 {
		t.Fatalf("fee_amount mismatch: got %s, want %s", got, amount)
	}
}

// ---------- Endpoint (multi-slot) ----------

func TestWriteReadEndpoint_Short(t *testing.T) {
	db := newMockStateDB()

	endpoint := "https://relay.example.com"
	WriteEndpoint(db, gwAddrA, endpoint)
	got := ReadEndpoint(db, gwAddrA)
	if got != endpoint {
		t.Fatalf("endpoint mismatch: got %q, want %q", got, endpoint)
	}
}

func TestWriteReadEndpoint_Long(t *testing.T) {
	db := newMockStateDB()

	// Endpoint longer than 32 bytes to exercise multi-slot storage.
	endpoint := "https://gateway.relay.example.com/api/v2/relay/mainnet"
	WriteEndpoint(db, gwAddrA, endpoint)
	got := ReadEndpoint(db, gwAddrA)
	if got != endpoint {
		t.Fatalf("endpoint mismatch: got %q, want %q", got, endpoint)
	}
}

func TestReadEndpoint_Empty(t *testing.T) {
	db := newMockStateDB()

	got := ReadEndpoint(db, gwAddrA)
	if got != "" {
		t.Fatalf("expected empty endpoint, got %q", got)
	}
}

// ---------- SupportedKinds ----------

func TestWriteReadSupportedKinds(t *testing.T) {
	db := newMockStateDB()

	kinds := []string{"signer", "paymaster", "oracle"}
	WriteSupportedKinds(db, gwAddrA, kinds)
	got := ReadSupportedKinds(db, gwAddrA)

	if len(got) != len(kinds) {
		t.Fatalf("kinds count mismatch: got %d, want %d", len(got), len(kinds))
	}
	// WriteSupportedKinds sorts the input, so expect sorted order.
	want := []string{"oracle", "paymaster", "signer"}
	for i, k := range want {
		if got[i] != k {
			t.Errorf("kind %d mismatch: got %q, want %q", i, got[i], k)
		}
	}
}

func TestReadSupportedKinds_Empty(t *testing.T) {
	db := newMockStateDB()

	got := ReadSupportedKinds(db, gwAddrA)
	if got != nil {
		t.Fatalf("expected nil kinds, got %v", got)
	}
}

// ---------- Gateway count ----------

func TestGatewayCount(t *testing.T) {
	db := newMockStateDB()

	if ReadGatewayCount(db) != 0 {
		t.Fatal("count should be 0 initially")
	}

	IncrementGatewayCount(db)
	IncrementGatewayCount(db)
	IncrementGatewayCount(db)

	if got := ReadGatewayCount(db); got != 3 {
		t.Fatalf("count mismatch: got %d, want 3", got)
	}
}

// ---------- Multiple gateway registrations ----------

func TestMultipleGateways(t *testing.T) {
	db := newMockStateDB()

	// Register gateway A.
	WriteActive(db, gwAddrA, true)
	WriteEndpoint(db, gwAddrA, "https://a.example.com")
	WriteSupportedKinds(db, gwAddrA, []string{"signer"})
	WriteMaxRelayGas(db, gwAddrA, 100_000)
	WriteFeePolicy(db, gwAddrA, "free")
	WriteFeeAmount(db, gwAddrA, big.NewInt(0))
	WriteRegisteredAt(db, gwAddrA, 100)
	IncrementGatewayCount(db)

	// Register gateway B.
	WriteActive(db, gwAddrB, true)
	WriteEndpoint(db, gwAddrB, "https://b.example.com")
	WriteSupportedKinds(db, gwAddrB, []string{"paymaster", "oracle"})
	WriteMaxRelayGas(db, gwAddrB, 200_000)
	WriteFeePolicy(db, gwAddrB, "fixed")
	WriteFeeAmount(db, gwAddrB, big.NewInt(5000))
	WriteRegisteredAt(db, gwAddrB, 200)
	IncrementGatewayCount(db)

	// Verify independence.
	if ReadEndpoint(db, gwAddrA) != "https://a.example.com" {
		t.Error("gateway A endpoint mismatch")
	}
	if ReadEndpoint(db, gwAddrB) != "https://b.example.com" {
		t.Error("gateway B endpoint mismatch")
	}

	kindsA := ReadSupportedKinds(db, gwAddrA)
	if len(kindsA) != 1 || kindsA[0] != "signer" {
		t.Errorf("gateway A kinds mismatch: %v", kindsA)
	}
	kindsB := ReadSupportedKinds(db, gwAddrB)
	if len(kindsB) != 2 || kindsB[0] != "oracle" || kindsB[1] != "paymaster" {
		t.Errorf("gateway B kinds mismatch: %v", kindsB)
	}

	if ReadFeeAmount(db, gwAddrA).Sign() != 0 {
		t.Error("gateway A fee should be 0")
	}
	if ReadFeeAmount(db, gwAddrB).Cmp(big.NewInt(5000)) != 0 {
		t.Error("gateway B fee should be 5000")
	}

	if ReadGatewayCount(db) != 2 {
		t.Errorf("gateway count should be 2, got %d", ReadGatewayCount(db))
	}
}

// ---------- Full GatewayConfig round-trip ----------

func TestGatewayConfig_RoundTrip(t *testing.T) {
	db := newMockStateDB()
	addr := gwAddrA

	cfg := GatewayConfig{
		AgentAddress:   addr,
		Endpoint:       "https://relay.tos.network/v1",
		SupportedKinds: []string{"signer", "paymaster"},
		MaxRelayGas:    300_000,
		FeePolicy:      "percent",
		FeeAmount:      big.NewInt(250),
		Active:         true,
		RegisteredAt:   42,
	}

	// Write all fields.
	WriteEndpoint(db, addr, cfg.Endpoint)
	WriteSupportedKinds(db, addr, cfg.SupportedKinds)
	WriteMaxRelayGas(db, addr, cfg.MaxRelayGas)
	WriteFeePolicy(db, addr, cfg.FeePolicy)
	WriteFeeAmount(db, addr, cfg.FeeAmount)
	WriteActive(db, addr, cfg.Active)
	WriteRegisteredAt(db, addr, cfg.RegisteredAt)

	// Read back and verify.
	if got := ReadEndpoint(db, addr); got != cfg.Endpoint {
		t.Errorf("Endpoint: got %q, want %q", got, cfg.Endpoint)
	}
	kinds := ReadSupportedKinds(db, addr)
	if len(kinds) != 2 || kinds[0] != "paymaster" || kinds[1] != "signer" {
		t.Errorf("SupportedKinds: got %v", kinds)
	}
	if got := ReadMaxRelayGas(db, addr); got != cfg.MaxRelayGas {
		t.Errorf("MaxRelayGas: got %d, want %d", got, cfg.MaxRelayGas)
	}
	if got := ReadFeePolicy(db, addr); got != cfg.FeePolicy {
		t.Errorf("FeePolicy: got %q, want %q", got, cfg.FeePolicy)
	}
	if got := ReadFeeAmount(db, addr); got.Cmp(cfg.FeeAmount) != 0 {
		t.Errorf("FeeAmount: got %s, want %s", got, cfg.FeeAmount)
	}
	if !ReadActive(db, addr) {
		t.Error("Active should be true")
	}
	if got := ReadRegisteredAt(db, addr); got != cfg.RegisteredAt {
		t.Errorf("RegisteredAt: got %d, want %d", got, cfg.RegisteredAt)
	}
}
