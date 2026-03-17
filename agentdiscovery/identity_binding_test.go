package agentdiscovery

import (
	"testing"

	"github.com/tos-network/gtos/agent"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
)

// mockStateDB is a minimal in-memory state store for testing.
type mockStateDB struct {
	store map[common.Address]map[common.Hash]common.Hash
}

func newMockStateDB() *mockStateDB {
	return &mockStateDB{store: make(map[common.Address]map[common.Hash]common.Hash)}
}

func (m *mockStateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	if slots, ok := m.store[addr]; ok {
		return slots[key]
	}
	return common.Hash{}
}

func (m *mockStateDB) SetState(addr common.Address, key common.Hash, val common.Hash) {
	if _, ok := m.store[addr]; !ok {
		m.store[addr] = make(map[common.Hash]common.Hash)
	}
	m.store[addr][key] = val
}

// registerAgent sets up an agent as registered and active in the mock state.
func registerAgent(db *mockStateDB, addr common.Address) {
	agent.WriteStatus(db, addr, agent.AgentActive)
	setRegisteredFlag(db, addr)
}

// setRegisteredFlag writes the registered flag in the same slot layout as agent.state.go.
func setRegisteredFlag(db *mockStateDB, addr common.Address) {
	// Replicate: agentSlot(addr, "registered") = keccak256(addr || 0x00 || "registered")
	key := make([]byte, 0, common.AddressLength+1+len("registered"))
	key = append(key, addr.Bytes()...)
	key = append(key, 0x00)
	key = append(key, "registered"...)
	slot := common.BytesToHash(crypto.Keccak256(key))
	var val common.Hash
	val[31] = 1
	// Write to AgentRegistryAddress, same as agent package.
	db.SetState(common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000101"), slot, val)
}

// setSuspendedFlag writes the suspended flag.
func setSuspendedFlag(db *mockStateDB, addr common.Address, suspended bool) {
	agent.WriteSuspended(db, addr, suspended)
}

func TestBindAgentCard(t *testing.T) {
	t.Parallel()

	db := newMockStateDB()
	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	registerAgent(db, addr)

	card := &AgentCard{
		AgentAddress: addr,
		Name:         "test-agent",
		Capabilities: []string{"sponsor.topup"},
	}

	if err := BindAgentCard(db, card); err != nil {
		t.Fatalf("BindAgentCard: %v", err)
	}
	if !card.OnChainVerified {
		t.Error("expected OnChainVerified = true")
	}
}

func TestBindAgentCard_NotRegistered(t *testing.T) {
	t.Parallel()

	db := newMockStateDB()
	addr := common.HexToAddress("0xdead")

	card := &AgentCard{AgentAddress: addr}
	if err := BindAgentCard(db, card); err != ErrAgentNotRegistered {
		t.Fatalf("expected ErrAgentNotRegistered, got %v", err)
	}
}

func TestBindAgentCard_Suspended(t *testing.T) {
	t.Parallel()

	db := newMockStateDB()
	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	registerAgent(db, addr)
	setSuspendedFlag(db, addr, true)

	card := &AgentCard{AgentAddress: addr}
	if err := BindAgentCard(db, card); err != ErrAgentSuspended {
		t.Fatalf("expected ErrAgentSuspended, got %v", err)
	}
}

func TestBindAgentCard_ZeroAddress(t *testing.T) {
	t.Parallel()

	db := newMockStateDB()
	card := &AgentCard{}
	if err := BindAgentCard(db, card); err != ErrCardNilAgent {
		t.Fatalf("expected ErrCardNilAgent, got %v", err)
	}
}

func TestFinalizeIdentityBinding(t *testing.T) {
	t.Parallel()

	db := newMockStateDB()
	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	registerAgent(db, addr)

	card := &AgentCard{
		AgentAddress: addr,
		Name:         "test-agent",
		Capabilities: []string{"sponsor.topup"},
		Endpoint:     "https://agent.example.com",
	}

	binding, err := FinalizeIdentityBinding(db, card, 1000)
	if err != nil {
		t.Fatalf("FinalizeIdentityBinding: %v", err)
	}

	if !binding.OnChainVerified {
		t.Error("expected OnChainVerified = true")
	}
	if !binding.CapabilitiesMatch {
		t.Error("expected CapabilitiesMatch = true")
	}
	if !binding.Active {
		t.Error("expected Active = true")
	}
	if binding.VerifiedAt != 1000 {
		t.Errorf("VerifiedAt = %d, want 1000", binding.VerifiedAt)
	}
	if binding.ExpiresAt != 1000+BindingTTLBlocks {
		t.Errorf("ExpiresAt = %d, want %d", binding.ExpiresAt, 1000+BindingTTLBlocks)
	}
	if binding.BindingHash == (common.Hash{}) {
		t.Error("expected non-zero BindingHash")
	}
	if binding.AgentAddress != addr {
		t.Errorf("AgentAddress = %s, want %s", binding.AgentAddress.Hex(), addr.Hex())
	}
}

func TestFinalizeIdentityBinding_NotRegistered(t *testing.T) {
	t.Parallel()

	db := newMockStateDB()
	card := &AgentCard{AgentAddress: common.HexToAddress("0xdead")}

	_, err := FinalizeIdentityBinding(db, card, 100)
	if err != ErrAgentNotRegistered {
		t.Fatalf("expected ErrAgentNotRegistered, got %v", err)
	}
}

func TestFinalizeIdentityBinding_Suspended(t *testing.T) {
	t.Parallel()

	db := newMockStateDB()
	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	registerAgent(db, addr)
	setSuspendedFlag(db, addr, true)

	card := &AgentCard{AgentAddress: addr}
	_, err := FinalizeIdentityBinding(db, card, 100)
	if err != ErrAgentSuspended {
		t.Fatalf("expected ErrAgentSuspended, got %v", err)
	}
}

func TestFinalizeIdentityBinding_ExcessiveFee(t *testing.T) {
	t.Parallel()

	db := newMockStateDB()
	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	registerAgent(db, addr)

	card := &AgentCard{
		AgentAddress: addr,
		FeeSchedule: &FeeSchedule{
			PercentFee: MaxFeePercentBasisPoints + 1,
		},
	}

	binding, err := FinalizeIdentityBinding(db, card, 500)
	if err != nil {
		t.Fatalf("FinalizeIdentityBinding: %v", err)
	}
	if binding.CapabilitiesMatch {
		t.Error("expected CapabilitiesMatch = false for excessive fee")
	}
	if !binding.OnChainVerified {
		t.Error("expected OnChainVerified = true even with excessive fee")
	}
}

func TestWriteReadIdentityBinding(t *testing.T) {
	t.Parallel()

	db := newMockStateDB()
	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")

	binding := &IdentityBinding{
		AgentAddress:      addr,
		OnChainVerified:   true,
		CapabilitiesMatch: true,
		Active:            true,
		BindingHash:       computeBindingHash(addr, 2000),
		VerifiedAt:        2000,
		ExpiresAt:         2000 + BindingTTLBlocks,
	}

	WriteIdentityBinding(db, binding)
	got := ReadIdentityBinding(db, addr)

	if got == nil {
		t.Fatal("ReadIdentityBinding returned nil")
	}
	if got.AgentAddress != addr {
		t.Errorf("AgentAddress = %s, want %s", got.AgentAddress.Hex(), addr.Hex())
	}
	if !got.OnChainVerified {
		t.Error("expected OnChainVerified = true")
	}
	if !got.CapabilitiesMatch {
		t.Error("expected CapabilitiesMatch = true")
	}
	if !got.Active {
		t.Error("expected Active = true")
	}
	if got.BindingHash != binding.BindingHash {
		t.Errorf("BindingHash mismatch")
	}
	if got.VerifiedAt != 2000 {
		t.Errorf("VerifiedAt = %d, want 2000", got.VerifiedAt)
	}
	if got.ExpiresAt != 2000+BindingTTLBlocks {
		t.Errorf("ExpiresAt = %d, want %d", got.ExpiresAt, 2000+BindingTTLBlocks)
	}
}

func TestReadIdentityBinding_NotFound(t *testing.T) {
	t.Parallel()

	db := newMockStateDB()
	addr := common.HexToAddress("0xdead")

	got := ReadIdentityBinding(db, addr)
	if got != nil {
		t.Fatalf("expected nil for non-existent binding, got %+v", got)
	}
}

func TestResolveAgentCard(t *testing.T) {
	t.Parallel()

	db := newMockStateDB()
	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	registerAgent(db, addr)

	card, err := ResolveAgentCard(db, addr)
	if err != nil {
		t.Fatalf("ResolveAgentCard: %v", err)
	}
	if !card.OnChainVerified {
		t.Error("expected OnChainVerified = true")
	}
	if card.AgentAddress != addr {
		t.Errorf("AgentAddress mismatch")
	}
}

func TestComputeBindingHash_Deterministic(t *testing.T) {
	t.Parallel()

	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	h1 := computeBindingHash(addr, 100)
	h2 := computeBindingHash(addr, 100)
	if h1 != h2 {
		t.Error("expected deterministic hash")
	}

	h3 := computeBindingHash(addr, 101)
	if h1 == h3 {
		t.Error("expected different hash for different block number")
	}
}
