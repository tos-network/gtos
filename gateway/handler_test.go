package gateway

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

// ---------- full vmtypes.StateDB mock ----------

type handlerMockStateDB struct {
	storage map[common.Address]map[common.Hash]common.Hash
}

func newHandlerMockStateDB() *handlerMockStateDB {
	return &handlerMockStateDB{
		storage: make(map[common.Address]map[common.Hash]common.Hash),
	}
}

func (m *handlerMockStateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	if slots, ok := m.storage[addr]; ok {
		return slots[key]
	}
	return common.Hash{}
}

func (m *handlerMockStateDB) SetState(addr common.Address, key common.Hash, val common.Hash) {
	if _, ok := m.storage[addr]; !ok {
		m.storage[addr] = make(map[common.Hash]common.Hash)
	}
	m.storage[addr][key] = val
}

func (m *handlerMockStateDB) CreateAccount(common.Address)                           {}
func (m *handlerMockStateDB) SubBalance(common.Address, *big.Int)                    {}
func (m *handlerMockStateDB) AddBalance(common.Address, *big.Int)                    {}
func (m *handlerMockStateDB) GetBalance(common.Address) *big.Int                     { return big.NewInt(0) }
func (m *handlerMockStateDB) GetNonce(common.Address) uint64                         { return 0 }
func (m *handlerMockStateDB) SetNonce(common.Address, uint64)                        {}
func (m *handlerMockStateDB) GetCodeHash(common.Address) common.Hash                 { return common.Hash{} }
func (m *handlerMockStateDB) GetCode(common.Address) []byte                          { return nil }
func (m *handlerMockStateDB) SetCode(common.Address, []byte)                         {}
func (m *handlerMockStateDB) GetCodeSize(common.Address) int                         { return 0 }
func (m *handlerMockStateDB) AddRefund(uint64)                                       {}
func (m *handlerMockStateDB) SubRefund(uint64)                                       {}
func (m *handlerMockStateDB) GetRefund() uint64                                      { return 0 }
func (m *handlerMockStateDB) GetCommittedState(common.Address, common.Hash) common.Hash {
	return common.Hash{}
}
func (m *handlerMockStateDB) Suicide(common.Address) bool    { return false }
func (m *handlerMockStateDB) HasSuicided(common.Address) bool { return false }
func (m *handlerMockStateDB) Exist(common.Address) bool      { return false }
func (m *handlerMockStateDB) Empty(common.Address) bool      { return true }
func (m *handlerMockStateDB) PrepareAccessList(common.Address, *common.Address, []common.Address, types.AccessList) {
}
func (m *handlerMockStateDB) AddressInAccessList(common.Address) bool { return false }
func (m *handlerMockStateDB) SlotInAccessList(common.Address, common.Hash) (bool, bool) {
	return false, false
}
func (m *handlerMockStateDB) AddAddressToAccessList(common.Address)             {}
func (m *handlerMockStateDB) AddSlotToAccessList(common.Address, common.Hash)   {}
func (m *handlerMockStateDB) RevertToSnapshot(int)                              {}
func (m *handlerMockStateDB) Snapshot() int                                     { return 0 }
func (m *handlerMockStateDB) AddLog(*types.Log)                                 {}
func (m *handlerMockStateDB) Logs() []*types.Log                                { return nil }
func (m *handlerMockStateDB) AddPreimage(common.Hash, []byte)                   {}
func (m *handlerMockStateDB) ForEachStorage(common.Address, func(common.Hash, common.Hash) bool) error {
	return nil
}

// ---------- helpers ----------

func makeCtx(db *handlerMockStateDB, from common.Address, blockNum uint64) *sysaction.Context {
	return &sysaction.Context{
		From:        from,
		Value:       big.NewInt(0),
		BlockNumber: new(big.Int).SetUint64(blockNum),
		StateDB:     db,
	}
}

func makeSysAction(kind sysaction.ActionKind, payload interface{}) *sysaction.SysAction {
	raw, _ := json.Marshal(payload)
	return &sysaction.SysAction{
		Action:  kind,
		Payload: raw,
	}
}

// agentSlot replicates the agent package's slot computation:
// keccak256(addr[20] || 0x00 || field).
func agentSlot(addr common.Address, field string) common.Hash {
	key := make([]byte, 0, common.AddressLength+1+len(field))
	key = append(key, addr.Bytes()...)
	key = append(key, 0x00)
	key = append(key, field...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// capBitmapSlot replicates capability package's bitmapSlot:
// keccak256("cap\x00bitmap\x00" || addr[20]).
func capBitmapSlot(addr common.Address) common.Hash {
	key := append([]byte("cap\x00bitmap\x00"), addr.Bytes()...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// capNameSlot replicates capability package's nameSlot:
// keccak256("cap\x00name\x00" || name).
func capNameSlot(name string) common.Hash {
	key := append([]byte("cap\x00name\x00"), []byte(name)...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// setupAgentWithGatewayCapability sets the storage slots directly so that
// agent.IsRegistered returns true and capability.HasCapability returns true
// for the GatewayRelay capability.
func setupAgentWithGatewayCapability(db *handlerMockStateDB, addr common.Address) {
	// 1. Mark agent as registered: slot = agentSlot(addr, "registered"), value[31] = 1.
	var regVal common.Hash
	regVal[31] = 1
	db.SetState(params.AgentRegistryAddress, agentSlot(addr, "registered"), regVal)

	// 2. Register capability name "GatewayRelay" -> bit 0.
	//    nameSlot value: byte[30] = 1 (set marker), byte[31] = 0 (bit index).
	var nameVal common.Hash
	nameVal[30] = 1 // set marker
	nameVal[31] = 0 // bit 0
	db.SetState(params.CapabilityRegistryAddress, capNameSlot(CapabilityName), nameVal)

	// 3. Grant capability bit 0 to addr: bitmap = 1.
	db.SetState(params.CapabilityRegistryAddress, capBitmapSlot(addr), common.BigToHash(big.NewInt(1)))
}

var (
	agentAddr    = common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")
	strangerAddr = common.HexToAddress("0xf71d99c2b05b3ab38ebabfae54f08b149f9dffa9fd49cf69e20b9f0ea86514f2")
)

// ---------- Register ----------

func TestHandleGatewayRegister_Success(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &gatewayHandler{}

	setupAgentWithGatewayCapability(db, agentAddr)

	ctx := makeCtx(db, agentAddr, 100)
	sa := makeSysAction(sysaction.ActionGatewayRegister, RegisterGatewayPayload{
		Endpoint:       "https://relay.example.com",
		SupportedKinds: []string{"signer", "paymaster"},
		MaxRelayGas:    500_000,
		FeePolicy:      "free",
	})

	if err := h.Handle(ctx, sa); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !ReadActive(db, agentAddr) {
		t.Fatal("gateway should be active")
	}
	if got := ReadEndpoint(db, agentAddr); got != "https://relay.example.com" {
		t.Fatalf("endpoint mismatch: got %q", got)
	}
	kinds := ReadSupportedKinds(db, agentAddr)
	if len(kinds) != 2 || kinds[0] != "paymaster" || kinds[1] != "signer" {
		t.Fatalf("supported kinds mismatch: %v", kinds)
	}
	if got := ReadMaxRelayGas(db, agentAddr); got != 500_000 {
		t.Fatalf("max relay gas mismatch: got %d", got)
	}
	if got := ReadFeePolicy(db, agentAddr); got != "free" {
		t.Fatalf("fee policy mismatch: got %q", got)
	}
	if got := ReadRegisteredAt(db, agentAddr); got != 100 {
		t.Fatalf("registered_at mismatch: got %d", got)
	}
	if got := ReadGatewayCount(db); got != 1 {
		t.Fatalf("gateway count should be 1, got %d", got)
	}
}

func TestHandleGatewayRegister_NoAgent(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &gatewayHandler{}

	// Agent not registered.
	ctx := makeCtx(db, strangerAddr, 100)
	sa := makeSysAction(sysaction.ActionGatewayRegister, RegisterGatewayPayload{
		Endpoint:       "https://relay.example.com",
		SupportedKinds: []string{"signer"},
		MaxRelayGas:    100_000,
		FeePolicy:      "free",
	})

	if err := h.Handle(ctx, sa); err != ErrNotRegisteredAgent {
		t.Fatalf("expected ErrNotRegisteredAgent, got %v", err)
	}
}

func TestHandleGatewayRegister_NoCapability(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &gatewayHandler{}

	// Register agent but do not grant GatewayRelay capability.
	var regVal common.Hash
	regVal[31] = 1
	db.SetState(params.AgentRegistryAddress, agentSlot(agentAddr, "registered"), regVal)

	ctx := makeCtx(db, agentAddr, 100)
	sa := makeSysAction(sysaction.ActionGatewayRegister, RegisterGatewayPayload{
		Endpoint:       "https://relay.example.com",
		SupportedKinds: []string{"signer"},
		MaxRelayGas:    100_000,
		FeePolicy:      "free",
	})

	if err := h.Handle(ctx, sa); err != ErrNoGatewayCapability {
		t.Fatalf("expected ErrNoGatewayCapability, got %v", err)
	}
}

// ---------- Update ----------

func TestHandleGatewayUpdate_Success(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &gatewayHandler{}

	setupAgentWithGatewayCapability(db, agentAddr)

	// Register first.
	ctx := makeCtx(db, agentAddr, 100)
	regSA := makeSysAction(sysaction.ActionGatewayRegister, RegisterGatewayPayload{
		Endpoint:       "https://old.example.com",
		SupportedKinds: []string{"signer"},
		MaxRelayGas:    100_000,
		FeePolicy:      "free",
	})
	if err := h.Handle(ctx, regSA); err != nil {
		t.Fatalf("register failed: %v", err)
	}

	// Update endpoint.
	updateSA := makeSysAction(sysaction.ActionGatewayUpdate, UpdateGatewayPayload{
		Endpoint: "https://new.example.com",
	})
	if err := h.Handle(ctx, updateSA); err != nil {
		t.Fatalf("update failed: %v", err)
	}

	if got := ReadEndpoint(db, agentAddr); got != "https://new.example.com" {
		t.Fatalf("endpoint not updated: got %q", got)
	}
	// Unchanged fields should remain.
	if got := ReadMaxRelayGas(db, agentAddr); got != 100_000 {
		t.Fatalf("max relay gas should be unchanged, got %d", got)
	}
}

func TestHandleGatewayUpdate_NotRegistered(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &gatewayHandler{}

	ctx := makeCtx(db, agentAddr, 100)
	sa := makeSysAction(sysaction.ActionGatewayUpdate, UpdateGatewayPayload{
		Endpoint: "https://new.example.com",
	})

	if err := h.Handle(ctx, sa); err != ErrGatewayNotFound {
		t.Fatalf("expected ErrGatewayNotFound, got %v", err)
	}
}

// ---------- Deregister ----------

func TestHandleGatewayDeregister_Success(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &gatewayHandler{}

	setupAgentWithGatewayCapability(db, agentAddr)

	// Register first.
	ctx := makeCtx(db, agentAddr, 100)
	regSA := makeSysAction(sysaction.ActionGatewayRegister, RegisterGatewayPayload{
		Endpoint:       "https://relay.example.com",
		SupportedKinds: []string{"signer"},
		MaxRelayGas:    100_000,
		FeePolicy:      "free",
	})
	if err := h.Handle(ctx, regSA); err != nil {
		t.Fatalf("register failed: %v", err)
	}

	// Deregister.
	deregSA := makeSysAction(sysaction.ActionGatewayDeregister, struct{}{})
	if err := h.Handle(ctx, deregSA); err != nil {
		t.Fatalf("deregister failed: %v", err)
	}

	if ReadActive(db, agentAddr) {
		t.Fatal("gateway should be inactive after deregister")
	}
}

func TestHandleGatewayDeregister_NotRegistered(t *testing.T) {
	db := newHandlerMockStateDB()
	h := &gatewayHandler{}

	ctx := makeCtx(db, agentAddr, 100)
	sa := makeSysAction(sysaction.ActionGatewayDeregister, struct{}{})

	if err := h.Handle(ctx, sa); err != ErrGatewayNotFound {
		t.Fatalf("expected ErrGatewayNotFound, got %v", err)
	}
}
