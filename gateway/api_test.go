package gateway

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
)

// mockStateDB and newMockStateDB are defined in gateway_test.go.

func newTestGatewayAPI(db *mockStateDB) *PublicGatewayAPI {
	return NewPublicGatewayAPI(func() stateDB { return db })
}

func TestAPIGetGatewayConfig(t *testing.T) {
	db := newMockStateDB()
	agent := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Register a gateway.
	WriteActive(db, agent, true)
	WriteRegisteredAt(db, agent, 100)
	WriteEndpoint(db, agent, "https://relay.example.com")
	WriteSupportedKinds(db, agent, []string{"signer", "paymaster"})
	WriteMaxRelayGas(db, agent, 500000)
	WriteFeePolicy(db, agent, "fixed")
	WriteFeeAmount(db, agent, big.NewInt(1000))

	api := newTestGatewayAPI(db)
	result, err := api.GetGatewayConfig(agent)
	if err != nil {
		t.Fatal(err)
	}
	if result.AgentAddress != agent {
		t.Errorf("AgentAddress = %s, want %s", result.AgentAddress.Hex(), agent.Hex())
	}
	if result.Endpoint != "https://relay.example.com" {
		t.Errorf("Endpoint = %s, want https://relay.example.com", result.Endpoint)
	}
	if len(result.SupportedKinds) != 2 || result.SupportedKinds[0] != "paymaster" || result.SupportedKinds[1] != "signer" {
		t.Errorf("SupportedKinds = %v, want [paymaster signer]", result.SupportedKinds)
	}
	if result.MaxRelayGas != 500000 {
		t.Errorf("MaxRelayGas = %d, want 500000", result.MaxRelayGas)
	}
	if result.FeePolicy != "fixed" {
		t.Errorf("FeePolicy = %s, want fixed", result.FeePolicy)
	}
	if result.FeeAmount != "1000" {
		t.Errorf("FeeAmount = %s, want 1000", result.FeeAmount)
	}
	if !result.Active {
		t.Error("Active = false, want true")
	}
	if result.RegisteredAt != 100 {
		t.Errorf("RegisteredAt = %d, want 100", result.RegisteredAt)
	}
}

func TestAPIGetGatewayConfigNotFound(t *testing.T) {
	db := newMockStateDB()
	agent := common.HexToAddress("0x2222222222222222222222222222222222222222")

	api := newTestGatewayAPI(db)
	_, err := api.GetGatewayConfig(agent)
	if err != ErrGatewayNotFound {
		t.Errorf("err = %v, want ErrGatewayNotFound", err)
	}
}

func TestAPIIsGatewayActive(t *testing.T) {
	db := newMockStateDB()
	agent := common.HexToAddress("0x1111111111111111111111111111111111111111")
	WriteActive(db, agent, true)

	api := newTestGatewayAPI(db)
	active, err := api.IsGatewayActive(agent)
	if err != nil {
		t.Fatal(err)
	}
	if !active {
		t.Error("IsGatewayActive = false, want true")
	}

	// Check inactive.
	other := common.HexToAddress("0x3333333333333333333333333333333333333333")
	active, err = api.IsGatewayActive(other)
	if err != nil {
		t.Fatal(err)
	}
	if active {
		t.Error("IsGatewayActive = true, want false")
	}
}
