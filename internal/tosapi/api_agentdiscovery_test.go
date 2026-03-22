package tosapi

import (
	"context"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/tos-network/gtos/agentdiscovery"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/p2p/discover"
	"github.com/tos-network/gtos/p2p/enode"
	"github.com/tos-network/gtos/p2p/enr"
	lua "github.com/tos-network/tolang"
)

const agentDiscoverySuggestedSource = `pragma tolang 0.4.0;
package demo.suggested;

capability SettlementExecute;

contract SettlementAgent {
    /// @requires(caller: SettlementExecute)
    function execute() public {
    }
}
`

const agentDiscoverySuggestedPackageSource = `pragma tolang 0.4.0;
package demo.bundle;

capability CheckoutExecute;

contract CheckoutAgent {
    /// @requires(caller: CheckoutExecute)
    function execute() public {
    }
}
`

type agentDiscoveryBackendMock struct {
	*getCodeBackendMock
	discovery *agentdiscovery.Service
}

func (b *agentDiscoveryBackendMock) AgentDiscovery() *agentdiscovery.Service {
	return b.discovery
}

func TestAgentDiscoveryPublishSuggestedArtifact(t *testing.T) {
	provider := startLocalUDPv5ForAPI(t)
	defer provider.Close()

	requester := startLocalUDPv5ForAPI(t, provider.Self())
	defer requester.Close()

	providerSvc, err := agentdiscovery.New(provider.LocalNode(), provider)
	if err != nil {
		t.Fatalf("new provider service: %v", err)
	}
	requesterSvc, err := agentdiscovery.New(requester.LocalNode(), requester)
	if err != nil {
		t.Fatalf("new requester service: %v", err)
	}

	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	artifact, err := lua.CompileArtifact([]byte(agentDiscoverySuggestedSource), "SettlementAgent.tol")
	if err != nil {
		t.Fatalf("compile source: %v", err)
	}
	addr := common.HexToAddress("0x4444444444444444444444444444444444444444444444444444444444444444")
	st.SetCode(addr, artifact)

	api := NewTOSAPI(&agentDiscoveryBackendMock{
		getCodeBackendMock: &getCodeBackendMock{
			backendMock: newBackendMock(),
			st:          st,
			head:        &types.Header{Number: big.NewInt(199)},
		},
		discovery: providerSvc,
	})

	identity := common.HexToAddress("0x1234")
	info, err := api.AgentDiscoveryPublishSuggested(context.Background(), AgentDiscoveryPublishSuggestedArgs{
		Address:         addr.Hex(),
		PrimaryIdentity: identity.Hex(),
		ConnectionModes: []string{"talkreq", "https"},
		CardSequence:    12,
	})
	if err != nil {
		t.Fatalf("publish suggested: %v", err)
	}
	if !info.HasPublishedCard {
		t.Fatal("expected published card info")
	}
	if err := pingWithRetryForAPI(requester, provider.Self()); err != nil {
		t.Fatalf("ping provider: %v", err)
	}
	resp, err := requesterSvc.GetCard(provider.Self())
	if err != nil {
		t.Fatalf("get card: %v", err)
	}
	if resp.ParsedCard == nil {
		t.Fatal("expected parsed card")
	}
	if resp.ParsedCard.AgentAddress != identity.Hex() {
		t.Fatalf("unexpected agent address %q", resp.ParsedCard.AgentAddress)
	}
	if resp.ParsedCard.AgentID != "settlementagent" {
		t.Fatalf("unexpected agent id %q", resp.ParsedCard.AgentID)
	}
	if len(resp.ParsedCard.Capabilities) != 1 || resp.ParsedCard.Capabilities[0].Name != "settlementexecute" {
		t.Fatalf("unexpected capabilities %+v", resp.ParsedCard.Capabilities)
	}
	if resp.ParsedCard.PackageName != "settlementagent" {
		t.Fatalf("unexpected package name %q", resp.ParsedCard.PackageName)
	}
}

func TestAgentDiscoveryGetSuggestedCardArtifact(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	artifact, err := lua.CompileArtifact([]byte(agentDiscoverySuggestedSource), "SettlementAgent.tol")
	if err != nil {
		t.Fatalf("compile source: %v", err)
	}
	addr := common.HexToAddress("0x4545454545454545454545454545454545454545454545454545454545454545")
	st.SetCode(addr, artifact)

	api := NewTOSAPI(&agentDiscoveryBackendMock{
		getCodeBackendMock: &getCodeBackendMock{
			backendMock: newBackendMock(),
			st:          st,
			head:        &types.Header{Number: big.NewInt(199)},
		},
	})
	card, err := api.AgentDiscoveryGetSuggestedCard(context.Background(), AgentDiscoverySuggestedCardArgs{
		Address: addr.Hex(),
	})
	if err != nil {
		t.Fatalf("get suggested card: %v", err)
	}
	if card == nil {
		t.Fatal("expected suggested card")
	}
	if card.AgentID != "settlementagent" {
		t.Fatalf("unexpected agent id %q", card.AgentID)
	}
	if len(card.Capabilities) != 1 || card.Capabilities[0].Name != "settlementexecute" {
		t.Fatalf("unexpected capabilities %+v", card.Capabilities)
	}
}

func TestAgentDiscoveryPublishSuggestedPackage(t *testing.T) {
	provider := startLocalUDPv5ForAPI(t)
	defer provider.Close()

	requester := startLocalUDPv5ForAPI(t, provider.Self())
	defer requester.Close()

	providerSvc, err := agentdiscovery.New(provider.LocalNode(), provider)
	if err != nil {
		t.Fatalf("new provider service: %v", err)
	}
	requesterSvc, err := agentdiscovery.New(requester.LocalNode(), requester)
	if err != nil {
		t.Fatalf("new requester service: %v", err)
	}

	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	pkgBytes, err := lua.CompilePackage([]byte(agentDiscoverySuggestedPackageSource), "CheckoutAgent.tol", &lua.PackageOptions{
		PackageName:    "demo.bundle",
		PackageVersion: "1.0.0",
	})
	if err != nil {
		t.Fatalf("compile package: %v", err)
	}
	addr := common.HexToAddress("0x4646464646464646464646464646464646464646464646464646464646464646")
	st.SetCode(addr, pkgBytes)

	api := NewTOSAPI(&agentDiscoveryBackendMock{
		getCodeBackendMock: &getCodeBackendMock{
			backendMock: newBackendMock(),
			st:          st,
			head:        &types.Header{Number: big.NewInt(199)},
		},
		discovery: providerSvc,
	})

	identity := common.HexToAddress("0x5678")
	if _, err := api.AgentDiscoveryPublishSuggested(context.Background(), AgentDiscoveryPublishSuggestedArgs{
		Address:         addr.Hex(),
		PrimaryIdentity: identity.Hex(),
		ConnectionModes: []string{"talkreq"},
		CardSequence:    14,
	}); err != nil {
		t.Fatalf("publish suggested package: %v", err)
	}
	if err := pingWithRetryForAPI(requester, provider.Self()); err != nil {
		t.Fatalf("ping provider: %v", err)
	}
	resp, err := requesterSvc.GetCard(provider.Self())
	if err != nil {
		t.Fatalf("get card: %v", err)
	}
	if resp.ParsedCard == nil {
		t.Fatal("expected parsed card")
	}
	if resp.ParsedCard.AgentAddress != identity.Hex() {
		t.Fatalf("unexpected agent address %q", resp.ParsedCard.AgentAddress)
	}
	if resp.ParsedCard.PackageName != "demo.bundle" {
		t.Fatalf("unexpected package name %q", resp.ParsedCard.PackageName)
	}
	if len(resp.ParsedCard.Capabilities) != 1 || resp.ParsedCard.Capabilities[0].Name != "checkoutexecute" {
		t.Fatalf("unexpected capabilities %+v", resp.ParsedCard.Capabilities)
	}
}

func startLocalUDPv5ForAPI(t *testing.T, bootnodes ...*enode.Node) *discover.UDPv5 {
	t.Helper()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	db, err := enode.OpenDB("")
	if err != nil {
		t.Fatalf("open node db: %v", err)
	}
	localNode := enode.NewLocalNode(db, key)

	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	realAddr := socket.LocalAddr().(*net.UDPAddr)
	localNode.SetStaticIP(realAddr.IP)
	localNode.Set(enr.UDP(realAddr.Port))

	udp, err := discover.ListenV5(socket, localNode, discover.Config{
		PrivateKey: key,
		Bootnodes:  bootnodes,
	})
	if err != nil {
		t.Fatalf("listen v5: %v", err)
	}
	return udp
}

func pingWithRetryForAPI(udp *discover.UDPv5, node *enode.Node) error {
	var lastErr error
	for i := 0; i < 5; i++ {
		if err := udp.Ping(node); err == nil {
			return nil
		} else {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
		}
	}
	return lastErr
}
