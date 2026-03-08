package agentdiscovery

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/p2p/discover"
	"github.com/tos-network/gtos/p2p/enode"
	"github.com/tos-network/gtos/p2p/enr"
)

func TestCapabilityBloomMatches(t *testing.T) {
	t.Parallel()

	bloom, err := buildCapabilityBloom([]string{"sponsor.topup.testnet", "oracle.resolve"})
	if err != nil {
		t.Fatalf("build bloom: %v", err)
	}
	if !bloomMatches(bloom, "sponsor.topup.testnet") {
		t.Fatalf("expected bloom match")
	}
	if bloomMatches(bloom, "observation.once") {
		t.Fatalf("unexpected false positive in deterministic test")
	}
}

func TestServicePublishAndGetCard(t *testing.T) {
	t.Parallel()

	provider := startLocalUDPv5(t)
	defer provider.Close()

	requester := startLocalUDPv5(t, provider.Self())
	defer requester.Close()

	providerSvc, err := New(provider.LocalNode(), provider)
	if err != nil {
		t.Fatalf("new provider service: %v", err)
	}
	requesterSvc, err := New(requester.LocalNode(), requester)
	if err != nil {
		t.Fatalf("new requester service: %v", err)
	}

	card := map[string]any{
		"version":  1,
		"agent_id": "agent-provider",
		"capabilities": []map[string]any{
			{"name": "sponsor.topup.testnet", "mode": "sponsored"},
		},
	}
	cardJSON, err := json.Marshal(card)
	if err != nil {
		t.Fatalf("marshal card: %v", err)
	}

	identity := common.HexToAddress("0x1234")
	if _, err := providerSvc.Publish(PublishConfig{
		PrimaryIdentity: identity,
		Capabilities:    []string{"sponsor.topup.testnet"},
		ConnectionModes: ConnectionModeTalkReq | ConnectionModeHTTPS,
		CardJSON:        string(cardJSON),
		CardSequence:    7,
	}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	var version profileVersionEntry
	if err := provider.Self().Record().Load(&version); err != nil {
		t.Fatalf("provider missing agv entry: %v", err)
	}
	if uint16(version) != ProfileVersion {
		t.Fatalf("wrong provider agv value %d", version)
	}
	var bloom capabilityBloomEntry
	if err := provider.Self().Record().Load(&bloom); err != nil {
		t.Fatalf("provider missing agb entry: %v", err)
	}
	if !bloomMatches(bloom, "sponsor.topup.testnet") {
		t.Fatalf("provider bloom does not match expected capability")
	}

	if err := requester.Ping(provider.Self()); err != nil {
		t.Fatalf("ping provider: %v", err)
	}
	if err := requester.LocalNode().Database().UpdateNode(provider.Self()); err != nil {
		t.Fatalf("update node db: %v", err)
	}
	if err := requester.LocalNode().Database().UpdateLastPongReceived(provider.Self().ID(), provider.Self().IP(), time.Now()); err != nil {
		t.Fatalf("update pong time: %v", err)
	}
	seeds := requester.LocalNode().Database().QuerySeeds(5, 24*time.Hour)
	if len(seeds) == 0 {
		t.Fatalf("expected node db seeds after update")
	}
	if err := seeds[0].Record().Load(&version); err != nil {
		t.Fatalf("seed missing agv entry: %v", err)
	}
	if uint16(version) != ProfileVersion {
		t.Fatalf("wrong seed agv value %d", version)
	}
	if err := seeds[0].Record().Load(&bloom); err != nil {
		t.Fatalf("seed missing agb entry: %v", err)
	}
	if !bloomMatches(bloom, "sponsor.topup.testnet") {
		t.Fatalf("seed bloom does not match expected capability")
	}
	candidates := requesterSvc.collectCandidates(10)
	if len(candidates) == 0 {
		t.Fatalf("expected collectCandidates to return at least one node")
	}
	foundProvider := false
	for _, candidate := range candidates {
		if candidate.ID() != provider.Self().ID() {
			continue
		}
		foundProvider = true
	}
	if !foundProvider {
		t.Fatalf("expected collectCandidates to include provider node")
	}
	_ = requester.Lookup(provider.Self().ID())

	results, err := requesterSvc.Search("sponsor.topup.testnet", 5)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) == 0 {
		t.Fatalf("expected at least one search result")
	}
	if results[0].PrimaryIdentity != identity.Hex() {
		t.Fatalf("wrong primary identity: %s", results[0].PrimaryIdentity)
	}

	node, err := ParseNode(results[0].NodeRecord)
	if err != nil {
		t.Fatalf("parse node: %v", err)
	}
	resp, err := requesterSvc.GetCard(node)
	if err != nil {
		t.Fatalf("get card: %v", err)
	}
	if resp.CardJSON != string(cardJSON) {
		t.Fatalf("unexpected card JSON: %s", resp.CardJSON)
	}
}

func TestDirectorySearchTalkHandler(t *testing.T) {
	t.Parallel()

	directory := startLocalUDPv5(t)
	defer directory.Close()

	provider := startLocalUDPv5(t, directory.Self())
	defer provider.Close()

	directorySvc, err := New(directory.LocalNode(), directory)
	if err != nil {
		t.Fatalf("new directory service: %v", err)
	}
	providerSvc, err := New(provider.LocalNode(), provider)
	if err != nil {
		t.Fatalf("new provider service: %v", err)
	}

	directoryCardJSON, err := json.Marshal(map[string]any{
		"version":  1,
		"agent_id": "directory-agent",
		"capabilities": []map[string]any{
			{"name": "directory.search", "mode": "sponsored"},
		},
	})
	if err != nil {
		t.Fatalf("marshal directory card: %v", err)
	}
	if _, err := directorySvc.Publish(PublishConfig{
		PrimaryIdentity: common.HexToAddress("0xd1"),
		Capabilities:    []string{"directory.search"},
		ConnectionModes: ConnectionModeTalkReq,
		CardJSON:        string(directoryCardJSON),
		CardSequence:    1,
	}); err != nil {
		t.Fatalf("publish directory: %v", err)
	}

	providerCardJSON, err := json.Marshal(map[string]any{
		"version":  1,
		"agent_id": "provider-agent",
		"capabilities": []map[string]any{
			{"name": "sponsor.topup.testnet", "mode": "sponsored"},
		},
	})
	if err != nil {
		t.Fatalf("marshal provider card: %v", err)
	}
	identity := common.HexToAddress("0x4321")
	if _, err := providerSvc.Publish(PublishConfig{
		PrimaryIdentity: identity,
		Capabilities:    []string{"sponsor.topup.testnet"},
		ConnectionModes: ConnectionModeTalkReq | ConnectionModeHTTPS,
		CardJSON:        string(providerCardJSON),
		CardSequence:    2,
	}); err != nil {
		t.Fatalf("publish provider: %v", err)
	}

	if err := pingWithRetry(directory, provider.Self()); err != nil {
		t.Fatalf("directory ping provider: %v", err)
	}
	reply := directorySvc.handleTalkRequest(enode.ID{}, nil, encodeTalkMessage(talkMessage{
		Type:       "SEARCH",
		Capability: "sponsor.topup.testnet",
		Limit:      5,
	}))
	msg, err := decodeTalkMessage(reply)
	if err != nil {
		t.Fatalf("decode talk reply: %v", err)
	}
	if msg.Type != "RESULTS" {
		t.Fatalf("unexpected reply type %q", msg.Type)
	}
	results := msg.Results
	if len(results) == 0 {
		t.Fatalf("expected directory results")
	}
	if results[0].PrimaryIdentity != identity.Hex() {
		t.Fatalf("unexpected provider identity %s", results[0].PrimaryIdentity)
	}
}

func TestSearchIncludesTrustSummary(t *testing.T) {
	t.Parallel()

	provider := startLocalUDPv5(t)
	defer provider.Close()

	requester := startLocalUDPv5(t, provider.Self())
	defer requester.Close()

	providerSvc, err := New(provider.LocalNode(), provider)
	if err != nil {
		t.Fatalf("new provider service: %v", err)
	}
	requesterSvc, err := New(requester.LocalNode(), requester)
	if err != nil {
		t.Fatalf("new requester service: %v", err)
	}

	identity := common.HexToAddress("0x9999")
	requesterSvc.SetSummaryProvider(func(addr common.Address, capability string) *ProviderTrustSummary {
		if addr != identity || capability != "sponsor.topup.testnet" {
			return nil
		}
		bit := uint8(17)
		return &ProviderTrustSummary{
			Registered:           true,
			Suspended:            false,
			Stake:                "250000000000000000",
			StakeBucket:          "medium",
			Reputation:           "42",
			ReputationBucket:     "high",
			RatingCount:          "7",
			CapabilityRegistered: true,
			CapabilityBit:        &bit,
			HasOnchainCapability: true,
			LocalRankScore:       123,
			LocalRankReason:      "registered,active,onchain-capability",
		}
	})

	cardJSON, err := json.Marshal(map[string]any{
		"version":  1,
		"agent_id": "trusted-provider",
		"capabilities": []map[string]any{
			{"name": "sponsor.topup.testnet", "mode": "sponsored"},
		},
	})
	if err != nil {
		t.Fatalf("marshal provider card: %v", err)
	}
	if _, err := providerSvc.Publish(PublishConfig{
		PrimaryIdentity: identity,
		Capabilities:    []string{"sponsor.topup.testnet"},
		ConnectionModes: ConnectionModeTalkReq | ConnectionModeHTTPS,
		CardJSON:        string(cardJSON),
		CardSequence:    3,
	}); err != nil {
		t.Fatalf("publish provider: %v", err)
	}

	if err := pingWithRetry(requester, provider.Self()); err != nil {
		t.Fatalf("requester ping provider: %v", err)
	}

	results, err := requesterSvc.Search("sponsor.topup.testnet", 5)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) == 0 {
		t.Fatalf("expected at least one search result")
	}
	if results[0].Trust == nil {
		t.Fatalf("expected trust summary in search result")
	}
	if !results[0].Trust.Registered || !results[0].Trust.HasOnchainCapability {
		t.Fatalf("unexpected trust summary: %+v", results[0].Trust)
	}
	if results[0].Trust.Reputation != "42" {
		t.Fatalf("unexpected reputation %s", results[0].Trust.Reputation)
	}
	if results[0].Trust.StakeBucket != "medium" || results[0].Trust.ReputationBucket != "high" {
		t.Fatalf("unexpected trust buckets: %+v", results[0].Trust)
	}
	if results[0].Trust.LocalRankScore != 123 {
		t.Fatalf("unexpected rank score %d", results[0].Trust.LocalRankScore)
	}
}

func startLocalUDPv5(t *testing.T, bootnodes ...*enode.Node) *discover.UDPv5 {
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

func pingWithRetry(udp *discover.UDPv5, node *enode.Node) error {
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
