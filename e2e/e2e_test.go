// Package e2e provides end-to-end integration tests that exercise the full 2046
// architecture: boundary schemas, policywallet validation, auditreceipt
// building, gateway lookup, and settlement callbacks working together.
package e2e

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/auditreceipt"
	"github.com/tos-network/gtos/boundary"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/gateway"
	"github.com/tos-network/gtos/policywallet"
	"github.com/tos-network/gtos/settlement"
)

// ---------- mock StateDB (shared by all packages via their stateDB interface) ----------

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
	walletAddr    = common.HexToAddress("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	ownerAddr     = common.HexToAddress("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	guardianAddr  = common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	sponsorAddr   = common.HexToAddress("0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")
	recipientAddr = common.HexToAddress("0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")
	gatewayAddr   = common.HexToAddress("0x1111111111111111111111111111111111111111")
	newOwnerAddr  = common.HexToAddress("0x2222222222222222222222222222222222222222")
	creatorAddr   = common.HexToAddress("0x3333333333333333333333333333333333333333")
	fulfillerAddr = common.HexToAddress("0x4444444444444444444444444444444444444444")
)

// ---------- helper ----------

func testHash(b byte) common.Hash {
	var h common.Hash
	h[31] = b
	return h
}

// ---------- TestFullIntentToReceiptFlow ----------
// Tests the complete 2046 lifecycle:
// 1. Create and validate IntentEnvelope
// 2. Create and validate PlanRecord
// 3. Setup policy wallet (owner, spend caps, terminal policy, allowlist)
// 4. Validate sponsored execution against policy
// 5. Register a gateway
// 6. Build audit receipt and write audit metadata
// 7. Register settlement callback
// 8. Build session proof
// 9. Verify all boundary objects are consistent

func TestFullIntentToReceiptFlow(t *testing.T) {
	db := newMockStateDB()

	// === Step 1: Create and validate IntentEnvelope ===
	intent := boundary.IntentEnvelope{
		IntentID:      "intent-e2e-001",
		SchemaVersion: boundary.SchemaVersion,
		Action:        "transfer",
		Requester:     ownerAddr,
		ActorAgentID:  ownerAddr,
		TerminalClass: boundary.TerminalApp,
		TrustTier:     boundary.TrustTierHigh,
		Params:        map[string]any{"to": recipientAddr.Hex(), "amount": "5000"},
		Constraints: &boundary.IntentConstraints{
			MaxValue:          big.NewInt(10000),
			AllowedRecipients: []common.Address{recipientAddr},
			RequiredTrustTier: boundary.TrustTierMedium,
			MaxGas:            100000,
			Deadline:          1700003600,
		},
		CreatedAt: 1700000000,
		ExpiresAt: 1700003600,
		Status:    boundary.IntentPending,
	}
	if err := intent.Validate(); err != nil {
		t.Fatalf("intent validation failed: %v", err)
	}

	// === Step 2: Create and validate PlanRecord ===
	plan := boundary.PlanRecord{
		PlanID:         "plan-e2e-001",
		IntentID:       intent.IntentID,
		SchemaVersion:  boundary.SchemaVersion,
		Provider:       gatewayAddr,
		Sponsor:        sponsorAddr,
		PolicyHash:     testHash(0x01),
		EstimatedGas:   50000,
		EstimatedValue: big.NewInt(5000),
		Route: []boundary.RouteStep{
			{Target: recipientAddr, Action: "transfer", Value: big.NewInt(5000)},
		},
		CreatedAt: 1700000000,
		ExpiresAt: 1700003600,
		Status:    boundary.PlanReady,
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("plan validation failed: %v", err)
	}
	if plan.IntentID != intent.IntentID {
		t.Fatal("plan.IntentID does not match intent.IntentID")
	}

	// === Step 3: Setup policy wallet ===
	policywallet.WriteOwner(db, walletAddr, ownerAddr)
	policywallet.WriteDailyLimit(db, walletAddr, big.NewInt(100_000))
	policywallet.WriteSingleTxLimit(db, walletAddr, big.NewInt(10_000))
	policywallet.WriteAllowlisted(db, walletAddr, sponsorAddr, true)
	policywallet.WriteTerminalPolicy(db, walletAddr, policywallet.TerminalApp, policywallet.TerminalPolicy{
		MaxSingleValue: big.NewInt(10000),
		MaxDailyValue:  big.NewInt(100000),
		MinTrustTier:   policywallet.TrustLow,
		Enabled:        true,
	})

	// Verify policy state
	if policywallet.ReadOwner(db, walletAddr) != ownerAddr {
		t.Fatal("owner mismatch after setup")
	}
	if !policywallet.ReadAllowlisted(db, walletAddr, sponsorAddr) {
		t.Fatal("sponsor should be allowlisted")
	}

	// === Step 4: Validate sponsored execution ===
	err := policywallet.ValidateSponsoredExecution(db, walletAddr, sponsorAddr, big.NewInt(5000), policywallet.TerminalApp, policywallet.TrustHigh)
	if err != nil {
		t.Fatalf("sponsored execution validation failed: %v", err)
	}

	// === Step 5: Register a gateway ===
	gateway.WriteEndpoint(db, gatewayAddr, "https://relay.example.com/v1")
	gateway.WriteSupportedKinds(db, gatewayAddr, []string{"signer", "paymaster"})
	gateway.WriteMaxRelayGas(db, gatewayAddr, 500000)
	gateway.WriteFeePolicy(db, gatewayAddr, "free")
	gateway.WriteFeeAmount(db, gatewayAddr, big.NewInt(0))
	gateway.WriteActive(db, gatewayAddr, true)
	gateway.WriteRegisteredAt(db, gatewayAddr, 100)
	gateway.IncrementGatewayCount(db)

	// Verify gateway lookup
	if !gateway.ReadActive(db, gatewayAddr) {
		t.Fatal("gateway should be active")
	}
	if gateway.ReadEndpoint(db, gatewayAddr) != "https://relay.example.com/v1" {
		t.Fatal("gateway endpoint mismatch")
	}
	kinds := gateway.ReadSupportedKinds(db, gatewayAddr)
	if len(kinds) != 2 || kinds[0] != "paymaster" || kinds[1] != "signer" {
		t.Fatalf("gateway supported kinds mismatch: %v", kinds)
	}
	if gateway.ReadGatewayCount(db) != 1 {
		t.Fatal("gateway count should be 1")
	}

	// === Step 6: Build audit receipt and write metadata ===
	txHash := crypto.Keccak256Hash([]byte("e2e-test-tx-001"))

	ar := &auditreceipt.AuditReceipt{
		TxHash:        txHash,
		BlockNumber:   42,
		Status:        1, // success
		GasUsed:       21000,
		IntentID:      intent.IntentID,
		PlanID:        plan.PlanID,
		From:          ownerAddr,
		To:            recipientAddr,
		Sponsor:       sponsorAddr,
		ActorAgentID:  ownerAddr,
		PolicyHash:    plan.PolicyHash,
		TerminalClass: string(intent.TerminalClass),
		TrustTier:     uint8(intent.TrustTier),
		Value:         big.NewInt(5000),
		SettledAt:     1700001000,
	}
	ar.ReceiptHash = auditreceipt.ComputeReceiptHash(ar)
	if ar.ReceiptHash == (common.Hash{}) {
		t.Fatal("receipt hash should not be zero")
	}

	// Write audit metadata to state
	auditreceipt.WriteAuditMeta(db, txHash, intent.IntentID, plan.PlanID, string(intent.TerminalClass), uint8(intent.TrustTier))

	// Verify audit metadata round-trip
	intentIDHash, planIDHash, classHash, trustTier := auditreceipt.ReadAuditMeta(db, txHash)
	if intentIDHash == "" {
		t.Fatal("intentIDHash should not be empty")
	}
	if planIDHash == "" {
		t.Fatal("planIDHash should not be empty")
	}
	if classHash == "" {
		t.Fatal("terminalClassHash should not be empty")
	}
	if trustTier != uint8(intent.TrustTier) {
		t.Fatalf("trustTier mismatch: got %d, want %d", trustTier, intent.TrustTier)
	}

	// === Step 7: Register settlement callback ===
	cbID := crypto.Keccak256Hash([]byte("callback-e2e-001"))
	settlement.WriteCallbackExists(db, cbID)
	settlement.WriteCallbackTxHash(db, cbID, txHash)
	settlement.WriteCallbackType(db, cbID, settlement.CallbackOnSettle)
	settlement.WriteCallbackTarget(db, cbID, recipientAddr)
	settlement.WriteCallbackMaxGas(db, cbID, 100000)
	settlement.WriteCallbackCreatedAt(db, cbID, 42)
	settlement.WriteCallbackExpiresAt(db, cbID, 42+1000)
	settlement.WriteCallbackStatus(db, cbID, settlement.StatusPending)
	settlement.WriteCallbackCreator(db, cbID, creatorAddr)
	settlement.IncrementCallbackCount(db)

	if !settlement.ReadCallbackExists(db, cbID) {
		t.Fatal("callback should exist")
	}
	if settlement.ReadCallbackTxHash(db, cbID) != txHash {
		t.Fatal("callback txHash mismatch")
	}
	if settlement.ReadCallbackType(db, cbID) != settlement.CallbackOnSettle {
		t.Fatal("callback type mismatch")
	}
	if settlement.ReadCallbackStatus(db, cbID) != settlement.StatusPending {
		t.Fatal("callback should be pending")
	}

	// === Step 8: Build session proof ===
	proof := auditreceipt.BuildSessionProof(
		txHash,
		"session-e2e-001",
		string(intent.TerminalClass),
		"terminal-device-001",
		uint8(intent.TrustTier),
		walletAddr,
		1700000000,
	)
	if proof.ProofHash == (common.Hash{}) {
		t.Fatal("session proof hash should not be zero")
	}

	// Persist and read back
	auditreceipt.WriteSessionProof(db, proof)
	readProof := auditreceipt.ReadSessionProof(db, txHash)
	if readProof == nil {
		t.Fatal("session proof should be readable from state")
	}
	if readProof.ProofHash != proof.ProofHash {
		t.Fatal("session proof hash mismatch after round-trip")
	}
	if readProof.AccountAddr != walletAddr {
		t.Fatal("session proof account mismatch")
	}
	if readProof.TrustTier != uint8(intent.TrustTier) {
		t.Fatal("session proof trust tier mismatch")
	}

	// === Step 9: Cross-check consistency ===
	// Verify the audit receipt references match the boundary objects
	if ar.IntentID != intent.IntentID {
		t.Fatal("audit receipt IntentID does not match intent")
	}
	if ar.PlanID != plan.PlanID {
		t.Fatal("audit receipt PlanID does not match plan")
	}
	if ar.PolicyHash != plan.PolicyHash {
		t.Fatal("audit receipt PolicyHash does not match plan")
	}
	if ar.TerminalClass != string(intent.TerminalClass) {
		t.Fatal("audit receipt TerminalClass does not match intent")
	}
	if ar.TrustTier != uint8(intent.TrustTier) {
		t.Fatal("audit receipt TrustTier does not match intent")
	}
	// Settlement callback references the same tx as the audit receipt
	if settlement.ReadCallbackTxHash(db, cbID) != ar.TxHash {
		t.Fatal("settlement callback txHash does not match audit receipt")
	}
}

// ---------- TestMultiTerminalAccess ----------
// Tests terminal-class policy differentiation:
// 1. Setup same account with different terminal policies
// 2. Verify app terminal allows high value
// 3. Verify card terminal rejects high value but allows low value
// 4. Verify kiosk terminal rejects all above its cap
// 5. Verify voice terminal respects trust tier

func TestMultiTerminalAccess(t *testing.T) {
	db := newMockStateDB()

	policywallet.WriteOwner(db, walletAddr, ownerAddr)
	policywallet.WriteAllowlisted(db, walletAddr, sponsorAddr, true)

	// App: high limits, low trust required
	policywallet.WriteTerminalPolicy(db, walletAddr, policywallet.TerminalApp, policywallet.TerminalPolicy{
		MaxSingleValue: big.NewInt(100_000),
		MaxDailyValue:  big.NewInt(1_000_000),
		MinTrustTier:   policywallet.TrustLow,
		Enabled:        true,
	})

	// Card: moderate limits, medium trust
	policywallet.WriteTerminalPolicy(db, walletAddr, policywallet.TerminalCard, policywallet.TerminalPolicy{
		MaxSingleValue: big.NewInt(5_000),
		MaxDailyValue:  big.NewInt(50_000),
		MinTrustTier:   policywallet.TrustMedium,
		Enabled:        true,
	})

	// Kiosk: very low limits
	policywallet.WriteTerminalPolicy(db, walletAddr, policywallet.TerminalKiosk, policywallet.TerminalPolicy{
		MaxSingleValue: big.NewInt(500),
		MaxDailyValue:  big.NewInt(5_000),
		MinTrustTier:   policywallet.TrustHigh,
		Enabled:        true,
	})

	// Voice: high trust required
	policywallet.WriteTerminalPolicy(db, walletAddr, policywallet.TerminalVoice, policywallet.TerminalPolicy{
		MaxSingleValue: big.NewInt(1_000),
		MaxDailyValue:  big.NewInt(10_000),
		MinTrustTier:   policywallet.TrustFull,
		Enabled:        true,
	})

	highValue := big.NewInt(50_000)
	lowValue := big.NewInt(1_000)

	// App terminal should allow high value with low trust
	if err := policywallet.ValidateSponsoredExecution(db, walletAddr, sponsorAddr, highValue, policywallet.TerminalApp, policywallet.TrustLow); err != nil {
		t.Fatalf("app terminal should allow high value: %v", err)
	}

	// Card terminal should reject high value
	if err := policywallet.ValidateSponsoredExecution(db, walletAddr, sponsorAddr, highValue, policywallet.TerminalCard, policywallet.TrustMedium); err != policywallet.ErrSponsorValueExceeded {
		t.Fatalf("card terminal should reject high value: got %v, want ErrSponsorValueExceeded", err)
	}

	// Card terminal should allow low value with medium trust
	if err := policywallet.ValidateSponsoredExecution(db, walletAddr, sponsorAddr, lowValue, policywallet.TerminalCard, policywallet.TrustMedium); err != nil {
		t.Fatalf("card terminal should allow low value: %v", err)
	}

	// Kiosk terminal should reject low value (1000 > 500 cap)
	if err := policywallet.ValidateSponsoredExecution(db, walletAddr, sponsorAddr, lowValue, policywallet.TerminalKiosk, policywallet.TrustHigh); err != policywallet.ErrSponsorValueExceeded {
		t.Fatalf("kiosk terminal should reject value above cap: got %v, want ErrSponsorValueExceeded", err)
	}

	// Kiosk terminal should allow value within cap
	if err := policywallet.ValidateSponsoredExecution(db, walletAddr, sponsorAddr, big.NewInt(400), policywallet.TerminalKiosk, policywallet.TrustHigh); err != nil {
		t.Fatalf("kiosk terminal should allow value within cap: %v", err)
	}

	// Voice terminal with low trust should fail
	if err := policywallet.ValidateSponsoredExecution(db, walletAddr, sponsorAddr, big.NewInt(100), policywallet.TerminalVoice, policywallet.TrustLow); err != policywallet.ErrSponsorTrustTooLow {
		t.Fatalf("voice terminal should reject low trust: got %v, want ErrSponsorTrustTooLow", err)
	}

	// Voice terminal with full trust should pass
	if err := policywallet.ValidateSponsoredExecution(db, walletAddr, sponsorAddr, big.NewInt(100), policywallet.TerminalVoice, policywallet.TrustFull); err != nil {
		t.Fatalf("voice terminal should allow full trust: %v", err)
	}
}

// ---------- TestPolicyWalletRecoveryFlow ----------
// Tests guardian-based wallet recovery:
// 1. Setup owner and guardian
// 2. Initiate recovery from guardian (write recovery state)
// 3. Verify owner can cancel (clear recovery state)
// 4. Re-initiate and complete after timelock
// 5. Verify new owner

func TestPolicyWalletRecoveryFlow(t *testing.T) {
	db := newMockStateDB()

	// Step 1: Setup owner and guardian
	policywallet.WriteOwner(db, walletAddr, ownerAddr)
	policywallet.WriteGuardian(db, walletAddr, guardianAddr)

	if policywallet.ReadOwner(db, walletAddr) != ownerAddr {
		t.Fatal("owner should be set")
	}
	if policywallet.ReadGuardian(db, walletAddr) != guardianAddr {
		t.Fatal("guardian should be set")
	}

	// Step 2: Initiate recovery
	initiatedBlock := uint64(1000)
	policywallet.WriteRecoveryState(db, walletAddr, policywallet.RecoveryState{
		Active:      true,
		Guardian:    guardianAddr,
		NewOwner:    newOwnerAddr,
		InitiatedAt: initiatedBlock,
		Timelock:    policywallet.RecoveryTimelockBlocks,
	})

	rs := policywallet.ReadRecoveryState(db, walletAddr)
	if !rs.Active {
		t.Fatal("recovery should be active")
	}
	if rs.Guardian != guardianAddr {
		t.Fatal("recovery guardian mismatch")
	}
	if rs.NewOwner != newOwnerAddr {
		t.Fatal("recovery new owner mismatch")
	}

	// Step 3: Owner cancels recovery
	policywallet.WriteRecoveryState(db, walletAddr, policywallet.RecoveryState{})
	rs = policywallet.ReadRecoveryState(db, walletAddr)
	if rs.Active {
		t.Fatal("recovery should not be active after cancel")
	}

	// Verify owner unchanged
	if policywallet.ReadOwner(db, walletAddr) != ownerAddr {
		t.Fatal("owner should remain unchanged after recovery cancel")
	}

	// Step 4: Re-initiate and complete after timelock
	policywallet.WriteRecoveryState(db, walletAddr, policywallet.RecoveryState{
		Active:      true,
		Guardian:    guardianAddr,
		NewOwner:    newOwnerAddr,
		InitiatedAt: initiatedBlock,
		Timelock:    policywallet.RecoveryTimelockBlocks,
	})

	// Simulate timelock elapsed: currentBlock >= initiatedAt + timelock
	currentBlock := initiatedBlock + policywallet.RecoveryTimelockBlocks
	rs = policywallet.ReadRecoveryState(db, walletAddr)
	if currentBlock < rs.InitiatedAt+rs.Timelock {
		t.Fatal("timelock should have elapsed")
	}

	// Complete recovery: transfer ownership and clear state
	policywallet.WriteOwner(db, walletAddr, rs.NewOwner)
	policywallet.WriteRecoveryState(db, walletAddr, policywallet.RecoveryState{})

	// Step 5: Verify new owner
	if policywallet.ReadOwner(db, walletAddr) != newOwnerAddr {
		t.Fatalf("owner should be newOwner after recovery, got %s", policywallet.ReadOwner(db, walletAddr).Hex())
	}
	rs = policywallet.ReadRecoveryState(db, walletAddr)
	if rs.Active {
		t.Fatal("recovery should be cleared after completion")
	}
}

// ---------- TestGaslessSponsoredTransfer ----------
// Tests gasless sponsored execution:
// 1. Create intent for transfer
// 2. Setup sponsor allowlist in policy wallet
// 3. Validate sponsored execution
// 4. Build sponsor attribution record (using auditreceipt types directly)
// 5. Build audit receipt with sponsor fields

func TestGaslessSponsoredTransfer(t *testing.T) {
	db := newMockStateDB()

	// Step 1: Create intent
	intent := boundary.IntentEnvelope{
		IntentID:      "intent-gasless-001",
		SchemaVersion: boundary.SchemaVersion,
		Action:        "transfer",
		Requester:     ownerAddr,
		ActorAgentID:  ownerAddr,
		TerminalClass: boundary.TerminalApp,
		TrustTier:     boundary.TrustTierHigh,
		Params:        map[string]any{"to": recipientAddr.Hex(), "amount": "2000"},
		CreatedAt:     1700000000,
		ExpiresAt:     1700003600,
		Status:        boundary.IntentPending,
	}
	if err := intent.Validate(); err != nil {
		t.Fatalf("intent validation failed: %v", err)
	}

	// Step 2: Setup sponsor allowlist
	policywallet.WriteOwner(db, walletAddr, ownerAddr)
	policywallet.WriteAllowlisted(db, walletAddr, sponsorAddr, true)
	policywallet.WriteTerminalPolicy(db, walletAddr, policywallet.TerminalApp, policywallet.TerminalPolicy{
		MaxSingleValue: big.NewInt(50000),
		MaxDailyValue:  big.NewInt(500000),
		MinTrustTier:   policywallet.TrustLow,
		Enabled:        true,
	})

	// Step 3: Validate sponsored execution
	err := policywallet.ValidateSponsoredExecution(db, walletAddr, sponsorAddr, big.NewInt(2000), policywallet.TerminalApp, policywallet.TrustHigh)
	if err != nil {
		t.Fatalf("sponsored execution should pass: %v", err)
	}

	// Step 4: Build sponsor attribution record (in-memory, no transaction object needed)
	txHash := crypto.Keccak256Hash([]byte("gasless-tx-001"))
	sponsorPolicyHash := crypto.Keccak256Hash([]byte("sponsor-policy-001"))

	sar := &auditreceipt.SponsorAttributionRecord{
		TxHash:            txHash,
		SponsorAddress:    sponsorAddr,
		SponsorSignerType: "secp256k1",
		SponsorNonce:      42,
		SponsorExpiry:     1700003600,
		PolicyHash:        sponsorPolicyHash,
		GasSponsored:      21000,
		Timestamp:         1700001000,
	}
	if sar.SponsorAddress != sponsorAddr {
		t.Fatal("sponsor attribution address mismatch")
	}
	if sar.GasSponsored != 21000 {
		t.Fatal("sponsor attribution gas mismatch")
	}

	// Step 5: Build audit receipt with sponsor fields
	ar := &auditreceipt.AuditReceipt{
		TxHash:            txHash,
		BlockNumber:       100,
		Status:            1,
		GasUsed:           21000,
		IntentID:          intent.IntentID,
		From:              ownerAddr,
		To:                recipientAddr,
		Sponsor:           sponsorAddr,
		ActorAgentID:      ownerAddr,
		SignerType:        "secp256k1",
		PolicyHash:        testHash(0x01),
		SponsorPolicyHash: sponsorPolicyHash,
		TerminalClass:     string(intent.TerminalClass),
		TrustTier:         uint8(intent.TrustTier),
		Value:             big.NewInt(2000),
		SettledAt:         1700001000,
	}
	ar.ReceiptHash = auditreceipt.ComputeReceiptHash(ar)

	if ar.ReceiptHash == (common.Hash{}) {
		t.Fatal("receipt hash should not be zero")
	}
	if ar.Sponsor != sponsorAddr {
		t.Fatal("audit receipt should include sponsor")
	}
	if ar.SponsorPolicyHash != sponsorPolicyHash {
		t.Fatal("audit receipt should include sponsor policy hash")
	}

	// Write and verify audit metadata
	auditreceipt.WriteAuditMeta(db, txHash, intent.IntentID, "", string(intent.TerminalClass), uint8(intent.TrustTier))
	intentIDHash, _, _, tier := auditreceipt.ReadAuditMeta(db, txHash)
	if intentIDHash == "" {
		t.Fatal("audit meta intentID should be stored")
	}
	if tier != uint8(boundary.TrustTierHigh) {
		t.Fatalf("audit meta trustTier mismatch: got %d, want %d", tier, boundary.TrustTierHigh)
	}
}

// ---------- TestPrivacyTerminalRestrictions ----------
// Tests privacy-tier terminal policies:
// 1. Setup privacy terminal policies
// 2. Verify shield allowed from app but not from voice
// 3. Verify private transfer allowed from robot but value-capped
// 4. Verify kiosk blocks all privacy actions

func TestPrivacyTerminalRestrictions(t *testing.T) {
	db := newMockStateDB()

	// App: allow all privacy actions, medium trust, high value cap
	policywallet.WritePrivacyTerminalPolicy(db, walletAddr, policywallet.PrivacyTerminalPolicy{
		TerminalClass:     policywallet.TerminalApp,
		MaxPrivateValue:   big.NewInt(100_000),
		AllowShield:       true,
		AllowUnshield:     true,
		AllowPrivTransfer: true,
		MinTrustTier:      policywallet.TrustMedium,
	})

	// Voice: deny all privacy actions
	policywallet.WritePrivacyTerminalPolicy(db, walletAddr, policywallet.PrivacyTerminalPolicy{
		TerminalClass:     policywallet.TerminalVoice,
		MaxPrivateValue:   big.NewInt(0),
		AllowShield:       false,
		AllowUnshield:     false,
		AllowPrivTransfer: false,
		MinTrustTier:      policywallet.TrustFull,
	})

	// Robot: allow shield and private transfer, value-capped
	policywallet.WritePrivacyTerminalPolicy(db, walletAddr, policywallet.PrivacyTerminalPolicy{
		TerminalClass:     policywallet.TerminalRobot,
		MaxPrivateValue:   big.NewInt(5_000),
		AllowShield:       true,
		AllowUnshield:     true,
		AllowPrivTransfer: true,
		MinTrustTier:      policywallet.TrustMedium,
	})

	// Kiosk: deny all
	policywallet.WritePrivacyTerminalPolicy(db, walletAddr, policywallet.PrivacyTerminalPolicy{
		TerminalClass:     policywallet.TerminalKiosk,
		MaxPrivateValue:   big.NewInt(0),
		AllowShield:       false,
		AllowUnshield:     false,
		AllowPrivTransfer: false,
		MinTrustTier:      policywallet.TrustFull,
	})

	// App: shield should pass
	if err := policywallet.ValidatePrivacyTerminalAccess(db, walletAddr, policywallet.TerminalApp, policywallet.TrustMedium, policywallet.PrivacyActionShield, big.NewInt(1000)); err != nil {
		t.Fatalf("app shield should be allowed: %v", err)
	}

	// App: private transfer should pass
	if err := policywallet.ValidatePrivacyTerminalAccess(db, walletAddr, policywallet.TerminalApp, policywallet.TrustMedium, policywallet.PrivacyActionPrivTransfer, big.NewInt(1000)); err != nil {
		t.Fatalf("app priv_transfer should be allowed: %v", err)
	}

	// Voice: shield should be denied (trust too low, and shield denied)
	err := policywallet.ValidatePrivacyTerminalAccess(db, walletAddr, policywallet.TerminalVoice, policywallet.TrustMedium, policywallet.PrivacyActionShield, big.NewInt(100))
	if err == nil {
		t.Fatal("voice shield should be denied")
	}

	// Voice: even with full trust, shield is not allowed
	err = policywallet.ValidatePrivacyTerminalAccess(db, walletAddr, policywallet.TerminalVoice, policywallet.TrustFull, policywallet.PrivacyActionShield, big.NewInt(100))
	if err != policywallet.ErrPrivTerminalShieldDenied {
		t.Fatalf("voice shield should return ErrPrivTerminalShieldDenied, got %v", err)
	}

	// Robot: private transfer within cap should pass
	if err := policywallet.ValidatePrivacyTerminalAccess(db, walletAddr, policywallet.TerminalRobot, policywallet.TrustMedium, policywallet.PrivacyActionPrivTransfer, big.NewInt(3000)); err != nil {
		t.Fatalf("robot priv_transfer within cap should pass: %v", err)
	}

	// Robot: private transfer exceeding cap should fail
	err = policywallet.ValidatePrivacyTerminalAccess(db, walletAddr, policywallet.TerminalRobot, policywallet.TrustMedium, policywallet.PrivacyActionPrivTransfer, big.NewInt(10_000))
	if err != policywallet.ErrPrivTerminalValueExceeded {
		t.Fatalf("robot priv_transfer above cap should fail with ErrPrivTerminalValueExceeded, got %v", err)
	}

	// Kiosk: all privacy actions should be blocked
	for _, action := range []string{policywallet.PrivacyActionShield, policywallet.PrivacyActionUnshield, policywallet.PrivacyActionPrivTransfer} {
		err := policywallet.ValidatePrivacyTerminalAccess(db, walletAddr, policywallet.TerminalKiosk, policywallet.TrustFull, action, big.NewInt(1))
		if err == nil {
			t.Fatalf("kiosk should block privacy action %s", action)
		}
	}
}

// ---------- TestSettlementCallbackLifecycle ----------
// Tests settlement callback lifecycle:
// 1. Register on_settle and on_timeout callbacks
// 2. Execute the on_settle callback
// 3. Verify expired callback cannot be executed (mark as expired)
// 4. Register async fulfillment
// 5. Verify fulfillment links back to original tx

func TestSettlementCallbackLifecycle(t *testing.T) {
	db := newMockStateDB()

	txHash := crypto.Keccak256Hash([]byte("settlement-test-tx"))
	currentBlock := uint64(1000)
	ttlBlocks := uint64(500)

	// Step 1: Register on_settle callback
	cbSettleID := crypto.Keccak256Hash([]byte("cb-settle-001"))
	settlement.WriteCallbackExists(db, cbSettleID)
	settlement.WriteCallbackTxHash(db, cbSettleID, txHash)
	settlement.WriteCallbackType(db, cbSettleID, settlement.CallbackOnSettle)
	settlement.WriteCallbackTarget(db, cbSettleID, recipientAddr)
	settlement.WriteCallbackData(db, cbSettleID, testHash(0xAA))
	settlement.WriteCallbackMaxGas(db, cbSettleID, 100000)
	settlement.WriteCallbackCreatedAt(db, cbSettleID, currentBlock)
	settlement.WriteCallbackExpiresAt(db, cbSettleID, currentBlock+ttlBlocks)
	settlement.WriteCallbackStatus(db, cbSettleID, settlement.StatusPending)
	settlement.WriteCallbackCreator(db, cbSettleID, creatorAddr)
	settlement.IncrementCallbackCount(db)

	// Register on_timeout callback
	cbTimeoutID := crypto.Keccak256Hash([]byte("cb-timeout-001"))
	settlement.WriteCallbackExists(db, cbTimeoutID)
	settlement.WriteCallbackTxHash(db, cbTimeoutID, txHash)
	settlement.WriteCallbackType(db, cbTimeoutID, settlement.CallbackOnTimeout)
	settlement.WriteCallbackTarget(db, cbTimeoutID, creatorAddr)
	settlement.WriteCallbackMaxGas(db, cbTimeoutID, 50000)
	settlement.WriteCallbackCreatedAt(db, cbTimeoutID, currentBlock)
	settlement.WriteCallbackExpiresAt(db, cbTimeoutID, currentBlock+100) // short TTL
	settlement.WriteCallbackStatus(db, cbTimeoutID, settlement.StatusPending)
	settlement.WriteCallbackCreator(db, cbTimeoutID, creatorAddr)
	settlement.IncrementCallbackCount(db)

	if settlement.ReadCallbackCount(db) != 2 {
		t.Fatalf("callback count should be 2, got %d", settlement.ReadCallbackCount(db))
	}

	// Step 2: Execute on_settle callback (within TTL)
	executeBlock := currentBlock + 100 // within 500-block TTL
	if executeBlock > settlement.ReadCallbackExpiresAt(db, cbSettleID) {
		t.Fatal("execute block should be within TTL")
	}
	settlement.WriteCallbackStatus(db, cbSettleID, settlement.StatusExecuted)
	settlement.WriteCallbackExecutedAt(db, cbSettleID, executeBlock)

	if settlement.ReadCallbackStatus(db, cbSettleID) != settlement.StatusExecuted {
		t.Fatal("settle callback should be executed")
	}
	if settlement.ReadCallbackExecutedAt(db, cbSettleID) != executeBlock {
		t.Fatal("settle callback executedAt mismatch")
	}

	// Step 3: Verify timeout callback has expired (simulate block past expiry)
	expiredBlock := currentBlock + 200 // past 100-block TTL for timeout cb
	if expiredBlock <= settlement.ReadCallbackExpiresAt(db, cbTimeoutID) {
		t.Fatal("expired block should be past TTL")
	}
	// Mark as expired
	settlement.WriteCallbackStatus(db, cbTimeoutID, settlement.StatusExpired)

	if settlement.ReadCallbackStatus(db, cbTimeoutID) != settlement.StatusExpired {
		t.Fatal("timeout callback should be expired")
	}

	// Step 4: Register async fulfillment
	ffID := crypto.Keccak256Hash([]byte("fulfillment-001"))
	receiptRef := crypto.Keccak256Hash([]byte("receipt-ref-001"))
	resultData := crypto.Keccak256Hash([]byte("result-data-001"))

	settlement.WriteFulfillmentExists(db, ffID)
	settlement.WriteFulfillmentOriginalTxHash(db, ffID, txHash)
	settlement.WriteFulfillmentFulfiller(db, ffID, fulfillerAddr)
	settlement.WriteFulfillmentResultData(db, ffID, resultData)
	settlement.WriteFulfillmentPolicyCheck(db, ffID, true)
	settlement.WriteFulfillmentFulfilledAt(db, ffID, currentBlock+150)
	settlement.WriteFulfillmentReceiptRef(db, ffID, receiptRef)
	settlement.IncrementFulfillmentCount(db)

	// Step 5: Verify fulfillment links back to original tx
	if !settlement.ReadFulfillmentExists(db, ffID) {
		t.Fatal("fulfillment should exist")
	}
	if settlement.ReadFulfillmentOriginalTxHash(db, ffID) != txHash {
		t.Fatal("fulfillment should reference original txHash")
	}
	if settlement.ReadFulfillmentFulfiller(db, ffID) != fulfillerAddr {
		t.Fatal("fulfillment fulfiller mismatch")
	}
	if settlement.ReadFulfillmentResultData(db, ffID) != resultData {
		t.Fatal("fulfillment result data mismatch")
	}
	if !settlement.ReadFulfillmentPolicyCheck(db, ffID) {
		t.Fatal("fulfillment policy check should be true")
	}
	if settlement.ReadFulfillmentReceiptRef(db, ffID) != receiptRef {
		t.Fatal("fulfillment receipt ref mismatch")
	}
	if settlement.ReadFulfillmentFulfilledAt(db, ffID) != currentBlock+150 {
		t.Fatal("fulfillment fulfilledAt mismatch")
	}
	if settlement.ReadFulfillmentCount(db) != 1 {
		t.Fatalf("fulfillment count should be 1, got %d", settlement.ReadFulfillmentCount(db))
	}

	// Cross-check: the original txHash from the fulfillment matches the callback's txHash
	if settlement.ReadFulfillmentOriginalTxHash(db, ffID) != settlement.ReadCallbackTxHash(db, cbSettleID) {
		t.Fatal("fulfillment original txHash should match callback txHash")
	}
}
