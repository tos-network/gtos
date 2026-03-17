package boundary

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
)

func testAddr(b byte) common.Address {
	var addr common.Address
	addr[19] = b
	return addr
}

func testHash(b byte) common.Hash {
	var h common.Hash
	h[31] = b
	return h
}

func TestSchemaVersion(t *testing.T) {
	if SchemaVersion != "0.1.0" {
		t.Fatalf("expected SchemaVersion 0.1.0, got %s", SchemaVersion)
	}
}

func TestIntentEnvelopeJSONRoundTrip(t *testing.T) {
	env := IntentEnvelope{
		IntentID:      "intent-001",
		SchemaVersion: SchemaVersion,
		Action:        "transfer",
		Requester:     testAddr(1),
		ActorAgentID:  testAddr(2),
		TerminalClass: TerminalApp,
		TrustTier:     TrustTierHigh,
		Params:        map[string]any{"amount": "100"},
		Constraints: &IntentConstraints{
			MaxValue:          big.NewInt(1000),
			AllowedRecipients: []common.Address{testAddr(3)},
			RequiredTrustTier: TrustTierMedium,
			MaxGas:            21000,
			Deadline:          1700000100,
		},
		CreatedAt: 1700000000,
		ExpiresAt: 1700003600,
		Status:    IntentPending,
	}

	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got IntentEnvelope
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.IntentID != env.IntentID {
		t.Errorf("IntentID mismatch: %s != %s", got.IntentID, env.IntentID)
	}
	if got.Action != env.Action {
		t.Errorf("Action mismatch: %s != %s", got.Action, env.Action)
	}
	if got.Requester != env.Requester {
		t.Errorf("Requester mismatch")
	}
	if got.TerminalClass != env.TerminalClass {
		t.Errorf("TerminalClass mismatch: %s != %s", got.TerminalClass, env.TerminalClass)
	}
	if got.TrustTier != env.TrustTier {
		t.Errorf("TrustTier mismatch: %d != %d", got.TrustTier, env.TrustTier)
	}
	if got.Status != env.Status {
		t.Errorf("Status mismatch: %s != %s", got.Status, env.Status)
	}
	if got.Constraints == nil {
		t.Fatal("Constraints should not be nil")
	}
	if got.Constraints.MaxValue.Cmp(env.Constraints.MaxValue) != 0 {
		t.Errorf("MaxValue mismatch")
	}
}

func TestPlanRecordJSONRoundTrip(t *testing.T) {
	plan := PlanRecord{
		PlanID:        "plan-001",
		IntentID:      "intent-001",
		SchemaVersion: SchemaVersion,
		Provider:      testAddr(10),
		Sponsor:       testAddr(11),
		PolicyHash:    testHash(1),
		EstimatedGas:  50000,
		EstimatedValue: big.NewInt(500),
		Route: []RouteStep{
			{Target: testAddr(20), Action: "approve", Value: big.NewInt(100)},
			{Target: testAddr(21), Action: "swap"},
		},
		CreatedAt: 1700000000,
		ExpiresAt: 1700003600,
		Status:    PlanReady,
	}

	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got PlanRecord
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.PlanID != plan.PlanID {
		t.Errorf("PlanID mismatch")
	}
	if got.Provider != plan.Provider {
		t.Errorf("Provider mismatch")
	}
	if got.EstimatedValue.Cmp(plan.EstimatedValue) != 0 {
		t.Errorf("EstimatedValue mismatch")
	}
	if len(got.Route) != 2 {
		t.Fatalf("expected 2 route steps, got %d", len(got.Route))
	}
	if got.Route[0].Action != "approve" {
		t.Errorf("Route[0].Action mismatch")
	}
}

func TestApprovalRecordJSONRoundTrip(t *testing.T) {
	approval := ApprovalRecord{
		ApprovalID:    "approval-001",
		IntentID:      "intent-001",
		PlanID:        "plan-001",
		SchemaVersion: SchemaVersion,
		Approver:      testAddr(5),
		ApproverRole:  RoleRequester,
		AccountID:     testAddr(6),
		TerminalClass: TerminalCard,
		TrustTier:     TrustTierMedium,
		PolicyHash:    testHash(2),
		Scope: &ApprovalScope{
			MaxValue:       big.NewInt(2000),
			AllowedActions: []string{"transfer", "swap"},
			AllowedTargets: []common.Address{testAddr(20)},
			TerminalClasses: []TerminalClass{TerminalApp, TerminalCard},
			MinTrustTier:   TrustTierLow,
		},
		CreatedAt: 1700000000,
		ExpiresAt: 1700003600,
		Status:    ApprovalGranted,
	}

	data, err := json.Marshal(approval)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got ApprovalRecord
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.ApprovalID != approval.ApprovalID {
		t.Errorf("ApprovalID mismatch")
	}
	if got.ApproverRole != approval.ApproverRole {
		t.Errorf("ApproverRole mismatch")
	}
	if got.Scope == nil {
		t.Fatal("Scope should not be nil")
	}
	if got.Scope.MaxValue.Cmp(approval.Scope.MaxValue) != 0 {
		t.Errorf("Scope.MaxValue mismatch")
	}
	if len(got.Scope.AllowedActions) != 2 {
		t.Errorf("expected 2 allowed actions, got %d", len(got.Scope.AllowedActions))
	}
}

func TestExecutionReceiptJSONRoundTrip(t *testing.T) {
	receipt := ExecutionReceipt{
		ReceiptID:     "receipt-001",
		IntentID:      "intent-001",
		PlanID:        "plan-001",
		ApprovalID:    "approval-001",
		SchemaVersion: SchemaVersion,
		TxHash:        testHash(10),
		BlockNumber:   12345,
		BlockHash:     testHash(11),
		From:          testAddr(1),
		To:            testAddr(2),
		Sponsor:       testAddr(3),
		ActorAgentID:  testAddr(4),
		TerminalClass: TerminalPOS,
		TrustTier:     TrustTierHigh,
		PolicyHash:    testHash(5),
		GasUsed:       21000,
		Value:         big.NewInt(100),
		Status:        ReceiptSuccess,
		SettledAt:     1700001000,
	}

	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got ExecutionReceipt
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.ReceiptID != receipt.ReceiptID {
		t.Errorf("ReceiptID mismatch")
	}
	if got.TxHash != receipt.TxHash {
		t.Errorf("TxHash mismatch")
	}
	if got.BlockNumber != receipt.BlockNumber {
		t.Errorf("BlockNumber mismatch")
	}
	if got.From != receipt.From {
		t.Errorf("From mismatch")
	}
	if got.GasUsed != receipt.GasUsed {
		t.Errorf("GasUsed mismatch")
	}
	if got.Value.Cmp(receipt.Value) != 0 {
		t.Errorf("Value mismatch")
	}
	if got.Status != receipt.Status {
		t.Errorf("Status mismatch")
	}
}

func TestAgentAccountBindingJSONRoundTrip(t *testing.T) {
	binding := AgentAccountBinding{
		AgentID:      testAddr(30),
		AccountID:    testAddr(31),
		Role:         RoleActor,
		PolicyHash:   testHash(20),
		Capabilities: []string{"transfer", "stake"},
		GrantedAt:    1700000000,
		ExpiresAt:    1700100000,
		Revoked:      false,
	}

	data, err := json.Marshal(binding)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got AgentAccountBinding
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.AgentID != binding.AgentID {
		t.Errorf("AgentID mismatch")
	}
	if got.Role != binding.Role {
		t.Errorf("Role mismatch")
	}
	if len(got.Capabilities) != 2 {
		t.Errorf("expected 2 capabilities, got %d", len(got.Capabilities))
	}
	if got.Revoked != false {
		t.Errorf("Revoked should be false")
	}
}

func TestIntentEnvelopeValidation(t *testing.T) {
	valid := IntentEnvelope{
		IntentID:      "intent-001",
		SchemaVersion: SchemaVersion,
		Action:        "transfer",
		Requester:     testAddr(1),
		CreatedAt:     1700000000,
		ExpiresAt:     1700003600,
		Status:        IntentPending,
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}

	tests := []struct {
		name   string
		modify func(*IntentEnvelope)
	}{
		{"empty intent_id", func(e *IntentEnvelope) { e.IntentID = "" }},
		{"empty action", func(e *IntentEnvelope) { e.Action = "" }},
		{"zero requester", func(e *IntentEnvelope) { e.Requester = common.Address{} }},
		{"invalid status", func(e *IntentEnvelope) { e.Status = "bogus" }},
		{"zero created_at", func(e *IntentEnvelope) { e.CreatedAt = 0 }},
		{"zero expires_at", func(e *IntentEnvelope) { e.ExpiresAt = 0 }},
		{"expires before created", func(e *IntentEnvelope) { e.ExpiresAt = e.CreatedAt }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := valid
			tt.modify(&env)
			if err := env.Validate(); err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

func TestPlanRecordValidation(t *testing.T) {
	valid := PlanRecord{
		PlanID:    "plan-001",
		IntentID:  "intent-001",
		Provider:  testAddr(10),
		CreatedAt: 1700000000,
		ExpiresAt: 1700003600,
		Status:    PlanDraft,
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}

	tests := []struct {
		name   string
		modify func(*PlanRecord)
	}{
		{"empty plan_id", func(p *PlanRecord) { p.PlanID = "" }},
		{"empty intent_id", func(p *PlanRecord) { p.IntentID = "" }},
		{"zero provider", func(p *PlanRecord) { p.Provider = common.Address{} }},
		{"invalid status", func(p *PlanRecord) { p.Status = "bogus" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := valid
			tt.modify(&plan)
			if err := plan.Validate(); err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

func TestApprovalRecordValidation(t *testing.T) {
	valid := ApprovalRecord{
		ApprovalID: "approval-001",
		IntentID:   "intent-001",
		PlanID:     "plan-001",
		Approver:   testAddr(5),
		CreatedAt:  1700000000,
		ExpiresAt:  1700003600,
		Status:     ApprovalPending,
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}

	inv := valid
	inv.ApprovalID = ""
	if err := inv.Validate(); err == nil {
		t.Error("expected error for empty approval_id")
	}
}

func TestExecutionReceiptValidation(t *testing.T) {
	valid := ExecutionReceipt{
		ReceiptID: "receipt-001",
		IntentID:  "intent-001",
		PlanID:    "plan-001",
		From:      testAddr(1),
		To:        testAddr(2),
		Status:    ReceiptSuccess,
		SettledAt: 1700001000,
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}

	tests := []struct {
		name   string
		modify func(*ExecutionReceipt)
	}{
		{"empty receipt_id", func(r *ExecutionReceipt) { r.ReceiptID = "" }},
		{"zero from", func(r *ExecutionReceipt) { r.From = common.Address{} }},
		{"zero to", func(r *ExecutionReceipt) { r.To = common.Address{} }},
		{"invalid status", func(r *ExecutionReceipt) { r.Status = "bogus" }},
		{"zero settled_at", func(r *ExecutionReceipt) { r.SettledAt = 0 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receipt := valid
			tt.modify(&receipt)
			if err := receipt.Validate(); err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}
