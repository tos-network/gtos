package boundary

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
)

func benchIntentEnvelope() IntentEnvelope {
	return IntentEnvelope{
		IntentID:      "intent-bench-001",
		SchemaVersion: SchemaVersion,
		Action:        "transfer",
		Requester:     testAddr(1),
		ActorAgentID:  testAddr(2),
		TerminalClass: TerminalApp,
		TrustTier:     TrustTierHigh,
		Params:        map[string]any{"amount": "100", "token": "TOS"},
		Constraints: &IntentConstraints{
			MaxValue:          big.NewInt(1_000_000),
			AllowedRecipients: []common.Address{testAddr(3), testAddr(4)},
			RequiredTrustTier: TrustTierMedium,
			MaxGas:            50000,
			Deadline:          1700000100,
		},
		CreatedAt: 1700000000,
		ExpiresAt: 1700003600,
		Status:    IntentPending,
	}
}

func benchPlanRecord() PlanRecord {
	return PlanRecord{
		PlanID:        "plan-bench-001",
		IntentID:      "intent-bench-001",
		SchemaVersion: SchemaVersion,
		Provider:      testAddr(10),
		Sponsor:       testAddr(11),
		PolicyHash:    testHash(1),
		EstimatedGas:  50000,
		EstimatedValue: big.NewInt(500),
		Route: []RouteStep{
			{Target: testAddr(20), Action: "approve", Value: big.NewInt(100)},
			{Target: testAddr(21), Action: "swap", ArtifactRef: "0xabcdef"},
			{Target: testAddr(22), Action: "transfer", Value: big.NewInt(400)},
		},
		CreatedAt: 1700000000,
		ExpiresAt: 1700003600,
		Status:    PlanReady,
	}
}

func benchExecutionReceipt() ExecutionReceipt {
	return ExecutionReceipt{
		ReceiptID:         "receipt-bench-001",
		IntentID:          "intent-bench-001",
		PlanID:            "plan-bench-001",
		ApprovalID:        "approval-bench-001",
		SchemaVersion:     SchemaVersion,
		TxHash:            testHash(10),
		BlockNumber:       12345678,
		BlockHash:         testHash(11),
		From:              testAddr(1),
		To:                testAddr(2),
		Sponsor:           testAddr(3),
		ActorAgentID:      testAddr(4),
		TerminalClass:     TerminalPOS,
		TrustTier:         TrustTierHigh,
		PolicyHash:        testHash(5),
		SponsorPolicyHash: testHash(6),
		ArtifactRef:       "0xdeadbeef",
		EffectsHash:       testHash(7),
		GasUsed:           21000,
		Value:             big.NewInt(1_000_000),
		Status:            ReceiptSuccess,
		ProofRef:          "proof-001",
		ReceiptRef:        "receipt-ref-001",
		SettledAt:         1700001000,
	}
}

func BenchmarkIntentEnvelopeValidate(b *testing.B) {
	env := benchIntentEnvelope()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := env.Validate(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIntentEnvelopeJSON(b *testing.B) {
	env := benchIntentEnvelope()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, err := json.Marshal(&env)
		if err != nil {
			b.Fatal(err)
		}
		var decoded IntentEnvelope
		if err := json.Unmarshal(data, &decoded); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPlanRecordValidate(b *testing.B) {
	plan := benchPlanRecord()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := plan.Validate(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkExecutionReceiptJSON(b *testing.B) {
	receipt := benchExecutionReceipt()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, err := json.Marshal(&receipt)
		if err != nil {
			b.Fatal(err)
		}
		var decoded ExecutionReceipt
		if err := json.Unmarshal(data, &decoded); err != nil {
			b.Fatal(err)
		}
	}
}
