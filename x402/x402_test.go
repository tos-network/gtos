package x402

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
)

type mockBroadcaster struct {
	lastRaw hexutil.Bytes
	hash    common.Hash
	err     error
}

func (m *mockBroadcaster) SendRawTransaction(_ context.Context, rawTx hexutil.Bytes) (common.Hash, error) {
	m.lastRaw = append(hexutil.Bytes(nil), rawTx...)
	return m.hash, m.err
}

func TestWritePaymentRequiredSetsHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	req := NewExactNativeRequirement(big.NewInt(1337), common.HexToAddress("0x1234"), big.NewInt(25), "test")
	if err := WritePaymentRequired(rec, req); err != nil {
		t.Fatalf("WritePaymentRequired: %v", err)
	}
	if rec.Code != 402 {
		t.Fatalf("unexpected status have=%d want=402", rec.Code)
	}
	if rec.Header().Get(HeaderPaymentRequired) == "" {
		t.Fatal("missing Payment-Required header")
	}
	if rec.Header().Get(LegacyHeaderPaymentRequired) == "" {
		t.Fatal("missing X-Payment-Required header")
	}
}

func TestVerifyExactPaymentGoldenVector(t *testing.T) {
	requirement := NewExactNativeRequirement(
		big.NewInt(1337),
		common.HexToAddress("0x1111111111111111111111111111111111111111111111111111111111111111"),
		big.NewInt(12345),
		"golden",
	)
	envelope := &PaymentEnvelope{
		X402Version: 1,
		Scheme:      SchemeExact,
		Network:     "tos:1337",
		Payload: TOSTransactionPayload{
			RawTransaction: "0x00f8a18205392a82c350a011111111111111111111111111111111111111111111111111111111111111118230398611223344aabbc0a0969b0a11b8a56bacf1ac18f219e7e376e7c213b7e7e7e46cc70a5dd086daff2a89736563703235366b3101a0109bbf2550567329ff51768666879a5d370e821fd51cd1f2444de5718e9342a3a03499fee0cdc9844a547689a5223e467fa6d9248c2c85abcedbd6a393c3ce816d",
		},
	}

	verified, err := VerifyExactPayment(requirement, envelope)
	if err != nil {
		t.Fatalf("VerifyExactPayment: %v", err)
	}
	if verified.From != common.HexToAddress("0x969b0a11b8a56bacf1ac18f219e7e376e7c213b7e7e7e46cc70a5dd086daff2a") {
		t.Fatalf("unexpected from %s", verified.From.Hex())
	}
	if verified.TransactionHash != common.HexToHash("0xe1f91071dc24343ac9677e292b9f11a4fa5885d4a8370a7982e68b3076db3489") {
		t.Fatalf("unexpected tx hash %s", verified.TransactionHash.Hex())
	}
}

func TestParsePaymentEnvelopeHeader(t *testing.T) {
	raw := PaymentEnvelope{
		X402Version: 1,
		Scheme:      SchemeExact,
		Network:     "tos:1337",
		Payload: TOSTransactionPayload{
			RawTransaction: "0x1234",
		},
	}
	payload, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	header := base64.StdEncoding.EncodeToString(payload)
	parsed, err := ParsePaymentEnvelopeHeader(header)
	if err != nil {
		t.Fatalf("ParsePaymentEnvelopeHeader: %v", err)
	}
	if parsed.Network != raw.Network || parsed.Payload.RawTransaction != raw.Payload.RawTransaction {
		t.Fatalf("unexpected parsed envelope: %+v", parsed)
	}
}

func TestSubmitVerifiedPayment(t *testing.T) {
	rawTx, err := hexutil.Decode("0x1234")
	if err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	expectedHash := common.HexToHash("0x01")
	mock := &mockBroadcaster{hash: expectedHash}
	payment := &VerifiedPayment{RawTransaction: rawTx}
	got, err := SubmitVerifiedPayment(context.Background(), mock, payment)
	if err != nil {
		t.Fatalf("SubmitVerifiedPayment: %v", err)
	}
	if got != expectedHash {
		t.Fatalf("unexpected hash %s", got.Hex())
	}
	if hexutil.Encode(mock.lastRaw) != "0x1234" {
		t.Fatalf("unexpected raw tx %s", hexutil.Encode(mock.lastRaw))
	}
}

func TestRequireExactPaymentChallengesWhenHeaderMissing(t *testing.T) {
	req := NewExactNativeRequirement(big.NewInt(1337), common.HexToAddress("0x1234"), big.NewInt(25), "challenge")
	nextCalled := false
	handler := RequireExactPayment(req, &mockBroadcaster{}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/paid", nil))

	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("unexpected status have=%d want=%d", rec.Code, http.StatusPaymentRequired)
	}
	if nextCalled {
		t.Fatal("expected next handler not to be called")
	}
	if rec.Header().Get(HeaderPaymentRequired) == "" {
		t.Fatal("missing Payment-Required header")
	}
}

func TestRequireExactPaymentVerifiesAndInjectsContext(t *testing.T) {
	req := NewExactNativeRequirement(
		big.NewInt(1337),
		common.HexToAddress("0x1111111111111111111111111111111111111111111111111111111111111111"),
		big.NewInt(12345),
		"paid",
	)
	env := PaymentEnvelope{
		X402Version: 1,
		Scheme:      SchemeExact,
		Network:     "tos:1337",
		Payload: TOSTransactionPayload{
			RawTransaction: "0x00f8a18205392a82c350a011111111111111111111111111111111111111111111111111111111111111118230398611223344aabbc0a0969b0a11b8a56bacf1ac18f219e7e376e7c213b7e7e7e46cc70a5dd086daff2a89736563703235366b3101a0109bbf2550567329ff51768666879a5d370e821fd51cd1f2444de5718e9342a3a03499fee0cdc9844a547689a5223e467fa6d9248c2c85abcedbd6a393c3ce816d",
		},
	}
	payload, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	header := base64.StdEncoding.EncodeToString(payload)

	mock := &mockBroadcaster{hash: common.HexToHash("0x01")}
	handler := RequireExactPayment(req, mock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verified, ok := VerifiedPaymentFromContext(r.Context())
		if !ok {
			t.Fatal("expected verified payment in context")
		}
		if verified.TransactionHash != common.HexToHash("0xe1f91071dc24343ac9677e292b9f11a4fa5885d4a8370a7982e68b3076db3489") {
			t.Fatalf("unexpected tx hash %s", verified.TransactionHash.Hex())
		}
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodGet, "/paid", nil)
	httpReq.Header.Set(HeaderPaymentSignature, header)
	handler.ServeHTTP(rec, httpReq)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status have=%d want=%d", rec.Code, http.StatusOK)
	}
	if hexutil.Encode(mock.lastRaw) != env.Payload.RawTransaction {
		t.Fatalf("unexpected broadcast raw tx have=%s want=%s", hexutil.Encode(mock.lastRaw), env.Payload.RawTransaction)
	}
}
