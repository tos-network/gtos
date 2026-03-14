package x402

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
)

type mockBroadcaster struct {
	lastRaw hexutil.Bytes
	hash    common.Hash
	err     error
}

const canonicalPaymentPrivKeyHex = "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f4c8f66ad19c7f4f54"

func (m *mockBroadcaster) SendRawTransaction(_ context.Context, rawTx hexutil.Bytes) (common.Hash, error) {
	m.lastRaw = append(hexutil.Bytes(nil), rawTx...)
	return m.hash, m.err
}

func mustBuildCanonicalPaymentEnvelope(t *testing.T, requirement PaymentRequirement) (*PaymentEnvelope, common.Address, common.Hash) {
	t.Helper()

	chainID, err := ParseNetworkChainID(requirement.Network)
	if err != nil {
		t.Fatalf("parse network chain id: %v", err)
	}
	value, ok := new(big.Int).SetString(requirement.MaxAmountRequired, 0)
	if !ok {
		t.Fatalf("invalid payment amount %q", requirement.MaxAmountRequired)
	}
	key, err := crypto.HexToECDSA(canonicalPaymentPrivKeyHex)
	if err != nil {
		t.Fatalf("load canonical payment key: %v", err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	tx := types.NewTx(&types.SignerTx{
		ChainID:    new(big.Int).Set(chainID),
		Nonce:      42,
		Gas:        50_000,
		To:         &requirement.PayToAddress,
		Value:      value,
		Data:       common.FromHex("0x11223344aabbc0"),
		From:       from,
		SignerType: accountsigner.SignerTypeSecp256k1,
	})
	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), key)
	if err != nil {
		t.Fatalf("sign canonical payment tx: %v", err)
	}
	rawTx, err := signedTx.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal canonical payment tx: %v", err)
	}

	return &PaymentEnvelope{
		X402Version: 1,
		Scheme:      SchemeExact,
		Network:     requirement.Network,
		Payload: TOSTransactionPayload{
			RawTransaction: hexutil.Encode(rawTx),
		},
	}, from, signedTx.Hash()
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
	envelope, wantFrom, wantHash := mustBuildCanonicalPaymentEnvelope(t, requirement)

	verified, err := VerifyExactPayment(requirement, envelope)
	if err != nil {
		t.Fatalf("VerifyExactPayment: %v", err)
	}
	if verified.From != wantFrom {
		t.Fatalf("unexpected from %s", verified.From.Hex())
	}
	if verified.TransactionHash != wantHash {
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
	env, _, wantHash := mustBuildCanonicalPaymentEnvelope(t, req)
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
		if verified.TransactionHash != wantHash {
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
