package x402

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/core/types"
)

const (
	HeaderPaymentRequired        = "Payment-Required"
	HeaderPaymentSignature       = "Payment-Signature"
	LegacyHeaderPaymentRequired  = "X-Payment-Required"
	LegacyHeaderPaymentSignature = "X-Payment"

	X402Version = 1
	SchemeExact = "exact"

	AssetNativeTOS = "native"
)

type PaymentRequirement struct {
	Scheme                  string         `json:"scheme"`
	Network                 string         `json:"network"`
	MaxAmountRequired       string         `json:"maxAmountRequired"`
	PayToAddress            common.Address `json:"payToAddress"`
	Asset                   string         `json:"asset,omitempty"`
	RequiredDeadlineSeconds int            `json:"requiredDeadlineSeconds,omitempty"`
	Description             string         `json:"description,omitempty"`
}

type PaymentRequiredResponse struct {
	X402Version int                  `json:"x402Version"`
	Accepts     []PaymentRequirement `json:"accepts"`
}

type TOSTransactionPayload struct {
	RawTransaction string `json:"rawTransaction"`
}

type PaymentEnvelope struct {
	X402Version int                   `json:"x402Version"`
	Scheme      string                `json:"scheme"`
	Network     string                `json:"network"`
	Payload     TOSTransactionPayload `json:"payload"`
}

type VerifiedPayment struct {
	ChainID         *big.Int
	From            common.Address
	To              common.Address
	Value           *big.Int
	TransactionHash common.Hash
	RawTransaction  []byte
	Transaction     *types.Transaction
}

type RawTransactionBroadcaster interface {
	SendRawTransaction(ctx context.Context, rawTx hexutil.Bytes) (common.Hash, error)
}

func NetworkForChainID(chainID *big.Int) string {
	if chainID == nil {
		return "tos:0"
	}
	return "tos:" + chainID.String()
}

func ParseNetworkChainID(network string) (*big.Int, error) {
	normalized := strings.ToLower(strings.TrimSpace(network))
	if !strings.HasPrefix(normalized, "tos:") {
		return nil, fmt.Errorf("x402: unsupported network %q", network)
	}
	value := strings.TrimPrefix(normalized, "tos:")
	chainID, ok := new(big.Int).SetString(value, 10)
	if !ok || chainID.Sign() <= 0 {
		return nil, fmt.Errorf("x402: invalid TOS chain id %q", network)
	}
	return chainID, nil
}

func NewExactNativeRequirement(chainID *big.Int, payTo common.Address, amount *big.Int, description string) PaymentRequirement {
	value := "0"
	if amount != nil {
		value = amount.String()
	}
	return PaymentRequirement{
		Scheme:            SchemeExact,
		Network:           NetworkForChainID(chainID),
		MaxAmountRequired: value,
		PayToAddress:      payTo,
		Asset:             AssetNativeTOS,
		Description:       description,
	}
}

func EncodePaymentRequiredHeader(resp PaymentRequiredResponse) (string, error) {
	payload, err := json.Marshal(resp)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(payload), nil
}

func WritePaymentRequired(w http.ResponseWriter, requirement PaymentRequirement) error {
	resp := PaymentRequiredResponse{
		X402Version: X402Version,
		Accepts:     []PaymentRequirement{requirement},
	}
	encoded, err := EncodePaymentRequiredHeader(resp)
	if err != nil {
		return err
	}
	w.Header().Set(HeaderPaymentRequired, encoded)
	w.Header().Set(LegacyHeaderPaymentRequired, encoded)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPaymentRequired)
	return json.NewEncoder(w).Encode(resp)
}

func ParsePaymentEnvelopeHeader(value string) (*PaymentEnvelope, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		decoded = []byte(strings.TrimSpace(value))
	}
	var env PaymentEnvelope
	if err := json.Unmarshal(decoded, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

func ReadPaymentEnvelope(r *http.Request) (*PaymentEnvelope, error) {
	header := r.Header.Get(HeaderPaymentSignature)
	if header == "" {
		header = r.Header.Get(LegacyHeaderPaymentSignature)
	}
	if header == "" {
		return nil, fmt.Errorf("x402: missing payment signature header")
	}
	return ParsePaymentEnvelopeHeader(header)
}

func VerifyExactPayment(requirement PaymentRequirement, envelope *PaymentEnvelope) (*VerifiedPayment, error) {
	if envelope == nil {
		return nil, fmt.Errorf("x402: nil payment envelope")
	}
	if envelope.Scheme != SchemeExact {
		return nil, fmt.Errorf("x402: unsupported scheme %q", envelope.Scheme)
	}
	if strings.ToLower(strings.TrimSpace(envelope.Network)) != strings.ToLower(strings.TrimSpace(requirement.Network)) {
		return nil, fmt.Errorf("x402: network mismatch have=%q want=%q", envelope.Network, requirement.Network)
	}

	chainID, err := ParseNetworkChainID(requirement.Network)
	if err != nil {
		return nil, err
	}
	requiredValue, ok := new(big.Int).SetString(strings.TrimSpace(requirement.MaxAmountRequired), 0)
	if !ok {
		return nil, fmt.Errorf("x402: invalid amount %q", requirement.MaxAmountRequired)
	}

	rawTx, err := hexutil.Decode(envelope.Payload.RawTransaction)
	if err != nil {
		return nil, fmt.Errorf("x402: invalid raw transaction: %w", err)
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(rawTx); err != nil {
		return nil, fmt.Errorf("x402: decode TOS tx: %w", err)
	}
	if tx.Type() != types.SignerTxType {
		return nil, fmt.Errorf("x402: unsupported TOS tx type %d", tx.Type())
	}
	if tx.ChainId() == nil || tx.ChainId().Cmp(chainID) != 0 {
		return nil, fmt.Errorf("x402: TOS tx chainId mismatch have=%v want=%v", tx.ChainId(), chainID)
	}
	signerType, ok := tx.SignerType()
	if !ok || signerType != accountsigner.SignerTypeSecp256k1 {
		return nil, fmt.Errorf("x402: unsupported TOS signer type %q", signerType)
	}
	to := tx.To()
	if to == nil {
		return nil, fmt.Errorf("x402: TOS payment tx must have recipient")
	}
	if *to != requirement.PayToAddress {
		return nil, fmt.Errorf("x402: payTo mismatch have=%s want=%s", to.Hex(), requirement.PayToAddress.Hex())
	}
	if tx.Value().Cmp(requiredValue) < 0 {
		return nil, fmt.Errorf("x402: insufficient TOS payment have=%s want=%s", tx.Value(), requiredValue)
	}

	from, err := types.Sender(types.LatestSignerForChainID(chainID), tx)
	if err != nil {
		return nil, fmt.Errorf("x402: recover sender: %w", err)
	}

	return &VerifiedPayment{
		ChainID:         new(big.Int).Set(chainID),
		From:            from,
		To:              *to,
		Value:           tx.Value(),
		TransactionHash: tx.Hash(),
		RawTransaction:  rawTx,
		Transaction:     tx,
	}, nil
}

func SubmitVerifiedPayment(ctx context.Context, broadcaster RawTransactionBroadcaster, payment *VerifiedPayment) (common.Hash, error) {
	if broadcaster == nil {
		return common.Hash{}, fmt.Errorf("x402: nil broadcaster")
	}
	if payment == nil {
		return common.Hash{}, fmt.Errorf("x402: nil payment")
	}
	return broadcaster.SendRawTransaction(ctx, hexutil.Bytes(payment.RawTransaction))
}
