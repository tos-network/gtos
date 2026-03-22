package verifyregistry

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/registry"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&handler{})
}

type handler struct{}

func (h *handler) Actions() []sysaction.ActionKind {
	return []sysaction.ActionKind{
		sysaction.ActionRegistryRegisterVerifier,
		sysaction.ActionRegistryDeactivateVerifier,
		sysaction.ActionRegistryAttestVerification,
		sysaction.ActionRegistryRevokeVerification,
	}
}

func (h *handler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	switch sa.Action {
	case sysaction.ActionRegistryRegisterVerifier:
		return h.handleRegisterVerifier(ctx, sa)
	case sysaction.ActionRegistryDeactivateVerifier:
		return h.handleDeactivateVerifier(ctx, sa)
	case sysaction.ActionRegistryAttestVerification:
		return h.handleSetVerification(ctx, sa, VerificationActive)
	case sysaction.ActionRegistryRevokeVerification:
		return h.handleSetVerification(ctx, sa, VerificationRevoked)
	default:
		return nil
	}
}

type registerVerifierPayload struct {
	Name         string `json:"name"`
	VerifierType uint16 `json:"verifier_type"`
	VerifierAddr string `json:"verifier_addr"`
	Controller   string `json:"controller,omitempty"`
	PolicyRef    string `json:"policy_ref,omitempty"`
	Version      uint32 `json:"version"`
}

func (h *handler) handleRegisterVerifier(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p registerVerifierPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	addr, err := parseStrictHexAddress(p.VerifierAddr)
	if err != nil {
		return ErrInvalidVerifier
	}
	controller := addr
	if strings.TrimSpace(p.Controller) != "" {
		controller, err = parseStrictHexAddress(p.Controller)
		if err != nil {
			return ErrInvalidVerifier
		}
	}
	policyRef, err := parseOptionalBytes32(p.PolicyRef)
	if err != nil {
		return ErrInvalidVerifier
	}
	if p.Name == "" || addr == (common.Address{}) || controller == (common.Address{}) {
		return ErrInvalidVerifier
	}
	if ctx.From != controller && !registry.IsGovernor(ctx.StateDB, ctx.From) {
		return ErrUnauthorizedVerifier
	}
	if existing := ReadVerifier(ctx.StateDB, p.Name); existing.Name != "" {
		return ErrVerifierExists
	}
	now := currentBlockU64(ctx)
	rec := VerifierRecord{
		Name:         p.Name,
		VerifierType: p.VerifierType,
		Controller:   controller,
		VerifierAddr: addr,
		PolicyRef:    policyRef,
		Version:      p.Version,
		Status:       VerifierActive,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	WriteVerifier(ctx.StateDB, rec)
	return nil
}

type verifierNamePayload struct {
	Name string `json:"name"`
}

func (h *handler) handleDeactivateVerifier(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p verifierNamePayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	rec := ReadVerifier(ctx.StateDB, p.Name)
	if rec.Name == "" {
		return ErrVerifierNotFound
	}
	if ctx.From != rec.Controller && ctx.From != rec.VerifierAddr && !registry.IsGovernor(ctx.StateDB, ctx.From) {
		return ErrUnauthorizedVerifier
	}
	if rec.Status == VerifierRevoked {
		return ErrVerifierAlreadyRevoked
	}
	rec.Status = VerifierRevoked
	rec.UpdatedAt = currentBlockU64(ctx)
	WriteVerifier(ctx.StateDB, rec)
	return nil
}

type subjectVerificationPayload struct {
	Subject    string `json:"subject"`
	ProofType  string `json:"proof_type"`
	VerifiedAt uint64 `json:"verified_at,omitempty"`
	ExpiryMS   uint64 `json:"expiry_ms,omitempty"`
}

func (h *handler) handleSetVerification(ctx *sysaction.Context, sa *sysaction.SysAction, status VerificationStatus) error {
	var p subjectVerificationPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	subject, err := parseStrictHexAddress(p.Subject)
	if err != nil {
		return ErrInvalidVerification
	}
	if subject == (common.Address{}) || p.ProofType == "" {
		return ErrInvalidVerification
	}
	verifier := ReadVerifier(ctx.StateDB, p.ProofType)
	if verifier.Name == "" {
		return ErrVerifierNotFound
	}
	authorizedWriter := ctx.From == verifier.VerifierAddr || ctx.From == verifier.Controller
	if status == VerificationRevoked && registry.IsGovernor(ctx.StateDB, ctx.From) {
		authorizedWriter = true
	}
	if !authorizedWriter {
		return ErrUnauthorizedVerifier
	}
	if verifier.Status != VerifierActive && status == VerificationActive {
		return ErrVerifierInactive
	}
	if status == VerificationRevoked {
		existing := ReadSubjectVerification(ctx.StateDB, subject, p.ProofType)
		if existing.Subject == (common.Address{}) {
			return ErrVerificationNotFound
		}
		if existing.Status == VerificationRevoked {
			return ErrVerificationAlreadyRevoked
		}
	}
	if p.ExpiryMS > 0 && p.VerifiedAt > 0 && p.ExpiryMS < p.VerifiedAt {
		return ErrInvalidVerification
	}
	record := SubjectVerificationRecord{
		Subject:    subject,
		ProofType:  p.ProofType,
		VerifiedAt: p.VerifiedAt,
		ExpiryMS:   p.ExpiryMS,
		Status:     status,
		UpdatedAt:  currentBlockU64(ctx),
	}
	if record.VerifiedAt == 0 && ctx.BlockNumber != nil {
		record.VerifiedAt = ctx.BlockNumber.Uint64()
	}
	WriteSubjectVerification(ctx.StateDB, record)
	return nil
}

func currentBlockU64(ctx *sysaction.Context) uint64 {
	if ctx == nil || ctx.BlockNumber == nil || ctx.BlockNumber.Sign() < 0 || !ctx.BlockNumber.IsUint64() {
		return 0
	}
	return ctx.BlockNumber.Uint64()
}

func parseStrictHexAddress(input string) (common.Address, error) {
	input = strings.TrimSpace(input)
	if !common.IsHexAddress(input) {
		return common.Address{}, ErrInvalidVerifier
	}
	return common.HexToAddress(input), nil
}

func parseOptionalBytes32(input string) ([32]byte, error) {
	var out [32]byte
	input = strings.TrimSpace(input)
	if input == "" {
		return out, nil
	}
	raw := input
	if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
		raw = raw[2:]
	}
	if len(raw) != 64 {
		return out, ErrInvalidVerifier
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != 32 {
		return out, ErrInvalidVerifier
	}
	copy(out[:], decoded)
	return out, nil
}
