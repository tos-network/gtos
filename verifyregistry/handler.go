package verifyregistry

import (
	"encoding/json"

	"github.com/tos-network/gtos/common"
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
	PolicyRef    string `json:"policy_ref,omitempty"`
	Version      uint32 `json:"version"`
}

func (h *handler) handleRegisterVerifier(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p registerVerifierPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	addr := common.HexToAddress(p.VerifierAddr)
	if p.Name == "" || addr == (common.Address{}) || ctx.From != addr {
		return ErrInvalidVerifier
	}
	if existing := ReadVerifier(ctx.StateDB, p.Name); existing.Name != "" {
		return ErrVerifierExists
	}
	rec := VerifierRecord{
		Name:         p.Name,
		VerifierType: p.VerifierType,
		VerifierAddr: addr,
		Version:      p.Version,
		Status:       VerifierActive,
	}
	if p.PolicyRef != "" {
		ref := common.HexToHash(p.PolicyRef)
		copy(rec.PolicyRef[:], ref[:])
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
	if ctx.From != rec.VerifierAddr {
		return ErrUnauthorizedVerifier
	}
	if rec.Status == VerifierRevoked {
		return ErrVerifierAlreadyRevoked
	}
	rec.Status = VerifierRevoked
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
	subject := common.HexToAddress(p.Subject)
	if subject == (common.Address{}) || p.ProofType == "" {
		return ErrInvalidVerification
	}
	verifier := ReadVerifier(ctx.StateDB, p.ProofType)
	if verifier.Name == "" {
		return ErrVerifierNotFound
	}
	if ctx.From != verifier.VerifierAddr {
		return ErrUnauthorizedVerifier
	}
	if verifier.Status != VerifierActive {
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
	}
	if record.VerifiedAt == 0 && ctx.BlockNumber != nil {
		record.VerifiedAt = ctx.BlockNumber.Uint64()
	}
	WriteSubjectVerification(ctx.StateDB, record)
	return nil
}
