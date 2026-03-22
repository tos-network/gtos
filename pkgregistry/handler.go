package pkgregistry

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/registry"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&pkgRegistryHandler{})
}

type pkgRegistryHandler struct{}

func (h *pkgRegistryHandler) Actions() []sysaction.ActionKind {
	return []sysaction.ActionKind{
		sysaction.ActionPackageRegisterPublisher,
		sysaction.ActionPackageSetPublisherStatus,
		sysaction.ActionPackagePublish,
		sysaction.ActionPackageDeprecate,
		sysaction.ActionPackageRevoke,
		sysaction.ActionPackageDisputeNamespace,
		sysaction.ActionPackageResolveNamespace,
	}
}

func (h *pkgRegistryHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	switch sa.Action {
	case sysaction.ActionPackageRegisterPublisher:
		return h.handleRegisterPublisher(ctx, sa)
	case sysaction.ActionPackageSetPublisherStatus:
		return h.handleSetPublisherStatus(ctx, sa)
	case sysaction.ActionPackagePublish:
		return h.handlePublish(ctx, sa)
	case sysaction.ActionPackageDeprecate:
		return h.handleSetPackageStatus(ctx, sa, PkgDeprecated)
	case sysaction.ActionPackageRevoke:
		return h.handleSetPackageStatus(ctx, sa, PkgRevoked)
	case sysaction.ActionPackageDisputeNamespace:
		return h.handleSetNamespaceStatus(ctx, sa, NamespaceDisputed)
	case sysaction.ActionPackageResolveNamespace:
		return h.handleSetNamespaceStatus(ctx, sa, NamespaceClear)
	default:
		return nil
	}
}

type registerPublisherPayload struct {
	PublisherID string `json:"publisher_id"`
	Controller  string `json:"controller"`
	MetadataRef string `json:"metadata_ref"`
	Namespace   string `json:"namespace"`
}

func (h *pkgRegistryHandler) handleRegisterPublisher(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p registerPublisherPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	controller, err := parseStrictHexAddress(p.Controller)
	if err != nil {
		return ErrInvalidPublisher
	}
	pubID, err := parseRequiredBytes32(p.PublisherID)
	if err != nil {
		return ErrInvalidPublisher
	}
	namespace := strings.TrimSpace(p.Namespace)
	if controller == (common.Address{}) {
		return ErrInvalidPublisher
	}
	if namespace == "" {
		return ErrNamespaceMissing
	}
	var pubKey [32]byte
	copy(pubKey[:], pubID[:])
	if ctx.From != controller && !registry.IsGovernor(ctx.StateDB, ctx.From) {
		return ErrUnauthorizedPublisher
	}
	if existing := ReadPublisher(ctx.StateDB, pubKey); existing.Controller != (common.Address{}) {
		return ErrPublisherExists
	}
	if owner := namespaceOwnerID(ctx.StateDB, namespace); owner != ([32]byte{}) && owner != pubKey {
		return ErrNamespaceExists
	}
	rec := PublisherRecord{
		PublisherID: pubKey,
		Controller:  controller,
		Namespace:   namespace,
		Status:      PkgActive,
		UpdatedBy:   ctx.From,
	}
	if p.MetadataRef != "" {
		meta, err := parseOptionalBytes32(p.MetadataRef)
		if err != nil {
			return ErrInvalidPublisher
		}
		rec.MetadataRef = meta
	}
	now := currentBlockU64(ctx)
	rec.CreatedAt = now
	rec.UpdatedAt = now
	WritePublisher(ctx.StateDB, rec)
	return nil
}

type setPublisherStatusPayload struct {
	PublisherID string `json:"publisher_id"`
	Status      uint8  `json:"status"`
	MetadataRef string `json:"metadata_ref,omitempty"`
	ReasonRef   string `json:"reason_ref,omitempty"`
}

func (h *pkgRegistryHandler) handleSetPublisherStatus(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p setPublisherStatusPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	pubID, err := parseRequiredBytes32(p.PublisherID)
	if err != nil {
		return ErrInvalidPublisher
	}
	var pubKey [32]byte
	copy(pubKey[:], pubID[:])
	rec := ReadPublisher(ctx.StateDB, pubKey)
	if rec.Controller == (common.Address{}) {
		return ErrPublisherNotFound
	}
	if ctx.From != rec.Controller && !registry.IsGovernor(ctx.StateDB, ctx.From) {
		return ErrUnauthorizedPublisher
	}
	next := PackageStatus(p.Status)
	if rec.Status == next {
		if p.MetadataRef == "" && p.ReasonRef == "" {
			return nil
		}
	} else if !canTransitionPublisherStatus(rec.Status, next) {
		return ErrInvalidPublisherState
	}
	rec.Status = next
	if p.MetadataRef != "" {
		meta, err := parseOptionalBytes32(p.MetadataRef)
		if err != nil {
			return ErrInvalidPublisher
		}
		rec.MetadataRef = meta
	}
	if p.ReasonRef != "" {
		reason, err := parseOptionalBytes32(p.ReasonRef)
		if err != nil {
			return ErrInvalidPublisher
		}
		rec.StatusRef = reason
	}
	rec.UpdatedAt = currentBlockU64(ctx)
	rec.UpdatedBy = ctx.From
	WritePublisher(ctx.StateDB, rec)
	return nil
}

type publishPackagePayload struct {
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
	PackageHash    string `json:"package_hash"`
	PublisherID    string `json:"publisher_id"`
	ManifestHash   string `json:"manifest_hash,omitempty"`
	Channel        uint16 `json:"channel"`
	ContractCount  uint16 `json:"contract_count"`
	DiscoveryRef   string `json:"discovery_ref,omitempty"`
	PublishedAt    uint64 `json:"published_at,omitempty"`
}

func (h *pkgRegistryHandler) handlePublish(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p publishPackagePayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	if p.PackageName == "" || p.PackageVersion == "" {
		return ErrInvalidPackage
	}
	if existing := ReadPackage(ctx.StateDB, p.PackageName, p.PackageVersion); existing.PackageHash != ([32]byte{}) {
		return ErrPackageExists
	}
	pubIDHash, err := parseRequiredBytes32(p.PublisherID)
	if err != nil {
		return ErrInvalidPackage
	}
	var pubID [32]byte
	copy(pubID[:], pubIDHash[:])
	publisher := ReadPublisher(ctx.StateDB, pubID)
	if publisher.Controller == (common.Address{}) {
		return ErrPublisherNotFound
	}
	if ctx.From != publisher.Controller && !registry.IsGovernor(ctx.StateDB, ctx.From) {
		return ErrUnauthorizedPublisher
	}
	if publisher.Status != PkgActive {
		return ErrPublisherInactive
	}
	if ns := ReadNamespaceGovernance(ctx.StateDB, publisher.Namespace); ns.Status == NamespaceDisputed {
		return ErrNamespaceDisputed
	}
	pkgHash, err := parseRequiredBytes32(p.PackageHash)
	if err != nil {
		return ErrInvalidPackage
	}
	if !PackageMatchesNamespace(p.PackageName, publisher.Namespace) {
		return ErrNamespaceMismatch
	}
	now := currentBlockU64(ctx)
	rec := PackageRecord{
		PackageName:    p.PackageName,
		PackageVersion: p.PackageVersion,
		Channel:        ChannelKind(p.Channel),
		Status:         PkgActive,
		ContractCount:  p.ContractCount,
		PublishedAt:    p.PublishedAt,
		PublisherID:    pubID,
		CreatedAt:      now,
		UpdatedAt:      now,
		UpdatedBy:      ctx.From,
	}
	copy(rec.PackageHash[:], pkgHash[:])
	if p.ManifestHash != "" {
		manifest, err := parseOptionalBytes32(p.ManifestHash)
		if err != nil {
			return ErrInvalidPackage
		}
		rec.ManifestHash = manifest
	}
	if p.DiscoveryRef != "" {
		discovery, err := parseOptionalBytes32(p.DiscoveryRef)
		if err != nil {
			return ErrInvalidPackage
		}
		rec.DiscoveryRef = discovery
	}
	if rec.PublishedAt == 0 {
		rec.PublishedAt = now
	}
	WritePackage(ctx.StateDB, rec)
	return nil
}

type packageStatusPayload struct {
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
	ReasonRef      string `json:"reason_ref,omitempty"`
}

func (h *pkgRegistryHandler) handleSetPackageStatus(ctx *sysaction.Context, sa *sysaction.SysAction, status PackageStatus) error {
	var p packageStatusPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	rec := ReadPackage(ctx.StateDB, p.PackageName, p.PackageVersion)
	if rec.PackageHash == ([32]byte{}) {
		return ErrPackageNotFound
	}
	publisher := ReadPublisher(ctx.StateDB, rec.PublisherID)
	if publisher.Controller == (common.Address{}) {
		return ErrPublisherNotFound
	}
	if ctx.From != publisher.Controller && !registry.IsGovernor(ctx.StateDB, ctx.From) {
		return ErrUnauthorizedPublisher
	}
	if rec.Status == status {
		return nil
	}
	if !canTransitionPackageStatus(rec.Status, status) {
		return ErrInvalidPackageState
	}
	rec.Status = status
	rec.UpdatedAt = currentBlockU64(ctx)
	rec.UpdatedBy = ctx.From
	if p.ReasonRef != "" {
		reason, err := parseOptionalBytes32(p.ReasonRef)
		if err != nil {
			return ErrInvalidPackage
		}
		rec.StatusRef = reason
	}
	WritePackage(ctx.StateDB, rec)
	return nil
}

type namespaceGovernancePayload struct {
	Namespace   string `json:"namespace"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

func (h *pkgRegistryHandler) handleSetNamespaceStatus(ctx *sysaction.Context, sa *sysaction.SysAction, status NamespaceStatus) error {
	if !registry.IsGovernor(ctx.StateDB, ctx.From) {
		return ErrUnauthorizedGovernor
	}
	var p namespaceGovernancePayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	namespace := strings.TrimSpace(p.Namespace)
	if namespace == "" {
		return ErrNamespaceMissing
	}
	pubID := namespaceOwnerID(ctx.StateDB, namespace)
	if pubID == ([32]byte{}) {
		return ErrNamespaceMissing
	}
	rec := ReadNamespaceGovernance(ctx.StateDB, namespace)
	if rec.Namespace == "" {
		rec.Namespace = namespace
		rec.PublisherID = pubID
		rec.CreatedAt = currentBlockU64(ctx)
	}
	if rec.PublisherID == ([32]byte{}) {
		rec.PublisherID = pubID
	}
	if status == NamespaceClear && rec.Status != NamespaceDisputed {
		return ErrNamespaceNotDisputed
	}
	rec.Status = status
	rec.UpdatedAt = currentBlockU64(ctx)
	rec.UpdatedBy = ctx.From
	if p.EvidenceRef != "" {
		evidence, err := parseOptionalBytes32(p.EvidenceRef)
		if err != nil {
			return ErrInvalidPublisher
		}
		rec.EvidenceRef = evidence
	} else if status == NamespaceClear {
		rec.EvidenceRef = [32]byte{}
	}
	WriteNamespaceGovernance(ctx.StateDB, rec)
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
		return common.Address{}, ErrInvalidPublisher
	}
	return common.HexToAddress(input), nil
}

func parseRequiredBytes32(input string) ([32]byte, error) {
	out, err := parseOptionalBytes32(input)
	if err != nil {
		return out, err
	}
	if out == ([32]byte{}) {
		return out, ErrInvalidPackage
	}
	return out, nil
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
		return out, ErrInvalidPackage
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != 32 {
		return out, ErrInvalidPackage
	}
	copy(out[:], decoded)
	return out, nil
}
