package pkgregistry

import (
	"encoding/json"
	"strings"

	"github.com/tos-network/gtos/common"
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
	controller := common.HexToAddress(p.Controller)
	pubID := common.HexToHash(p.PublisherID)
	namespace := strings.TrimSpace(p.Namespace)
	if controller == (common.Address{}) || pubID == (common.Hash{}) {
		return ErrInvalidPublisher
	}
	if namespace == "" {
		return ErrNamespaceMissing
	}
	if ctx.From != controller {
		return ErrInvalidPublisher
	}
	var pubKey [32]byte
	copy(pubKey[:], pubID[:])
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
	}
	if p.MetadataRef != "" {
		meta := common.HexToHash(p.MetadataRef)
		copy(rec.MetadataRef[:], meta[:])
	}
	WritePublisher(ctx.StateDB, rec)
	return nil
}

type setPublisherStatusPayload struct {
	PublisherID string `json:"publisher_id"`
	Status      uint8  `json:"status"`
	MetadataRef string `json:"metadata_ref,omitempty"`
}

func (h *pkgRegistryHandler) handleSetPublisherStatus(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p setPublisherStatusPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	pubID := common.HexToHash(p.PublisherID)
	var pubKey [32]byte
	copy(pubKey[:], pubID[:])
	rec := ReadPublisher(ctx.StateDB, pubKey)
	if rec.Controller == (common.Address{}) {
		return ErrPublisherNotFound
	}
	if ctx.From != rec.Controller {
		return ErrInvalidPublisher
	}
	rec.Status = PackageStatus(p.Status)
	if p.MetadataRef != "" {
		meta := common.HexToHash(p.MetadataRef)
		copy(rec.MetadataRef[:], meta[:])
	}
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
	pubIDHash := common.HexToHash(p.PublisherID)
	var pubID [32]byte
	copy(pubID[:], pubIDHash[:])
	publisher := ReadPublisher(ctx.StateDB, pubID)
	if publisher.Controller == (common.Address{}) {
		return ErrPublisherNotFound
	}
	if ctx.From != publisher.Controller {
		return ErrInvalidPublisher
	}
	if publisher.Status != PkgActive {
		return ErrPublisherInactive
	}
	pkgHash := common.HexToHash(p.PackageHash)
	if pkgHash == (common.Hash{}) {
		return ErrInvalidPackage
	}
	if !PackageMatchesNamespace(p.PackageName, publisher.Namespace) {
		return ErrNamespaceMismatch
	}
	rec := PackageRecord{
		PackageName:    p.PackageName,
		PackageVersion: p.PackageVersion,
		Channel:        ChannelKind(p.Channel),
		Status:         PkgActive,
		ContractCount:  p.ContractCount,
		PublishedAt:    p.PublishedAt,
		PublisherID:    pubID,
	}
	copy(rec.PackageHash[:], pkgHash[:])
	if p.ManifestHash != "" {
		manifest := common.HexToHash(p.ManifestHash)
		copy(rec.ManifestHash[:], manifest[:])
	}
	if p.DiscoveryRef != "" {
		discovery := common.HexToHash(p.DiscoveryRef)
		copy(rec.DiscoveryRef[:], discovery[:])
	}
	if rec.PublishedAt == 0 && ctx.BlockNumber != nil {
		rec.PublishedAt = ctx.BlockNumber.Uint64()
	}
	WritePackage(ctx.StateDB, rec)
	return nil
}

type packageStatusPayload struct {
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
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
	if publisher.Controller == (common.Address{}) || ctx.From != publisher.Controller {
		return ErrInvalidPublisher
	}
	rec.Status = status
	WritePackage(ctx.StateDB, rec)
	return nil
}
