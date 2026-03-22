package pkgregistry

import (
	"errors"

	"github.com/tos-network/gtos/common"
)

// ChannelKind identifies the release channel of a published package.
type ChannelKind uint16

const (
	ChannelDev        ChannelKind = 0
	ChannelBeta       ChannelKind = 1
	ChannelStable     ChannelKind = 2
	ChannelDeprecated ChannelKind = 3
)

// PackageStatus represents the lifecycle status of a publisher or package.
type PackageStatus uint8

const (
	PkgActive     PackageStatus = 0
	PkgDeprecated PackageStatus = 1
	PkgRevoked    PackageStatus = 2
)

func (s PackageStatus) String() string {
	switch s {
	case PkgDeprecated:
		return "deprecated"
	case PkgRevoked:
		return "revoked"
	default:
		return "active"
	}
}

// NamespaceStatus represents the governor-managed lifecycle of a claimed
// package namespace.
type NamespaceStatus uint8

const (
	NamespaceClear    NamespaceStatus = 0
	NamespaceDisputed NamespaceStatus = 1
)

func (s NamespaceStatus) String() string {
	switch s {
	case NamespaceDisputed:
		return "disputed"
	default:
		return "clear"
	}
}

func canTransitionPackageStatus(cur, next PackageStatus) bool {
	switch cur {
	case PkgActive:
		return next == PkgDeprecated || next == PkgRevoked
	case PkgDeprecated:
		return next == PkgRevoked
	default:
		return false
	}
}

func canTransitionPublisherStatus(cur, next PackageStatus) bool {
	switch cur {
	case PkgActive:
		return next == PkgDeprecated || next == PkgRevoked
	case PkgDeprecated:
		return next == PkgActive || next == PkgRevoked
	default:
		return false
	}
}

// PublisherRecord is the on-chain identity of a package publisher.
type PublisherRecord struct {
	PublisherID [32]byte
	Controller  common.Address
	MetadataRef [32]byte
	Namespace   string
	Status      PackageStatus
	CreatedAt   uint64
	UpdatedAt   uint64
	UpdatedBy   common.Address
	StatusRef   [32]byte
}

// PackageRecord is the on-chain record for a published package version.
type PackageRecord struct {
	PackageName    string
	PackageVersion string
	PackageHash    [32]byte
	PublisherID    [32]byte
	ManifestHash   [32]byte
	Channel        ChannelKind
	Status         PackageStatus
	ContractCount  uint16
	DiscoveryRef   [32]byte
	PublishedAt    uint64
	CreatedAt      uint64
	UpdatedAt      uint64
	UpdatedBy      common.Address
	StatusRef      [32]byte
}

// NamespaceGovernanceRecord captures governor-managed freeze/dispute state for
// a claimed namespace.
type NamespaceGovernanceRecord struct {
	Namespace   string
	PublisherID [32]byte
	Status      NamespaceStatus
	EvidenceRef [32]byte
	CreatedAt   uint64
	UpdatedAt   uint64
	UpdatedBy   common.Address
}

var (
	ErrPublisherExists       = errors.New("pkgregistry: publisher already registered")
	ErrPublisherNotFound     = errors.New("pkgregistry: publisher not found")
	ErrPackageExists         = errors.New("pkgregistry: package version already published")
	ErrPackageNotFound       = errors.New("pkgregistry: package version not found")
	ErrInvalidPublisher      = errors.New("pkgregistry: invalid publisher payload")
	ErrInvalidPackage        = errors.New("pkgregistry: invalid package payload")
	ErrPublisherInactive     = errors.New("pkgregistry: publisher is not active")
	ErrNamespaceExists       = errors.New("pkgregistry: namespace already claimed")
	ErrNamespaceMissing      = errors.New("pkgregistry: namespace missing")
	ErrNamespaceMismatch     = errors.New("pkgregistry: package namespace mismatch")
	ErrUnauthorizedPublisher = errors.New("pkgregistry: sender is not publisher controller or governor")
	ErrUnauthorizedGovernor  = errors.New("pkgregistry: sender is not protocol governor")
	ErrInvalidPublisherState = errors.New("pkgregistry: invalid publisher status transition")
	ErrInvalidPackageState   = errors.New("pkgregistry: invalid package status transition")
	ErrNamespaceDisputed     = errors.New("pkgregistry: namespace is under dispute")
	ErrNamespaceNotDisputed  = errors.New("pkgregistry: namespace is not under dispute")
)
