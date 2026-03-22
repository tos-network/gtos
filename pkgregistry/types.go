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

// PublisherRecord is the on-chain identity of a package publisher.
type PublisherRecord struct {
	PublisherID [32]byte
	Controller  common.Address
	MetadataRef [32]byte
	Status      PackageStatus
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
}

var (
	ErrPublisherExists   = errors.New("pkgregistry: publisher already registered")
	ErrPublisherNotFound = errors.New("pkgregistry: publisher not found")
	ErrPackageExists     = errors.New("pkgregistry: package version already published")
	ErrPackageNotFound   = errors.New("pkgregistry: package version not found")
	ErrInvalidPublisher  = errors.New("pkgregistry: invalid publisher payload")
	ErrInvalidPackage    = errors.New("pkgregistry: invalid package payload")
	ErrPublisherInactive = errors.New("pkgregistry: publisher is not active")
)
